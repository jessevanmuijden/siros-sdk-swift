// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Generic HTTP client for remote identity verification backends.
///
/// Implements the common 3-step IDV flow:
/// 1. Session token acquisition
/// 2. Biometric (liveness) submission
/// 3. Document (ID scan) submission → credential offer URI
///
/// Provider-agnostic — any backend following the session → liveness → document
/// pattern works. The app provides a ``BiometricCaptureDelegate`` for
/// vendor-specific UI capture.
public final class RemoteIDVClient: @unchecked Sendable {

    /// Configuration for the remote IDV backend.
    public struct Config: Sendable {
        /// Base URL of the IDV server.
        public let serverUrl: String
        /// Authorization header value.
        public let authToken: String
        /// Session token endpoint path.
        public let sessionTokenPath: String
        /// Liveness submission endpoint path.
        public let livenessPath: String
        /// ID scan submission endpoint path.
        public let idScanPath: String

        public init(
            serverUrl: String,
            authToken: String,
            sessionTokenPath: String = "/v1/session-token",
            livenessPath: String = "/v1/liveness",
            idScanPath: String = "/v1/id-scan"
        ) {
            self.serverUrl = serverUrl.hasSuffix("/") ? String(serverUrl.dropLast()) : serverUrl
            self.authToken = authToken
            self.sessionTokenPath = sessionTokenPath
            self.livenessPath = livenessPath
            self.idScanPath = idScanPath
        }
    }

    private let config: Config
    private let session: URLSession

    public init(config: Config, session: URLSession = .shared) {
        self.config = config
        self.session = session
    }

    /// Get a session token from the IDV backend.
    public func getSessionToken() async throws -> String {
        let json = try await postJson(
            path: config.sessionTokenPath,
            body: [:]
        )
        guard let token = json["sessionToken"] as? String else {
            throw IDVError.networkError(underlying: URLError(.cannotParseResponse))
        }
        return token
    }

    /// Submit biometric data for liveness verification.
    ///
    /// - Parameter payload: Vendor-specific biometric data.
    /// - Returns: Opaque session ID for the subsequent document step.
    public func submitBiometric(payload: [String: Any]) async throws -> String {
        let json = try await postJson(
            path: config.livenessPath,
            body: payload,
            on422: { msg in IDVError.livenessFailed(message: msg) }
        )
        guard let sessionId = json["livenessSessionId"] as? String else {
            throw IDVError.networkError(underlying: URLError(.cannotParseResponse))
        }
        return sessionId
    }

    /// Submit document images for identity verification and credential issuance.
    ///
    /// - Parameter payload: Document images + liveness session ID.
    /// - Returns: ``IDVResult`` with credential offer URI.
    public func submitDocument(payload: [String: Any]) async throws -> IDVResult {
        let json = try await postJson(
            path: config.idScanPath,
            body: payload,
            on422: { msg in IDVError.verificationFailed(message: msg) }
        )
        guard let offerURI = json["credentialOfferURI"] as? String else {
            throw IDVError.networkError(underlying: URLError(.cannotParseResponse))
        }
        return IDVResult(
            credentialOfferURI: offerURI,
            transactionId: json["transactionId"] as? String
        )
    }

    /// Maps a 422 from the IDV backend to an ``IDVError``. The backend's error
    /// body is `{"error": "<message>", "error_code": "<code>"}`: an `nfc_*` code
    /// means the document's chip was not read and authenticated
    /// (``IDVError/documentChipNotVerified(reason:message:)``); anything else
    /// goes to the step's own `fallback`, with the raw body as before.
    static func idvError(
        for422ErrorCode errorCode: String?,
        errorMessage: String?,
        responseBody: String,
        fallback: (String) -> IDVError
    ) -> IDVError {
        if let errorCode, errorCode.hasPrefix("nfc_") {
            let message = errorMessage.flatMap { $0.isEmpty ? nil : $0 } ?? responseBody
            return .documentChipNotVerified(reason: errorCode, message: message)
        }
        return fallback(responseBody)
    }

    // MARK: - HTTP helper

    private func postJson(
        path: String,
        body: [String: Any],
        on422: ((String) -> IDVError)? = nil
    ) async throws -> [String: Any] {
        guard let url = URL(string: "\(config.serverUrl)\(path)") else {
            throw IDVError.networkError(underlying: URLError(.badURL))
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(config.authToken, forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw IDVError.networkError(underlying: URLError(.badServerResponse))
        }

        if http.statusCode == 422, let handler = on422 {
            let msg = String(data: data, encoding: .utf8) ?? "Verification failed"
            let error = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            throw Self.idvError(
                for422ErrorCode: error?["error_code"] as? String,
                errorMessage: error?["error"] as? String,
                responseBody: msg,
                fallback: handler
            )
        }
        guard http.statusCode >= 200 && http.statusCode < 300 else {
            let msg = String(data: data, encoding: .utf8) ?? "HTTP \(http.statusCode)"
            throw IDVError.networkError(underlying: NSError(domain: "IDV", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: msg]))
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw IDVError.networkError(underlying: URLError(.cannotParseResponse))
        }
        return json
    }
}

/// Delegate for vendor-specific biometric capture UI.
///
/// The SDK's ``RemoteIDVProvider`` calls these methods to capture biometric
/// data from the user. The delegate presents the vendor SDK's UI and returns
/// the captured data as a dictionary matching the backend's expected format.
public protocol BiometricCaptureDelegate: AnyObject, Sendable {
    /// Human-readable name of the capture provider.
    var name: String { get }

    /// Whether the capture SDK is available on this device.
    func isAvailable() async -> Bool

    /// Capture liveness biometric data.
    ///
    /// - Parameters:
    ///   - presentingViewController: View controller for presenting capture UI.
    ///   - sessionToken: Server-issued session token.
    /// - Returns: Dictionary payload for ``RemoteIDVClient/submitBiometric(payload:)``.
    func captureLiveness(presentingViewController: Any, sessionToken: String) async throws -> [String: Any]

    /// Capture document images.
    ///
    /// - Parameters:
    ///   - presentingViewController: View controller for presenting capture UI.
    ///   - sessionToken: Server-issued session token.
    ///   - livenessSessionId: From the prior liveness step.
    /// - Returns: Dictionary payload for ``RemoteIDVClient/submitDocument(payload:)``.
    func captureDocument(presentingViewController: Any, sessionToken: String, livenessSessionId: String) async throws -> [String: Any]
}

/// Identity verification provider backed by a remote IDV server and
/// a pluggable ``BiometricCaptureDelegate``.
///
/// ```swift
/// let client = RemoteIDVClient(config: .init(serverUrl: "...", authToken: "..."))
/// let delegate = FaceTecCaptureDelegate()
/// let provider = RemoteIDVProvider(client: client, delegate: delegate)
/// try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: vc)
/// ```
public final class RemoteIDVProvider: @unchecked Sendable, IdentityVerificationProvider {

    private let client: RemoteIDVClient
    private let delegate: BiometricCaptureDelegate

    public var name: String { delegate.name }

    public init(client: RemoteIDVClient, delegate: BiometricCaptureDelegate) {
        self.client = client
        self.delegate = delegate
    }

    public func isAvailable() async -> Bool {
        await delegate.isAvailable()
    }

    public func startVerification(presentingViewController: Any) async throws -> IDVResult {
        let sessionToken = try await client.getSessionToken()
        let livenessPayload = try await delegate.captureLiveness(
            presentingViewController: presentingViewController,
            sessionToken: sessionToken
        )
        let livenessSessionId = try await client.submitBiometric(payload: livenessPayload)
        let documentPayload = try await delegate.captureDocument(
            presentingViewController: presentingViewController,
            sessionToken: sessionToken,
            livenessSessionId: livenessSessionId
        )
        return try await client.submitDocument(payload: documentPayload)
    }
}
