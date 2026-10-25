// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

#if canImport(CommonCrypto)
import CommonCrypto
#endif

#if canImport(Security)
import Security
#endif

#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/// A fully local `AuthProvider` for development and testing.
///
/// Generates EC P-256 keys and performs WebAuthn-style register/authenticate
/// flows without requiring system credential manager UI (ASAuthorization).
/// This is the Swift equivalent of `LocalAuthProvider` on Android.
///
/// - Important: This provider is documented as dev/test-only, not for
///   production use. That said, on Apple platforms (where `Security` is
///   available) it still gates its signing key behind real device
///   authentication (`kSecAttrAccessControl` + `LAContext`/
///   `kSecUseAuthenticationContext`) rather than providing none at all, in
///   case it's ever exercised as a real fallback. Where `Security` is
///   unavailable (e.g. Linux), it throws rather than silently signing.
public final class LocalAuthProvider: AuthProvider, @unchecked Sendable {
    /// Stored credential metadata.
    public struct CredentialEntry: Sendable {
        public let credentialId: Data
        public let rpId: String
        public let userHandle: Data
        public let userName: String
        public var signCount: UInt32

        #if canImport(Security)
        /// Keychain `kSecAttrApplicationTag` used to re-fetch a context-bound
        /// `SecKey` reference at sign time (see `signWithKey`), rather than
        /// holding a bare in-memory `SecKey`, so the access-control gate set
        /// at creation time is actually enforced on every signing operation.
        let keyTag: Data
        #endif
    }

    #if canImport(Security)
    /// Deterministic keychain tag for a given credential ID. Shared between
    /// `register()` (which creates the item) and tests (which verify its
    /// access-control attributes) to avoid duplicating the format.
    static func keyTag(for credentialId: Data) -> Data {
        Data("org.siros.sdk.localauth.\(credentialId.base64EncodedString())".utf8)
    }
    #endif

    private let lock = NSLock()
    private var credentials: [Data: CredentialEntry] = [:]

    /// The credential ID from the most recent register or authenticate call.
    public private(set) var lastCredentialId: Data?

    /// The PRF output from the most recent register or authenticate call.
    public private(set) var lastPrfOutput: PrfOutput?

    /// Remove the most recently registered credential from local storage.
    /// Call this when the backend rejects the registration to avoid orphaned passkeys.
    public func rollbackLastRegistration() {
        let removed: CredentialEntry? = lock.withLock {
            guard let credId = lastCredentialId else { return nil }
            let entry = credentials.removeValue(forKey: credId)
            lastCredentialId = nil
            lastPrfOutput = nil
            return entry
        }
        #if canImport(Security)
        if let tag = removed?.keyTag {
            deleteKey(tag: tag)
        }
        #endif
    }

    public init() {}

    /// Authenticator-data flags of an assertion: UP (0x01) and UV (0x04).
    /// Every signing key is created with `.userPresence` access control, so
    /// the keychain refuses to sign until the user passed biometry or the
    /// device passcode: verification is enforced for every assertion this
    /// provider produces, whatever the relying party asked for, and the UV
    /// bit is therefore truthful. Without it a relying party that requires
    /// verification (the account-deletion step-up does) rejects the assertion.
    static let assertionFlags: UInt8 = 0x01 | 0x04

    #if canImport(Security)
    public func register(options: RegisterOptions) async throws -> RegisterResult {
        // Generate a random credential ID
        var credentialId = Data(count: 32)
        credentialId.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }

        // Require device authentication (biometry or passcode) before this
        // key can ever be used to sign. A bare `SecKeyCreateRandomKey` key
        // (the previous behavior) has no such gate at all — signing always
        // succeeds unconditionally, with zero device-authentication
        // guarantee. `.userPresence` (rather than `.biometryCurrentSet`) is
        // used so the key isn't invalidated by biometry re-enrollment and
        // still allows passcode fallback.
        var acError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &acError
        ) else {
            throw SirosError.auth(message: "Failed to create access control: \(String(describing: acError))")
        }

        let keyTag = Self.keyTag(for: credentialId)

        // Generate EC P-256 key pair. It must be persisted
        // (`kSecAttrIsPermanent: true`) for the access-control gate to be
        // enforceable at all — enforcement happens via the keychain item,
        // not the bare in-memory key reference — and so `signWithKey` can
        // re-fetch it through `SecItemCopyMatching`/`kSecUseAuthenticationContext`.
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: accessControl,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw SirosError.auth(message: "Failed to generate key pair")
        }

        // Build authenticator data
        let rpIdHash = sha256(Data(options.rpId.utf8))
        let flags: UInt8 = 0x41 // UP + AT
        var signCount: UInt32 = 0
        let signCountBytes = withUnsafeBytes(of: &signCount) { Data($0) }

        // AAGUID: "SIRO S-WA LLET -KEY" as bytes
        let aaguid = Data([0x53, 0x49, 0x52, 0x4F, 0x20, 0x53, 0x2D, 0x57,
                           0x41, 0x20, 0x4C, 0x4C, 0x45, 0x54, 0x20, 0x2D])

        // Credential ID length (big-endian 16-bit)
        let credIdLen = UInt16(credentialId.count).bigEndian
        let credIdLenBytes = withUnsafeBytes(of: credIdLen) { Data($0) }

        // Export public key in COSE format
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw SirosError.auth(message: "Failed to export public key")
        }

        // The external representation is 04 || x || y (65 bytes for P-256)
        let x = pubKeyData[1...32]
        let y = pubKeyData[33...64]
        let coseKey = cborCoseEC2Key(x: Data(x), y: Data(y))

        var authData = Data()
        authData.append(rpIdHash)
        authData.append(flags)
        authData.append(signCountBytes)
        authData.append(aaguid)
        authData.append(credIdLenBytes)
        authData.append(credentialId)
        authData.append(coseKey)

        // Build "none" attestation object (CBOR map)
        let attestationObject = cborAttestationNone(authData: authData)

        // Build clientDataJSON
        let clientData: [String: Any] = [
            "type": "webauthn.create",
            "challenge": base64UrlEncode(options.challenge),
            "origin": "https://\(options.rpId)",
        ]
        let clientDataJSON = try JSONSerialization.data(withJSONObject: clientData)

        // PRF output if salt provided
        var prfOutput: PrfOutput?
        if let salt = options.prfSalt {
            prfOutput = computePrf(credentialId: credentialId, salt: salt)
        }

        // Store credential
        let entry = CredentialEntry(
            credentialId: credentialId,
            rpId: options.rpId,
            userHandle: options.userId,
            userName: options.userName,
            signCount: 0,
            keyTag: keyTag
        )
        lock.withLock {
            credentials[credentialId] = entry
            lastCredentialId = credentialId
            lastPrfOutput = prfOutput
        }

        return RegisterResult(
            credentialId: credentialId,
            attestationObject: attestationObject,
            clientDataJSON: clientDataJSON,
            prfOutput: prfOutput
        )
    }

    public func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult {
        let found: CredentialEntry = try lock.withLock {
            var entry: CredentialEntry?
            if let allowed = options.allowCredentials {
                for cred in allowed {
                    if let found = credentials[cred.id] {
                        entry = found
                        break
                    }
                }
            } else {
                entry = credentials.values.first { $0.rpId == options.rpId }
            }
            guard var result = entry else {
                throw SirosError.auth(message: "No matching credential found for rpId: \(options.rpId)")
            }
            result.signCount += 1
            credentials[result.credentialId] = result
            return result
        }

        // Build authenticator data
        let rpIdHash = sha256(Data(options.rpId.utf8))
        let flags = Self.assertionFlags
        var signCount = found.signCount.bigEndian
        let signCountBytes = withUnsafeBytes(of: &signCount) { Data($0) }

        var authData = Data()
        authData.append(rpIdHash)
        authData.append(flags)
        authData.append(signCountBytes)

        // Build clientDataJSON
        let clientData: [String: Any] = [
            "type": "webauthn.get",
            "challenge": base64UrlEncode(options.challenge),
            "origin": "https://\(options.rpId)",
        ]
        let clientDataJSON = try JSONSerialization.data(withJSONObject: clientData)

        // Sign authData || SHA-256(clientDataJSON)
        let clientDataHash = sha256(clientDataJSON)
        var signedData = authData
        signedData.append(clientDataHash)

        let signature = try signWithKey(tag: found.keyTag, data: signedData)

        // PRF output if a salt applies to the chosen credential
        var prfOutput: PrfOutput?
        if let salt = options.prfSalt(for: found.credentialId) {
            prfOutput = computePrf(credentialId: found.credentialId, salt: salt)
        }

        lock.withLock {
            lastCredentialId = found.credentialId
            lastPrfOutput = prfOutput
        }

        return AuthenticateResult(
            credentialId: found.credentialId,
            authenticatorData: authData,
            clientDataJSON: clientDataJSON,
            signature: signature,
            userHandle: found.userHandle,
            prfOutput: prfOutput
        )
    }

    public func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput {
        computePrf(credentialId: credentialId, salt: salt)
    }
    #else
    public func register(options: RegisterOptions) async throws -> RegisterResult {
        throw SirosError.auth(message: "LocalAuthProvider is not available on this platform")
    }

    public func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult {
        throw SirosError.auth(message: "LocalAuthProvider is not available on this platform")
    }

    public func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput {
        throw SirosError.auth(message: "LocalAuthProvider is not available on this platform")
    }
    #endif

    // MARK: - Internal helpers

    #if canImport(CommonCrypto)
    private func sha256(_ data: Data) -> Data {
        var hash = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { dataPtr in
            hash.withUnsafeMutableBytes { hashPtr in
                _ = CC_SHA256(dataPtr.baseAddress, CC_LONG(data.count), hashPtr.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return hash
    }

    /// Software PRF for this dev/test provider: HMAC-SHA-256 keyed with the
    /// credential ID over the salt. Documented divergence from the Kotlin
    /// SDK's `LocalAuthProvider`, which keys the same HMAC with
    /// `credentialId || "SIROS-LOCAL-PRF-v1"`. Neither provider's credentials
    /// roam, so a container sealed by one is never presented to the other;
    /// reconciling would only re-key existing dev wallets on one platform.
    /// Not a substitute for a real authenticator's PRF - see
    /// `ASAuthorizationAuthProvider.getPrfOutput`, which fails closed.
    private func computePrf(credentialId: Data, salt: Data) -> PrfOutput {
        // HMAC-SHA-256 with credentialId as key and salt as message
        let key = credentialId
        var hmac = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        key.withUnsafeBytes { keyPtr in
            salt.withUnsafeBytes { saltPtr in
                hmac.withUnsafeMutableBytes { hmacPtr in
                    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
                            keyPtr.baseAddress, key.count,
                            saltPtr.baseAddress, salt.count,
                            hmacPtr.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        return PrfOutput(first: hmac)
    }
    #endif

    private func base64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    #if canImport(Security)
    /// Fetch the persisted, access-control-gated `SecKey` for `tag` and sign
    /// `data` with it. Re-fetching via `SecItemCopyMatching` (rather than
    /// reusing an in-memory reference) is what actually threads device
    /// authentication through the operation: `kSecUseAuthenticationContext`
    /// only applies to `SecItem*` queries, and is the only way to plug in an
    /// explicit `LAContext` (e.g. a caller-supplied, pre-evaluated context
    /// with a custom prompt reason) rather than relying on the system's
    /// default authentication UI.
    private func signWithKey(tag: Data, data: Data, context: LAContext? = nil) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        #if canImport(LocalAuthentication)
        query[kSecUseAuthenticationContext as String] = context ?? LAContext()
        #endif

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            throw SirosError.auth(
                message: "Failed to retrieve signing key (status \(status)) " +
                    "— device authentication may have failed, been cancelled, or wasn't available"
            )
        }
        // Bridged CFTypeRef -> SecKey (Security framework CF/Swift toll-free bridging).
        let key = item as! SecKey // swiftlint:disable:this force_cast

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            throw SirosError.auth(message: "Signing failed")
        }
        return signature
    }

    /// Remove the persisted keychain item for `tag`, so a dev/test-only
    /// provider doesn't leave real keychain entries behind after a rolled
    /// back or otherwise abandoned registration.
    private func deleteKey(tag: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
        ]
        SecItemDelete(query as CFDictionary)
    }
    #endif

    // MARK: - CBOR helpers

    private func cborCoseEC2Key(x: Data, y: Data) -> Data {
        // COSE_Key map: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        var out = Data()
        out.append(0xA5) // map of 5 items
        out.append(contentsOf: cborUInt(1)); out.append(contentsOf: cborUInt(2))       // kty: EC2
        out.append(contentsOf: cborUInt(3)); out.append(contentsOf: cborNegInt(6))      // alg: ES256 (-7)
        out.append(contentsOf: cborNegInt(0)); out.append(contentsOf: cborUInt(1))      // crv: P-256
        out.append(contentsOf: cborNegInt(1)); out.append(contentsOf: cborBytes(x))     // x
        out.append(contentsOf: cborNegInt(2)); out.append(contentsOf: cborBytes(y))     // y
        return out
    }

    private func cborAttestationNone(authData: Data) -> Data {
        // {"fmt": "none", "attStmt": {}, "authData": <bytes>}
        var out = Data()
        out.append(0xA3) // map of 3 items
        out.append(contentsOf: cborText("fmt")); out.append(contentsOf: cborText("none"))
        out.append(contentsOf: cborText("attStmt")); out.append(0xA0) // empty map
        out.append(contentsOf: cborText("authData")); out.append(contentsOf: cborBytes(authData))
        return out
    }

    private func cborUInt(_ value: UInt64) -> Data {
        if value < 24 { return Data([UInt8(value)]) }
        if value <= UInt8.max { return Data([0x18, UInt8(value)]) }
        if value <= UInt16.max {
            var v = UInt16(value).bigEndian
            return Data([0x19]) + Data(bytes: &v, count: 2)
        }
        var v = UInt32(value).bigEndian
        return Data([0x1A]) + Data(bytes: &v, count: 4)
    }

    private func cborNegInt(_ value: UInt64) -> Data {
        // CBOR negative: major type 1, value = -1 - n → encode n
        if value < 24 { return Data([0x20 | UInt8(value)]) }
        return Data([0x38, UInt8(value)])
    }

    private func cborBytes(_ data: Data) -> Data {
        var header = Data()
        let len = UInt64(data.count)
        if len < 24 { header.append(0x40 | UInt8(len)) }
        else if len <= UInt8.max { header.append(contentsOf: [0x58, UInt8(len)]) }
        else {
            var v = UInt16(len).bigEndian
            header.append(0x59)
            header.append(contentsOf: Data(bytes: &v, count: 2))
        }
        return header + data
    }

    private func cborText(_ string: String) -> Data {
        let utf8 = Data(string.utf8)
        let len = UInt64(utf8.count)
        var header = Data()
        if len < 24 { header.append(0x60 | UInt8(len)) }
        else if len <= UInt8.max { header.append(contentsOf: [0x78, UInt8(len)]) }
        else {
            var v = UInt16(len).bigEndian
            header.append(0x79)
            header.append(contentsOf: Data(bytes: &v, count: 2))
        }
        return header + utf8
    }
}
