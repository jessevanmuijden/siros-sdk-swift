// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A durable OID4VCI renewal candidate for one credential batch - see
/// privatedata-spec SPEC.md §6.2 "S.credentialRefreshTokens". `dpopJwk` MUST
/// be presented back unchanged on every renewal of the same batch (RFC
/// 9449/ARF ISSU_65 key-binding), never regenerated client-side.
public struct CredentialRefreshTokenEntry: Sendable, Equatable {
    public let refreshToken: String
    public let dpopJwk: String?
    public let credentialIssuerIdentifier: String
    public let credentialConfigurationId: String
    /// Identifier of the client-held DPoP key the token is bound to when this
    /// wallet signed the DPoP proofs itself (`sign_client_auth`,
    /// go-wallet-backend#317) - `dpopJwk` is nil in that case. Presented back
    /// as `dpop_key_id` on renewal so the engine asks this wallet to sign with
    /// the same key.
    public let dpopKeyId: String?

    public init(
        refreshToken: String,
        dpopJwk: String?,
        credentialIssuerIdentifier: String,
        credentialConfigurationId: String,
        dpopKeyId: String? = nil
    ) {
        self.refreshToken = refreshToken
        self.dpopJwk = dpopJwk
        self.credentialIssuerIdentifier = credentialIssuerIdentifier
        self.credentialConfigurationId = credentialConfigurationId
        self.dpopKeyId = dpopKeyId
    }

    func toJsonObject() -> [String: Any] {
        var dict: [String: Any] = [
            "refreshToken": refreshToken,
            "credentialIssuerIdentifier": credentialIssuerIdentifier,
            "credentialConfigurationId": credentialConfigurationId,
        ]
        if let dpopJwk { dict["dpopJwk"] = dpopJwk }
        if let dpopKeyId { dict["dpopKeyId"] = dpopKeyId }
        return dict
    }

    static func fromJsonObject(_ obj: [String: Any]) -> CredentialRefreshTokenEntry? {
        guard let refreshToken = obj["refreshToken"] as? String,
              let credentialIssuerIdentifier = obj["credentialIssuerIdentifier"] as? String,
              let credentialConfigurationId = obj["credentialConfigurationId"] as? String else {
            return nil
        }
        return CredentialRefreshTokenEntry(
            refreshToken: refreshToken,
            dpopJwk: obj["dpopJwk"] as? String,
            credentialIssuerIdentifier: credentialIssuerIdentifier,
            credentialConfigurationId: credentialConfigurationId,
            dpopKeyId: obj["dpopKeyId"] as? String
        )
    }
}
