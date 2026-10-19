// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The `result` of a `wmp.flow.complete` for an OpenID4VCI issuance, with the same
/// guarantees as the engine's ``FlowCompleteMessage``: decoding never throws on the
/// metadata members, the metadata is kept verbatim and never printed or re-encoded.
///
/// A REPLAYED completion (after a reconnect or resume) is a redacted copy: it names the
/// members it had removed in ``redactedMembers`` (WMP spec), and `credentials` are kept.
/// A member listed there is not recoverable (see ``RedactedMembers``). The live completion
/// on the connected SSE stream is complete and has no marker.
public struct WmpFlowCompleteResult: Decodable, Sendable {
    public var credentials: [CredentialResult]?
    public var credentialMetadata: CredentialResponseMetadata?
    public var credentialMetadataEncryptedResponse: LenientFlag?
    public var redactedMembers: RedactedMembers?
    public var refreshToken: String?
    public var dpopJwk: String?
    public var dpopKeyId: String?

    enum CodingKeys: String, CodingKey {
        case credentials
        case credentialMetadata = "credential_metadata"
        case credentialMetadataEncryptedResponse = "credential_metadata_encrypted_response"
        case redactedMembers = "redacted_members"
        case refreshToken = "refresh_token"
        case dpopJwk = "dpop_jwk"
        case dpopKeyId = "dpop_key_id"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // A credential list that does not decode is an error: nothing can be stored without it.
        credentials = try c.decodeIfPresent([CredentialResult].self, forKey: .credentials)
        credentialMetadata = try c.decodeIfPresent(CredentialResponseMetadata.self, forKey: .credentialMetadata)
        credentialMetadataEncryptedResponse = try c.decodeIfPresent(LenientFlag.self, forKey: .credentialMetadataEncryptedResponse)
        redactedMembers = try c.decodeIfPresent(RedactedMembers.self, forKey: .redactedMembers)
        // Withheld or mistyped token members are simply absent, never a failure of the frame.
        refreshToken = (try? c.decodeIfPresent(String.self, forKey: .refreshToken)) ?? nil
        dpopJwk = (try? c.decodeIfPresent(String.self, forKey: .dpopJwk)) ?? nil
        dpopKeyId = (try? c.decodeIfPresent(String.self, forKey: .dpopKeyId)) ?? nil
    }

    /// Decodes the `result` of a `FlowCompleteParams`.
    public init(result: AnyCodable) throws {
        let data = try JSONEncoder().encode(result)
        self = try JSONDecoder().decode(WmpFlowCompleteResult.self, from: data)
    }

    /// True when the issuer's metadata (and so any delivered seed) was withheld from this
    /// copy: the seed is UNAVAILABLE and must never be invented or substituted.
    public var credentialMetadataWithheld: Bool {
        redactedMembers?.contains(RedactedMembers.credentialMetadata) ?? false
    }

    /// True when the renewal material of this issuance (refresh token or its DPoP key) was
    /// withheld: renewal for it is unavailable and the client re-issues.
    public var renewalMaterialWithheld: Bool {
        guard let redacted = redactedMembers else { return false }
        return redacted.contains(RedactedMembers.refreshToken) || redacted.contains(RedactedMembers.dpopJwk)
            || redacted.contains(RedactedMembers.dpopKeyId)
    }
}

extension WmpFlowCompleteResult: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Redacted: the result carries credentials, tokens and possibly a seed.
    public var description: String { "WmpFlowCompleteResult(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}
