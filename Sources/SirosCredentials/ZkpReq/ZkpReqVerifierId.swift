// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The `verifier_id` of nym_auth rulebook v0.4: the PREFIXED identifier, never the bare name. For
/// `x509_san_dns` it is the Client Identifier including its prefix (`x509_san_dns:verifier.example`); for
/// `semantic` it is `semantic_id:` followed by the semantic identifier (from the registration certificate when
/// present, otherwise the access certificate). `verifier_input` is `SHA-256(verifier_id)` over its UTF-8 bytes.
public enum ZkpReqVerifierId {
    public static let x509SanDnsPrefix = "x509_san_dns:"
    public static let semanticPrefix = "semantic_id:"

    /// `x509_san_dns:<dns name>`. A name that already carries the prefix is not prefixed twice.
    public static func x509SanDns(_ dnsName: String) -> String {
        dnsName.hasPrefix(x509SanDnsPrefix) ? dnsName : x509SanDnsPrefix + dnsName
    }

    /// `semantic_id:<semantic identifier>`. A value that already carries the prefix is not prefixed twice.
    public static func semantic(_ semanticId: String) -> String {
        semanticId.hasPrefix(semanticPrefix) ? semanticId : semanticPrefix + semanticId
    }

    /// `verifier_input = SHA-256(verifier_id)`, 32 bytes.
    public static func verifierInput(_ verifierId: String) -> [UInt8] {
        Array(SHA256.hash(data: Data(verifierId.utf8)))
    }
}
