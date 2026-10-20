// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// The proving seam of the `nymauth-*` circuits: ONE narrow call that takes the verified circuit
// bytes and the already-assembled inputs and returns the proof and the pseudonym (the ABI the
// circuit authors define, mirrored from siros-sdk-kotlin's NymAuthNativeProver).
//
// Native code is needed here and none is shipped: the vendored Longfellow and Vega bindings
// expose the generic mdoc/age circuits only. Until a binding implements `NymAuthNativeProver`,
// the default (`RefusingNymAuthNativeProver`) refuses every request; the SDK never substitutes
// another proof. An implementation MUST NOT log or retain any argument: `secretSeed` is the
// issuer-delivered seed and the circuit input is private.

/// Proves a `nymauth-*` request. Any failure is a thrown ``NymAuthNativeError``.
public protocol NymAuthNativeProver: Sendable {
    func prove(_ request: NymAuthProveRequest) async throws -> NymAuthProveResponse
}

/// The coarse reason a native prover refused to make a proof (never the broken rule, never a value).
public enum NymAuthRefusal: String, Sendable, Equatable {
    case seedMismatch, issuerSignature, deviceSignature, credential, unsatisfied
}

/// The kinds of failure a native nymauth binding reports: a superset of the Vega and Longfellow error types.
public enum NymAuthNativeErrorKind: String, Sendable, Equatable {
    /// An argument has the wrong size, format or range.
    case invalidInput
    /// The circuit artifact is malformed or past its budget.
    case invalidCircuit
    /// The circuit is well formed but not one this build knows: this app version does not support it.
    case unsupportedCircuit
    /// The inputs break a rule; see ``NymAuthRefusal``.
    case refused
    /// The prover failed.
    case proverFailed
    /// The proof does not verify.
    case proofInvalid
    /// The proof verifies, but not for the named values.
    case mismatch
    /// A bug in the binding (a caught panic).
    case `internal`
    /// No native prover is wired in (the default).
    case noNativeProver
}

/// What a ``NymAuthNativeProver`` throws. It carries a ``kind`` and, for `.refused`, a coarse
/// ``refusal``, and NO message: the bindings' own messages can hold a circuit digest or a rule, and
/// nothing of them is kept.
public struct NymAuthNativeError: Error, Sendable, Equatable, CustomStringConvertible {
    public let kind: NymAuthNativeErrorKind
    public let refusal: NymAuthRefusal?

    public init(_ kind: NymAuthNativeErrorKind, refusal: NymAuthRefusal? = nil) {
        self.kind = kind
        self.refusal = refusal
    }

    public var description: String { "nymauth native prover: \(kind.rawValue)" + (refusal.map { " (\($0.rawValue))" } ?? "") }

    /// The Vega binding's error by variant name and, for `Refused`, its coarse `code`.
    public static func vega(variant: String, refusedCode: String? = nil) -> NymAuthNativeError {
        switch variant {
        case "InvalidInput": return NymAuthNativeError(.invalidInput)
        case "InvalidShapes": return NymAuthNativeError(.invalidCircuit)
        case "UnknownCircuit": return NymAuthNativeError(.unsupportedCircuit)
        case "Refused": return NymAuthNativeError(.refused, refusal: refusal(ofVegaCode: refusedCode))
        case "ProverFailed": return NymAuthNativeError(.proverFailed)
        case "ProofInvalid": return NymAuthNativeError(.proofInvalid)
        case "Mismatch": return NymAuthNativeError(.mismatch)
        default: return NymAuthNativeError(.internal)
        }
    }

    /// The Longfellow binding's `NymAuthError` by variant name.
    public static func longfellow(variant: String) -> NymAuthNativeError {
        switch variant {
        case "InvalidInput": return NymAuthNativeError(.invalidInput)
        case "Circuit": return NymAuthNativeError(.invalidCircuit)
        case "UnsupportedCircuit": return NymAuthNativeError(.unsupportedCircuit)
        case "Credential": return NymAuthNativeError(.refused, refusal: .credential)
        case "Unsatisfied": return NymAuthNativeError(.refused, refusal: .unsatisfied)
        case "Prover": return NymAuthNativeError(.proverFailed)
        case "Verification": return NymAuthNativeError(.proofInvalid)
        default: return NymAuthNativeError(.internal)
        }
    }

    private static func refusal(ofVegaCode code: String?) -> NymAuthRefusal {
        switch code {
        case "SeedMismatch": return .seedMismatch
        case "IssuerSignature": return .issuerSignature
        case "DeviceSignature": return .deviceSignature
        case "Credential": return .credential
        default: return .unsatisfied // a code this build does not know is still a refusal; it is not guessed at
        }
    }
}

/// What ``NymAuthNativeProver/prove(_:)`` receives. Everything here is derived by the SDK from the
/// stored credential, the verifier's request and the device signer; the native side does not parse
/// the request. Its description, debug description and mirror are redacted.
public struct NymAuthProveRequest: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The catalog `system` of the circuit.
    public let system: String
    public let circuitId: String
    /// The catalog descriptor's `params`, verbatim.
    public let circuitParams: [String: JSONValue]
    /// The decompressed circuit artifact, its hash verified against the catalog. Do not retain it past the call.
    public let circuit: Data
    /// The credential's `IssuerSigned` structure as CBOR.
    public let issuerSigned: Data
    /// The 16-byte issuer-delivered `secret_seed`, already checked against `ssc`.
    public let secretSeed: [UInt8]
    /// Big-endian x and y of the issuer key (the `x5chain` leaf), 32 bytes each.
    public let issuerKeyX: [UInt8]
    public let issuerKeyY: [UInt8]
    /// `T`: `YYYY-MM-DDThh:mm:ssZ`, 20 ASCII characters.
    public let time: String
    /// `E`: `YYYY-MM-DD`, `0000-00-00` for no lower bound.
    public let earliest: String
    /// `C`: `YYYY-MM-DD`, `9999-12-31` for no upper bound.
    public let cutoff: String
    /// `e2`: SHA-256 of the COSE `Signature1` message the device key signed.
    public let challengeDigest: [UInt8]
    /// The device key's ES256 signature on that message, `r || s`, 64 bytes.
    public let deviceSignature: [UInt8]
    /// `SHA-256(verifier_id)`, 32 bytes.
    public let verifierInput: [UInt8]
    /// The SessionTranscript the proof is bound to (Longfellow's Fiat-Shamir seed).
    public let transcriptSeed: [UInt8]

    public init(
        system: String, circuitId: String, circuitParams: [String: JSONValue], circuit: Data, issuerSigned: Data,
        secretSeed: [UInt8], issuerKeyX: [UInt8], issuerKeyY: [UInt8], time: String, earliest: String, cutoff: String,
        challengeDigest: [UInt8], deviceSignature: [UInt8], verifierInput: [UInt8], transcriptSeed: [UInt8]
    ) {
        self.system = system
        self.circuitId = circuitId
        self.circuitParams = circuitParams
        self.circuit = circuit
        self.issuerSigned = issuerSigned
        self.secretSeed = secretSeed
        self.issuerKeyX = issuerKeyX
        self.issuerKeyY = issuerKeyY
        self.time = time
        self.earliest = earliest
        self.cutoff = cutoff
        self.challengeDigest = challengeDigest
        self.deviceSignature = deviceSignature
        self.verifierInput = verifierInput
        self.transcriptSeed = transcriptSeed
    }

    public var description: String { "NymAuthProveRequest(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// What ``NymAuthNativeProver/prove(_:)`` returns: the proof bytes as the circuit's own verifier
/// reads them, and the pseudonym it reports. Redacted like the request.
public struct NymAuthProveResponse: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let proof: [UInt8]
    public let pseudonym: [UInt8]

    public init(proof: [UInt8], pseudonym: [UInt8]) {
        self.proof = proof
        self.pseudonym = pseudonym
    }

    public var description: String { "NymAuthProveResponse(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// The default: no native prover is wired in, so every request is refused. Never a fallback to
/// another proof.
public struct RefusingNymAuthNativeProver: NymAuthNativeProver {
    public init() {}

    public func prove(_ request: NymAuthProveRequest) async throws -> NymAuthProveResponse {
        throw NymAuthNativeError(.noNativeProver)
    }
}

/// Holds the native prover a host supplies (at most one). With none, ``prover`` is the refusing
/// default and ``canProve`` is false, so a presenter can leave the circuit out of its choices.
public final class NymAuthNativeProverRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var registered: (any NymAuthNativeProver)?

    public init(_ prover: (any NymAuthNativeProver)? = nil) { registered = prover }

    /// Whether a native prover is wired in; false means every request is refused.
    public var canProve: Bool { lock.withLock { registered != nil } }

    /// The registered prover, or the refusing default.
    public var prover: any NymAuthNativeProver { lock.withLock { registered } ?? RefusingNymAuthNativeProver() }

    /// Supplies (or, with nil, removes) the native prover.
    public func register(_ prover: (any NymAuthNativeProver)?) { lock.withLock { registered = prover } }
}
