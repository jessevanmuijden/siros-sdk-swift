// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// Plain-data types for a planned `circuit_zk` request and the wallet's circuits.
// Mirror of the Kotlin SDK's CircuitZkMatching.kt data types; the planner and the
// matcher glue that produce and consume them are separate.

/// A request's circuit list: the verifier's two independent lists
/// (`circuit_proof_system_values`, `circuit_id_values`), kept as two lists. A
/// circuit is admitted when its system is in `proofSystems` AND its id (or an
/// alias) is in `circuitIds`; a list the verifier did not send is nil and
/// constrains nothing, and a list sent empty admits nothing. Deliberately not
/// expanded into pairs: both lists are verifier-controlled and their product is an
/// allocation an untrusted request could make arbitrarily large.
public struct CircuitZkCircuitFilter: Sendable, Equatable {
    public let proofSystems: [String]?
    public let circuitIds: [String]?

    public init(proofSystems: [String]?, circuitIds: [String]?) {
        self.proofSystems = proofSystems
        self.circuitIds = circuitIds
    }

    public func admits(_ circuit: CircuitZkCircuit) -> Bool {
        (proofSystems?.contains(circuit.system) ?? true)
            && (circuitIds.map { ids in ids.contains(circuit.circuitId) || circuit.aliases.contains(where: ids.contains) } ?? true)
    }
}

/// What a `circuit_zk` credential query asks for, as plain data. `raw` is the
/// credential query the plan was made from.
public struct CircuitZkPlan: Sendable, Equatable {
    public let functions: [CircuitZkFunction]
    public let circuitFilter: CircuitZkCircuitFilter?
    public let raw: [String: JSONValue]

    public init(functions: [CircuitZkFunction], circuitFilter: CircuitZkCircuitFilter? = nil, raw: [String: JSONValue] = [:]) {
        self.functions = functions
        self.circuitFilter = circuitFilter
        self.raw = raw
    }
}

/// A circuit the wallet can prove with.
public struct CircuitZkCircuit: Sendable, Equatable {
    public let system: String
    public let circuitId: String
    public let docTypes: Set<String>
    /// The declared function set; nil declares none (no function filtering).
    public let functions: Set<String>?
    public let aliases: Set<String>
    public let credentialType: String?
    public let capabilities: String?
    /// The catalog `systemVersion`; nil when the source does not know it.
    public let systemVersion: String?

    public init(
        system: String, circuitId: String, docTypes: Set<String>, functions: Set<String>? = nil,
        aliases: Set<String> = [], credentialType: String? = nil, capabilities: String? = nil,
        systemVersion: String? = nil
    ) {
        self.system = system
        self.circuitId = circuitId
        self.docTypes = docTypes
        self.functions = functions
        self.aliases = aliases
        self.credentialType = credentialType
        self.capabilities = capabilities
        self.systemVersion = systemVersion
    }

    /// Whether the matcher, not this SDK, decides if the circuit serves a request:
    /// it declares `capabilities` or a `credentialType`.
    public var constrainedByMatcher: Bool { capabilities != nil || credentialType != nil }
}

/// The current circuits (typically from the circuit catalog).
public protocol CircuitZkCircuitSource: Sendable {
    func circuits() -> [CircuitZkCircuit]
}

/// The outcome of validating a plan. `accessDenied`'s rule id is for local logs
/// and tests; it must never reach the verifier, which only sees `access_denied`.
public enum CircuitZkVerdict: Sendable, Equatable {
    case ok
    case accessDenied(ruleId: String)
}

/// Decides whether a planned request is satisfiable before anything else happens.
public protocol CircuitZkRequestValidator: Sendable {
    func validate(_ plan: CircuitZkPlan) -> CircuitZkVerdict
}
