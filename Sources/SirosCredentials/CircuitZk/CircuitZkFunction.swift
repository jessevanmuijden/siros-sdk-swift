// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One planned function of a `circuit_zk` request (`id`, `handle`, raw `params`).
public struct CircuitZkFunction: Sendable, Equatable {
    public let id: String
    public let handle: String
    public let params: [String: JSONValue]

    public init(id: String, handle: String, params: [String: JSONValue] = [:]) {
        self.id = id
        self.handle = handle
        self.params = params
    }
}
