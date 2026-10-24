// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// MARK: - WMP Metadata

/// WMP metadata envelope present in every request/response.
public struct WmpMeta: Codable, Sendable, Equatable {
    public static let wmpVersion = "0.1"

    public var version: String
    public var sessionId: String?
    public var sender: String?
    public var timestamp: String?
    public var traceId: String?
    // swiftlint:disable:next discouraged_optional_boolean
    public var encrypted: Bool?

    public init(
        version: String = WmpMeta.wmpVersion,
        sessionId: String? = nil,
        sender: String? = nil,
        timestamp: String? = nil,
        traceId: String? = nil,
        // swiftlint:disable:next discouraged_optional_boolean
        encrypted: Bool? = nil
    ) {
        self.version = version
        self.sessionId = sessionId
        self.sender = sender
        self.timestamp = timestamp
        self.traceId = traceId
        self.encrypted = encrypted
    }

    enum CodingKeys: String, CodingKey {
        case version, sender, timestamp, encrypted
        case sessionId = "session_id"
        case traceId = "trace_id"
    }
}

// MARK: - JSON-RPC 2.0

/// JSON-RPC 2.0 request.
public struct JsonRpcRequest: Codable, Sendable, Equatable {
    public var jsonrpc: String
    public var id: String?
    public var method: String
    public var params: [String: AnyCodable]?

    public init(
        jsonrpc: String = "2.0",
        id: String? = nil,
        method: String,
        params: [String: AnyCodable]? = nil
    ) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.method = method
        self.params = params
    }
}

/// JSON-RPC 2.0 response.
public struct JsonRpcResponse: Codable, Sendable, Equatable {
    public var jsonrpc: String
    public var id: String?
    public var result: [String: AnyCodable]?
    public var error: JsonRpcError?

    public init(
        jsonrpc: String = "2.0",
        id: String? = nil,
        result: [String: AnyCodable]? = nil,
        error: JsonRpcError? = nil
    ) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.result = result
        self.error = error
    }
}

/// JSON-RPC error object.
public struct JsonRpcError: Codable, Sendable, Equatable {
    public var code: Int
    public var message: String
    public var data: AnyCodable?

    public init(code: Int, message: String, data: AnyCodable? = nil) {
        self.code = code
        self.message = message
        self.data = data
    }
}

// MARK: - Session lifecycle types

/// WMP session creation parameters.
public struct SessionCreateParams: Codable, Sendable {
    public var wmp: WmpMeta
    public var participants: [String]?
    public var capabilitiesOffered: [String: AnyCodable]?
    public var security: [String: AnyCodable]?
    public var ttl: Int?
    public var auth: SessionAuth?

    public init(
        wmp: WmpMeta,
        participants: [String]? = nil,
        capabilitiesOffered: [String: AnyCodable]? = nil,
        security: [String: AnyCodable]? = nil,
        ttl: Int? = nil,
        auth: SessionAuth? = nil
    ) {
        self.wmp = wmp
        self.participants = participants
        self.capabilitiesOffered = capabilitiesOffered
        self.security = security
        self.ttl = ttl
        self.auth = auth
    }

    enum CodingKeys: String, CodingKey {
        case wmp, participants, security, ttl, auth
        case capabilitiesOffered = "capabilities_offered"
    }
}

/// Session authentication.
public struct SessionAuth: Codable, Sendable {
    public var type: String
    public var token: String

    public init(type: String, token: String) {
        self.type = type
        self.token = token
    }
}

/// WMP session creation result.
public struct SessionCreateResult: Codable, Sendable {
    public var wmp: WmpMeta
    public var capabilities: [String: AnyCodable]?
    public var security: [String: AnyCodable]?
    public var challenge: String?
    public var resumptionToken: String?

    enum CodingKeys: String, CodingKey {
        case wmp, capabilities, security, challenge
        case resumptionToken = "resumption_token"
    }
}

/// WMP session resume parameters.
public struct SessionResumeParams: Codable, Sendable {
    public var wmp: WmpMeta
    public var sessionId: String
    public var resumptionToken: String
    public var lastReceivedId: String?

    public init(
        wmp: WmpMeta,
        sessionId: String,
        resumptionToken: String,
        lastReceivedId: String? = nil
    ) {
        self.wmp = wmp
        self.sessionId = sessionId
        self.resumptionToken = resumptionToken
        self.lastReceivedId = lastReceivedId
    }

    enum CodingKeys: String, CodingKey {
        case wmp
        case sessionId = "session_id"
        case resumptionToken = "resumption_token"
        case lastReceivedId = "last_received_id"
    }
}

/// WMP session resume result.
public struct SessionResumeResult: Codable, Sendable {
    public var wmp: WmpMeta
    public var resumed: Bool
    public var resumptionToken: String?
    public var missedMessages: Int?

    enum CodingKeys: String, CodingKey {
        case wmp, resumed
        case resumptionToken = "resumption_token"
        case missedMessages = "missed_messages"
    }
}

/// WMP session close parameters.
public struct SessionCloseParams: Codable, Sendable {
    public var wmp: WmpMeta
    public var reason: String?

    public init(wmp: WmpMeta, reason: String? = nil) {
        self.wmp = wmp
        self.reason = reason
    }
}

// MARK: - WMP Method Constants

public enum WmpMethods {
    public static let sessionCreate = "wmp.session.create"
    public static let sessionResume = "wmp.session.resume"
    public static let sessionClose = "wmp.session.close"
    public static let sessionAuthenticate = "wmp.session.authenticate"

    public static let flowStart = "wmp.flow.start"
    public static let flowProgress = "wmp.flow.progress"
    public static let flowAction = "wmp.flow.action"
    public static let flowComplete = "wmp.flow.complete"
    public static let flowError = "wmp.flow.error"
    public static let flowCancel = "wmp.flow.cancel"

    public static let messageDeliver = "wmp.message.deliver"
    public static let messageAck = "wmp.message.ack"

    public static let capabilityUpdate = "wmp.capability.update"

    public static let resolve = "wmp.resolve"

    public static let credentialNotification = "wmp.credential.notification"
}

/// Standard JSON-RPC error codes used by WMP.
public enum WmpErrorCodes {
    public static let parseError = -32700
    public static let invalidRequest = -32600
    public static let methodNotFound = -32601
    public static let invalidParams = -32602
    public static let internalError = -32603

    // WMP-specific error codes
    public static let sessionError = -32000
    public static let authRequired = -32001
    public static let authFailed = -32002
    public static let flowError = -32010
    public static let flowNotFound = -32011
    public static let flowCancelled = -32012
    public static let capabilityError = -32020
    public static let relayError = -32030
    public static let encryptionError = -32040
    public static let resolveError = -32050
}

// MARK: - Flow Types

/// Parameters for wmp.flow.start.
public struct FlowStartParams: Codable, Sendable {
    public var wmp: WmpMeta
    public var flowId: String
    public var flowType: String
    public var params: AnyCodable?

    public init(wmp: WmpMeta, flowId: String, flowType: String, params: AnyCodable? = nil) {
        self.wmp = wmp; self.flowId = flowId; self.flowType = flowType; self.params = params
    }

    enum CodingKeys: String, CodingKey {
        case wmp, params
        case flowId = "flow_id"
        case flowType = "flow_type"
    }
}

/// Result for wmp.flow.start.
public struct FlowStartResult: Codable, Sendable {
    public var wmp: WmpMeta?
    public var flowId: String
    public var flowType: String

    public init(wmp: WmpMeta? = nil, flowId: String, flowType: String) {
        self.wmp = wmp; self.flowId = flowId; self.flowType = flowType
    }

    enum CodingKeys: String, CodingKey {
        case wmp
        case flowId = "flow_id"
        case flowType = "flow_type"
    }
}

/// Parameters for wmp.flow.progress (notification).
public struct FlowProgressParams: Codable, Sendable {
    public var wmp: WmpMeta?
    public var flowId: String
    public var step: String
    public var payload: AnyCodable?

    public init(wmp: WmpMeta? = nil, flowId: String, step: String, payload: AnyCodable? = nil) {
        self.wmp = wmp; self.flowId = flowId; self.step = step; self.payload = payload
    }

    enum CodingKeys: String, CodingKey {
        case wmp, step, payload
        case flowId = "flow_id"
    }
}

/// Parameters for wmp.flow.action (request).
public struct FlowActionParams: Codable, Sendable {
    public var wmp: WmpMeta?
    public var flowId: String
    public var action: String
    public var params: AnyCodable?

    public init(wmp: WmpMeta? = nil, flowId: String, action: String, params: AnyCodable? = nil) {
        self.wmp = wmp; self.flowId = flowId; self.action = action; self.params = params
    }

    enum CodingKeys: String, CodingKey {
        case wmp, action, params
        case flowId = "flow_id"
    }
}

/// Result for wmp.flow.action.
public struct FlowActionResult: Codable, Sendable {
    public var wmp: WmpMeta?
    public var flowId: String
    public var accepted: Bool

    public init(wmp: WmpMeta? = nil, flowId: String, accepted: Bool = true) {
        self.wmp = wmp; self.flowId = flowId; self.accepted = accepted
    }

    enum CodingKeys: String, CodingKey {
        case wmp, accepted
        case flowId = "flow_id"
    }
}

/// Parameters for wmp.flow.complete (notification).
public struct FlowCompleteParams: Codable, Sendable {
    public var wmp: WmpMeta?
    public var flowId: String
    public var result: AnyCodable?

    public init(wmp: WmpMeta? = nil, flowId: String, result: AnyCodable? = nil) {
        self.wmp = wmp; self.flowId = flowId; self.result = result
    }

    enum CodingKeys: String, CodingKey {
        case wmp, result
        case flowId = "flow_id"
    }
}

/// Parameters for wmp.flow.error (notification).
public struct FlowErrorParams: Codable, Sendable {
    public var wmp: WmpMeta?
    public var flowId: String
    public var code: String?
    public var message: String?
    public var data: AnyCodable?

    public init(wmp: WmpMeta? = nil, flowId: String, code: String? = nil, message: String? = nil, data: AnyCodable? = nil) {
        self.wmp = wmp; self.flowId = flowId; self.code = code; self.message = message; self.data = data
    }

    /// The protocol's numeric flow-error code (go-wmp `ErrFlowError`); the application code travels in
    /// `data.error_code`.
    public static let flowErrorCode = -31006

    enum CodingKeys: String, CodingKey {
        case wmp, code, message, data
        case flowId = "flow_id"
    }

    /// `code` is a number on the wire (go-wmp `FlowErrorParams.Code` is an `int`); a string is accepted
    /// too, and either reads as text here.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        wmp = try c.decodeIfPresent(WmpMeta.self, forKey: .wmp)
        flowId = try c.decode(String.self, forKey: .flowId)
        if let number = try? c.decodeIfPresent(Int.self, forKey: .code) {
            code = String(number)
        } else {
            code = try c.decodeIfPresent(String.self, forKey: .code)
        }
        message = try c.decodeIfPresent(String.self, forKey: .message)
        data = try c.decodeIfPresent(AnyCodable.self, forKey: .data)
    }
}

/// Parameters for wmp.flow.cancel.
public struct FlowCancelParams: Codable, Sendable {
    public var wmp: WmpMeta?
    public var flowId: String
    public var reason: String?

    public init(wmp: WmpMeta? = nil, flowId: String, reason: String? = nil) {
        self.wmp = wmp; self.flowId = flowId; self.reason = reason
    }

    enum CodingKeys: String, CodingKey {
        case wmp, reason
        case flowId = "flow_id"
    }
}

/// Parameters for wmp.resolve.
public struct ResolveParams: Codable, Sendable {
    public var wmp: WmpMeta?
    public var type: String
    public var identifier: String
    public var params: AnyCodable?

    public init(wmp: WmpMeta? = nil, type: String, identifier: String, params: AnyCodable? = nil) {
        self.wmp = wmp; self.type = type; self.identifier = identifier; self.params = params
    }
}

/// Result for wmp.resolve.
public struct ResolveResult: Codable, Sendable {
    public var wmp: WmpMeta?
    public var type: String
    public var data: AnyCodable?

    public init(wmp: WmpMeta? = nil, type: String, data: AnyCodable? = nil) {
        self.wmp = wmp; self.type = type; self.data = data
    }
}
