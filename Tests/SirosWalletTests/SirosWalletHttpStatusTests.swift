// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
import SirosCredentials
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

/// `SirosWallet.defaultHttpFn` is the transport every client the wallet builds
/// runs over, so the lifecycle protocol - which is expressed entirely in status
/// codes and error bodies - only works if it turns a non-2xx into
/// `SirosError.backendApi` with both preserved. It used to discard the
/// response, which made the blocked-state and erasure-retry paths unreachable
/// in a real app while every unit test - each injecting its own transport -
/// stayed green. These drive the real function, so reverting it fails them.
final class SirosWalletHttpStatusTests: XCTestCase {

    private func send(status: Int, body: String) async throws -> Data {
        let server = try LoopbackServer(status: status, body: body)
        defer { server.stop() }
        let url = URL(string: "http://127.0.0.1:\(server.port)/auth/passkey/login/finish")!
        return try await SirosWallet.defaultHttpFn("POST", url, [:], nil)
    }

    func testSuccessfulResponseIsReturnedUnchanged() async throws {
        let data = try await send(status: 200, body: #"{"uuid":"u"}"#)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), #"{"uuid":"u"}"#)
    }

    /// The case the whole blocked-state path depends on.
    func testLifecycleRefusalArrivesAsBackendApiWithStatusAndBody() async throws {
        let body = #"{"error":"WALLET_SUSPENDED","message":"This device is suspended"}"#
        do {
            _ = try await send(status: 403, body: body)
            XCTFail("a 403 must not be reported as success")
        } catch let error as SirosError {
            guard case let .backendApi(code, _, carried) = error else {
                return XCTFail("expected .backendApi, got \(error)")
            }
            XCTAssertEqual(code, 403)
            XCTAssertEqual(carried, body, "the body must survive - the refusal code is in it")
            XCTAssertEqual(error.walletLifecycleRefusal, .suspended)
        }
    }

    /// The case the erasure retry depends on.
    func testErasureIncompleteArrivesAsBackendApi409() async throws {
        let body = #"{"error":"ERASURE_INCOMPLETE","revoked":2}"#
        do {
            _ = try await send(status: 409, body: body)
            XCTFail("a 409 must not be reported as success")
        } catch let error as SirosError {
            guard case let .backendApi(code, _, carried) = error else {
                return XCTFail("expected .backendApi, got \(error)")
            }
            XCTAssertEqual(code, 409)
            XCTAssertEqual(carried, body)
        }
    }
}
