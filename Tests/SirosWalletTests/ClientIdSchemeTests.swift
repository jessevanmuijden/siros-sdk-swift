// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class ClientIdSchemeTests: XCTestCase {

    func testParsePlainDidReturnsDidCaseWithFullDidAsIdentifier() {
        let scheme = ClientIdScheme.parse("did:web:verifier.example.com")
        guard case .did(let did, let method) = scheme else {
            return XCTFail("expected .did, got \(scheme)")
        }
        XCTAssertEqual(did, "did:web:verifier.example.com")
        XCTAssertEqual(method, "web")
        XCTAssertEqual(scheme.identifier, "did:web:verifier.example.com")
        XCTAssertEqual(scheme.displayName, "verifier.example.com")
    }

    /// Regression: OpenID4VP 1.0 final spec's `decentralized_identifier:`
    /// client_id_scheme wraps the same DID-based identity go-wallet-backend
    /// also emits as a bare `did:...` client_id under the older `did` scheme
    /// name. Before this fix, `parse` had no case for the
    /// `decentralized_identifier:` prefix and fell through to
    /// `.preRegistered`, so `.identifier`/`.displayName` displayed the wire
    /// protocol prefix verbatim instead of the bare DID.
    func testParseDecentralizedIdentifierPrefixStripsToBareDid() {
        let scheme = ClientIdScheme.parse("decentralized_identifier:did:web:verifier.example.com")
        guard case .did(let did, let method) = scheme else {
            return XCTFail("expected .did, got \(scheme)")
        }
        XCTAssertEqual(did, "did:web:verifier.example.com", "must not retain the decentralized_identifier: wrapper")
        XCTAssertEqual(method, "web")
        XCTAssertEqual(scheme.identifier, "did:web:verifier.example.com")
        XCTAssertEqual(scheme.displayName, "verifier.example.com")
    }

    func testParseDecentralizedIdentifierWithNonDidRemainderFallsThroughToPreRegistered() {
        // A malformed/unexpected wire value (not itself a "did:..." string)
        // must not crash or silently misparse - falls through to the same
        // catch-all every other unrecognized prefix does.
        let scheme = ClientIdScheme.parse("decentralized_identifier:not-a-did")
        guard case .preRegistered(let clientId) = scheme else {
            return XCTFail("expected .preRegistered, got \(scheme)")
        }
        XCTAssertEqual(clientId, "decentralized_identifier:not-a-did")
    }
}
