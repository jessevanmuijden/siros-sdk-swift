// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import SirosCredentials

/// SPEC 5A against the privatedata-spec delivered-secret vectors (1b796d2, verbatim).
final class DeliveredSecretReceiptTests: XCTestCase {
    private static let hash = "2893c0c68da7735ef17da110405161c2f81d09d9faebc1340f00218c4e3f9ec4"

    /// Every vector line as ordered JSON, by id.
    private func vectors() throws -> [String: RawJSON] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "privatedata-spec-vectors-1b796d2", withExtension: "jsonl"))
        let data = try Data(contentsOf: url)
        XCTAssertEqual(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(), Self.hash, "re-copy from privatedata-spec and update PROVENANCE")
        var out: [String: RawJSON] = [:]
        for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
            let value = try XCTUnwrap(RawJSON.parse(String(line)))
            if case .object(let pairs) = value, case .string(let id)? = pairs.first(where: { $0.0 == "id" })?.1 { out[id] = value }
        }
        return out
    }

    private func member(_ value: RawJSON, _ name: String) -> RawJSON? {
        guard case .object(let pairs) = value else { return nil }
        return pairs.first { $0.0 == name }?.1
    }

    private func cases(_ vectors: [String: RawJSON], _ id: String) throws -> [RawJSON] {
        guard case .array(let list)? = member(try XCTUnwrap(member(try XCTUnwrap(vectors[id]), "inputs")), "cases") else { throw XCTSkip("no cases") }
        return list
    }

    private func string(_ value: RawJSON?) -> String? { if case .string(let s)? = value { return s }; return nil }

    private func hex(_ text: String) -> [UInt8] {
        stride(from: 0, to: text.count, by: 2).map { UInt8(text[text.index(text.startIndex, offsetBy: $0)..<text.index(text.startIndex, offsetBy: $0 + 2)], radix: 16) ?? 0 }
    }

    private func input(_ metadata: RawJSON?) -> DeliveredSecretMetadataInput {
        guard let metadata else { return .absent }
        guard case .object(let pairs) = metadata else { return .notObject }
        return .members(pairs.map { DeliveredSecretMember(name: $0.0, value: $0.1.jsonValue) })
    }

    private func receive(_ testCase: RawJSON, deferred: Bool = false) throws -> Result<DeliveredSecretReceived, DeliveredSecretRefusal> {
        let response = try XCTUnwrap(member(testCase, "response"))
        let commitment = string(member(testCase, "commitmentNamespace")).flatMap { namespace in
            string(member(testCase, "sscHex")).map { DeliveredSecretCommitment(namespace: namespace, ssc: hex($0)) }
        }
        var encrypted = false
        if case .bool(true)? = member(testCase, "jweEncrypted") { encrypted = true }
        do {
            return .success(try DeliveredSecretReceipt.receive(
                metadata: input(member(response, "credential_metadata")), jweEncrypted: encrypted,
                deferred: deferred || string(member(testCase, "responseType")) == "deferred",
                hasNotificationId: member(response, "notification_id") != nil, commitment: commitment))
        } catch let refusal as DeliveredSecretRefusal {
            return .failure(refusal)
        }
    }

    private func entries(_ value: RawJSON?) -> [DeliveredSecretMember] {
        guard case .array(let list)? = value else { return [] }
        return list.map {
            DeliveredSecretMember(name: string(member($0, "type")) ?? "", value: (member($0, "value") ?? .null).jsonValue)
        }
    }

    func testAcceptedWireShapes() throws {
        let v = try vectors()
        let wire = try cases(v, "delivered-secret-wire-001")
        XCTAssertEqual(wire.count, 4)
        for testCase in wire {
            let name = string(member(testCase, "name")) ?? "?"
            let received = try XCTUnwrap(try? receive(testCase).get(), name)
            let expected = try XCTUnwrap(member(try XCTUnwrap(member(testCase, "expected")), "storedMetadataPerCredential"), name)
            XCTAssertEqual(received.storedMetadata, entries(expected), "\(name): stored in the order received")
            XCTAssertFalse(received.displayMembers.contains { $0.name == "org.siros.secret_seed" }, name)
            XCTAssertEqual(received.seeds.count, received.storedMetadata.first { $0.name == "org.siros.secret_seed" }?.value.objectValue?.count)
        }
    }

    func testEveryMalformedOrRefusedResponseIsRefused() throws {
        let v = try vectors()
        for id in ["delivered-secret-malformed-001", "delivered-secret-refusal-001"] {
            let all = try cases(v, id)
            XCTAssertGreaterThanOrEqual(all.count, 6)
            for testCase in all {
                let name = string(member(testCase, "name")) ?? "?"
                if case .success = try receive(testCase) { XCTFail("\(id)/\(name): must be refused") }
            }
        }
        // The refusal reasons are the specific ones.
        let refusal = try cases(v, "delivered-secret-refusal-001")
        let reasons = try refusal.map { testCase -> DeliveredSecretRefusal in
            guard case .failure(let reason) = try receive(testCase) else { throw XCTSkip("accepted") }
            return reason
        }
        XCTAssertEqual(reasons, [.plainResponse, .missingNotificationId, .commitmentMismatch, .commitmentNamespaceAbsent, .metadataNotObject, .deferredResponse])
    }

    func testTheCommitmentIsCheckedBeforeStoring() throws {
        let v = try vectors()
        let seedHex = "00112233445566778899aabbccddeeff"
        for testCase in try cases(v, "delivered-secret-commitment-001") {
            let name = string(member(testCase, "name")) ?? "?"
            let ssc = hex(try XCTUnwrap(string(member(testCase, "ssc_hex"))))
            let result = Result {
                try DeliveredSecretReceipt.receive(
                    metadata: .members([DeliveredSecretMember(name: "org.siros.secret_seed", value: .object(["org.siros.nym_auth": .string(seedHex)]))]),
                    jweEncrypted: true, deferred: false, hasNotificationId: true,
                    commitment: DeliveredSecretCommitment(namespace: "org.siros.nym_auth", ssc: ssc))
            }
            if name == "match" { XCTAssertNoThrow(try result.get(), name) } else { XCTAssertThrowsError(try result.get(), name) }
        }
        // a short or empty ssc never matches
        XCTAssertThrowsError(try DeliveredSecretReceipt.receive(
            metadata: .members([DeliveredSecretMember(name: "org.siros.secret_seed", value: .object(["n": .string(seedHex)]))]),
            jweEncrypted: true, deferred: false, hasNotificationId: true, commitment: DeliveredSecretCommitment(namespace: "n", ssc: [])))
    }

    func testStripBeforeMerge() throws {
        let v = try vectors()
        let all = try cases(v, "delivered-secret-strip-001")
        XCTAssertEqual(all.count, 3)
        for testCase in all {
            let name = string(member(testCase, "name")) ?? "?"
            guard case .object(let response)? = member(testCase, "responseCredentialMetadata") else { return XCTFail(name) }
            let members = response.map { DeliveredSecretMember(name: $0.0, value: $0.1.jsonValue) }
            let issuer = member(testCase, "issuerCredentialMetadata")?.jsonValue.objectValue
            let expected = try XCTUnwrap(member(testCase, "expected"))
            let received = try DeliveredSecretReceipt.receive(
                metadata: .members(members), jweEncrypted: true, deferred: false, hasNotificationId: true, commitment: nil)
            XCTAssertEqual(Dictionary(uniqueKeysWithValues: received.displayMembers.map { ($0.name, $0.value) }),
                           try XCTUnwrap(member(expected, "strippedResponse")?.jsonValue.objectValue), name)
            XCTAssertEqual(DeliveredSecretReceipt.mergedDisplayMetadata(issuer: issuer, response: members),
                           try XCTUnwrap(member(expected, "mergedDisplayMetadata")?.jsonValue.objectValue), name)
            XCTAssertEqual(received.storedMetadata.filter { $0.name == "org.siros.secret_seed" },
                           entries(member(expected, "storedMetadata")).filter { $0.name == "org.siros.secret_seed" }, name)
            XCTAssertFalse(DeliveredSecretReceipt.mergedDisplayMetadata(issuer: issuer, response: members).values.contains {
                $0.objectValue?["org.siros.nym_auth"]?.stringValue != nil
            }, "the seed never reaches display metadata: \(name)")
        }
    }

    func testAdvertisement() throws {
        let v = try vectors()
        let all = try cases(v, "delivered-secret-advertise-001")
        XCTAssertEqual(all.count, 12)
        for testCase in all {
            let name = string(member(testCase, "name")) ?? "?"
            let metadata = member(testCase, "issuerCredentialMetadata")?.jsonValue.objectValue
            let outcome = string(member(try XCTUnwrap(member(testCase, "expected")), "outcome"))
            switch DeliveredSecretReceipt.advertisement(issuerCredentialMetadata: metadata) {
            case .none: XCTAssertEqual(outcome, "no-advertisement", name)
            case .advertised: XCTAssertEqual(outcome, "valid-advertisement", name)
            case .malformed: XCTAssertEqual(outcome, "malformed", name)
            }
        }
    }

    func testNothingPrintsTheSeed() throws {
        let received = try DeliveredSecretReceipt.receive(
            metadata: .members([DeliveredSecretMember(name: "org.siros.secret_seed", value: .object(["n": .string("00112233445566778899aabbccddeeff")]))]),
            jweEncrypted: true, deferred: false, hasNotificationId: true, commitment: nil)
        var dumped = ""
        dump(received, to: &dumped)
        for text in [dumped, "\(received)", String(reflecting: received)] { XCTAssertFalse(text.contains("00112233"), text) }
        XCTAssertEqual(received.seeds["n"]?.count, 16)
    }

    func testAbsentMetadataIsNotADeliveredSecret() throws {
        let received = try DeliveredSecretReceipt.receive(metadata: .absent, jweEncrypted: false, deferred: true, hasNotificationId: false, commitment: nil)
        XCTAssertEqual(received.seeds.count, 0)
        XCTAssertTrue(received.storedMetadata.isEmpty)
        // other members without a seed need neither encryption nor a notification id
        let other = try DeliveredSecretReceipt.receive(
            metadata: .members([DeliveredSecretMember(name: "display", value: .array([]))]), jweEncrypted: false, deferred: false,
            hasNotificationId: false, commitment: nil)
        XCTAssertEqual(other.displayMembers.count, 1)
    }
}
