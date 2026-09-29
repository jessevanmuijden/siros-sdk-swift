// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
@testable import SirosCredentials

final class CredentialUtilsTests: XCTestCase {

    private var sampleJwt: String {
        let header = base64Url("""
        {"alg":"ES256","typ":"vc+sd-jwt"}
        """)
        let payload = base64Url("""
        {"iss":"https://issuer.example.com","sub":"user123","iat":1700000000,"exp":1800000000,"vct":"urn:example:diploma","given_name":"Alice","family_name":"Smith","degree":"MSc Computer Science","cnf":{"jwk":{}},"_sd_alg":"sha-256"}
        """)
        return "\(header).\(payload).fakesig"
    }

    private func base64Url(_ string: String) -> String {
        Data(string.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func testParseJwtPayloadExtractsPayload() {
        let payload = CredentialUtils.parseJwtPayload(sampleJwt)
        XCTAssertNotNil(payload)
        XCTAssertEqual(payload?["iss"] as? String, "https://issuer.example.com")
        XCTAssertEqual(payload?["given_name"] as? String, "Alice")
    }

    func testParseJwtPayloadHandlesSdJwtWithDisclosures() {
        let sdJwt = "\(sampleJwt)~disclosure1~disclosure2"
        let payload = CredentialUtils.parseJwtPayload(sdJwt)
        XCTAssertNotNil(payload)
        XCTAssertEqual(payload?["given_name"] as? String, "Alice")
    }

    func testParseJwtPayloadReturnsNilForInvalidInput() {
        XCTAssertNil(CredentialUtils.parseJwtPayload("not-a-jwt"))
        XCTAssertNil(CredentialUtils.parseJwtPayload(""))
        XCTAssertNil(CredentialUtils.parseJwtPayload("only-one-part"))
    }

    func testParseJwtPayloadReturnsNilForMalformedBase64() {
        XCTAssertNil(CredentialUtils.parseJwtPayload("aaa.!!!invalid!!!.bbb"))
    }

    func testExtractClaimsReturnsUserFacingClaims() {
        let cred = StoredCredential(id: 1, format: "vc+sd-jwt", raw: sampleJwt, batchId: 1, instanceId: 0)
        let claims = CredentialUtils.extractClaims(cred)
        let keys = claims.map(\.key)
        XCTAssertTrue(keys.contains("given_name"))
        XCTAssertTrue(keys.contains("family_name"))
        XCTAssertTrue(keys.contains("degree"))
        XCTAssertFalse(keys.contains("iss"))
        XCTAssertFalse(keys.contains("exp"))
        XCTAssertFalse(keys.contains("cnf"))
        XCTAssertFalse(keys.contains("_sd_alg"))
        XCTAssertFalse(keys.contains("vct"))
    }

    func testExtractClaimsUsesVctmLabels() {
        let cred = StoredCredential(
            id: 1, format: "vc+sd-jwt", raw: sampleJwt,
            metadata: CredentialMetadata(claims: [
                ClaimMeta(path: ["given_name"], label: "First Name"),
                ClaimMeta(path: ["family_name"], label: "Surname"),
            ]),
            batchId: 1, instanceId: 0
        )
        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertEqual(claims.first(where: { $0.key == "given_name" })?.label, "First Name")
        XCTAssertEqual(claims.first(where: { $0.key == "family_name" })?.label, "Surname")
    }

    func testExtractClaimsFormatsKeysWhenNoVctm() {
        let cred = StoredCredential(id: 1, format: "vc+sd-jwt", raw: sampleJwt, batchId: 1, instanceId: 0)
        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertEqual(claims.first(where: { $0.key == "given_name" })?.label, "Given Name")
    }

    func testExtractClaimsReturnsEmptyForUnparseableCredential() {
        let cred = StoredCredential(id: 2, format: "vc+sd-jwt", raw: "not-a-jwt", batchId: 2, instanceId: 0)
        XCTAssertTrue(CredentialUtils.extractClaims(cred).isEmpty)
    }

    func testExtractClaimsResolvesDeeplyNestedVctmPath() {
        let header = base64Url(#"{"alg":"ES256","typ":"vc+sd-jwt"}"#)
        let payload = base64Url("""
        {"iss":"https://issuer.example.com","exp":1800000000,"vct":"urn:example:diploma",
         "credentialSubject":{"hasClaim":{"awardedBy":{"institution":"ArtEZ"}},"givenName":"Alice"}}
        """)
        let raw = "\(header).\(payload).fakesig"
        let cred = StoredCredential(
            id: 3, format: "vc+sd-jwt", raw: raw,
            metadata: CredentialMetadata(claims: [
                ClaimMeta(path: ["credentialSubject", "hasClaim", "awardedBy", "institution"], label: "Institution"),
            ]),
            batchId: 3, instanceId: 0
        )
        let claims = CredentialUtils.extractClaims(cred)
        let institution = claims.first(where: { $0.key == "credentialSubject.hasClaim.awardedBy.institution" })
        XCTAssertEqual(institution?.label, "Institution")
        XCTAssertEqual(institution?.value, "ArtEZ")
        // The ancestor top-level key must not also be dumped raw as its own claim.
        XCTAssertFalse(claims.contains(where: { $0.key == "credentialSubject" }))
    }

    func testExtractClaimsSkipsVctmClaimMissingFromCredential() {
        let cred = StoredCredential(
            id: 4, format: "vc+sd-jwt", raw: sampleJwt,
            metadata: CredentialMetadata(claims: [
                ClaimMeta(path: ["credentialSubject", "nonexistent"], label: "Nope"),
            ]),
            batchId: 4, instanceId: 0
        )
        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertFalse(claims.contains(where: { $0.label == "Nope" }))
    }

    func testParseSdJwtPartsDecodesHeaderPayloadAndDisclosures() {
        let disclosure = base64Url(#"["salt123","given_name","Alice"]"#)
        let raw = "\(sampleJwt)~\(disclosure)~"
        let parts = CredentialUtils.parseSdJwtParts(raw)
        XCTAssertNotNil(parts.header)
        XCTAssertTrue(parts.header?.contains("ES256") ?? false)
        XCTAssertNotNil(parts.payload)
        XCTAssertTrue(parts.payload?.contains("Alice") ?? false)
        XCTAssertEqual(parts.disclosures.count, 1)
        XCTAssertTrue(parts.disclosures[0].contains("given_name"))
    }

    func testPrettyPrintJsonIndentsValidJson() {
        let pretty = CredentialUtils.prettyPrintJson(#"{"a":1,"b":2}"#)
        XCTAssertTrue(pretty.contains("\n"))
        XCTAssertTrue(pretty.contains("\"a\""))
    }

    func testPrettyPrintJsonReturnsInputUnchangedForNonJson() {
        XCTAssertEqual(CredentialUtils.prettyPrintJson("not json"), "not json")
    }

    func testPrettyPrintXmlIndentsNestedElements() {
        let pretty = CredentialUtils.prettyPrintXml("<svg><text>{{name}}</text></svg>")
        XCTAssertTrue(pretty.contains("\n"))
        XCTAssertTrue(pretty.contains("<text>"))
        XCTAssertTrue(pretty.contains("{{name}}"))
    }

    func testFormatClaimKey() {
        XCTAssertEqual(CredentialUtils.formatClaimKey("given_name"), "Given Name")
        XCTAssertEqual(CredentialUtils.formatClaimKey("family-name"), "Family Name")
        XCTAssertEqual(CredentialUtils.formatClaimKey("degree"), "Degree")
    }

    func testBuildMetadataCombinesOfferAndVctm() {
        let offer = CredentialOffer(
            credentialConfigurationId: "diploma",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Diploma (offer)",
            issuerName: "Test Issuer",
            backgroundColor: "#000000"
        )
        let vctm = Vctm(
            vct: "urn:example:diploma",
            display: [
                VctmDisplay(
                    locale: "en",
                    name: "University Diploma",
                    description: "A diploma from VCTM",
                    rendering: VctmRendering(
                        simple: VctmSimpleRendering(
                            backgroundColor: "#003366",
                            textColor: "#ffffff"
                        )
                    )
                ),
            ],
            claims: [
                VctmClaim(
                    path: ["given_name"],
                    display: [VctmClaimDisplay(locale: "en", label: "Given Name")],
                    sd: "allowed",
                    mandatory: true
                ),
            ]
        )

        let metadata = CredentialUtils.buildMetadata(
            offer: offer, vctm: vctm, rawCredential: sampleJwt)

        // VCTM display may or may not match locale — check fallback behavior
        XCTAssertNotNil(metadata.name)
        XCTAssertEqual(metadata.issuer?.name, "Test Issuer")
        XCTAssertEqual(metadata.vct, "urn:example:diploma")
        XCTAssertNotNil(metadata.claims)
    }

    func testBuildMetadataFallsBackToOfferWhenNoVctm() {
        let offer = CredentialOffer(
            credentialConfigurationId: "diploma",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Diploma (offer)",
            issuerName: "Test Issuer",
            backgroundColor: "#000000"
        )
        let metadata = CredentialUtils.buildMetadata(offer: offer)
        XCTAssertEqual(metadata.name, "Diploma (offer)")
        XCTAssertEqual(metadata.backgroundColor, "#000000")
        XCTAssertNil(metadata.claims)
    }

    // MARK: - mdoc (mso_mdoc)

    private let mdocDocType = "org.iso.18013.5.1.mDL"
    private let mdocNamespace = "org.iso.18013.5.1"

    private func buildTaggedItem(digestId: UInt64, elementIdentifier: String, elementValue: String) -> CBOR {
        let item: CBOR = .map([
            .utf8String("digestID"): .unsignedInt(digestId),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String(elementIdentifier),
            .utf8String("elementValue"): .utf8String(elementValue),
        ])
        return .tagged(.encodedCBORDataItem, .byteString(item.encode()))
    }

    private func buildTaggedItemBytes(digestId: UInt64, elementIdentifier: String, elementValue: [UInt8]) -> CBOR {
        let item: CBOR = .map([
            .utf8String("digestID"): .unsignedInt(digestId),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String(elementIdentifier),
            .utf8String("elementValue"): .byteString(elementValue),
        ])
        return .tagged(.encodedCBORDataItem, .byteString(item.encode()))
    }

    /// Build a synthetic mdoc credential's raw (base64url) bytes: a DeviceResponse-shaped envelope.
    private func buildMdocRaw(extraItems: [CBOR] = []) -> String {
        let items: CBOR = .array([
            buildTaggedItem(digestId: 0, elementIdentifier: "family_name", elementValue: "Doe"),
            buildTaggedItem(digestId: 1, elementIdentifier: "given_name", elementValue: "Jane"),
        ] + extraItems)
        let nameSpaces: CBOR = .map([.utf8String(mdocNamespace): items])
        let issuerAuth: CBOR = .array(Array(repeating: .byteString([]), count: 4))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): nameSpaces,
            .utf8String("issuerAuth"): issuerAuth,
        ])
        let document: CBOR = .map([
            .utf8String("docType"): .utf8String(mdocDocType),
            .utf8String("issuerSigned"): issuerSigned,
        ])
        let envelope: CBOR = .map([
            .utf8String("documents"): .array([document]),
            .utf8String("status"): .unsignedInt(0),
        ])
        return Data(envelope.encode()).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func testExtractClaimsDispatchesToMdocParsingForMsoMdocFormat() {
        let cred = StoredCredential(
            id: 5,
            format: "mso_mdoc",
            raw: buildMdocRaw(),
            metadata: CredentialMetadata(
                doctype: mdocDocType,
                claims: [
                    ClaimMeta(path: [mdocNamespace, "family_name"], label: "Family Name", mandatory: true),
                ]
            ),
            batchId: 5,
            instanceId: 0
        )

        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertEqual(claims.count, 2)
        let familyName = claims.first { $0.key == "\(mdocNamespace).family_name" }
        XCTAssertEqual(familyName?.label, "Family Name")
        XCTAssertEqual(familyName?.value, "Doe")
        XCTAssertEqual(familyName?.mandatory, true)

        let givenName = claims.first { $0.key == "\(mdocNamespace).given_name" }
        // No ClaimMeta entry for given_name - falls back to formatted key.
        XCTAssertEqual(givenName?.label, "Given Name")
        XCTAssertEqual(givenName?.value, "Jane")
    }

    func testBuildMdocMetadataPopulatesDoctypeAndClaimsFromMddlSchema() {
        let offer = CredentialOffer(
            credentialConfigurationId: "mdl",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Driving Licence (offer)",
            issuerName: "Test Issuer"
        )
        let locale = Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        let schema = MddlSchema(
            format: "mso_mdoc",
            doctype: mdocDocType,
            display: [MddlDisplay(locale: locale, name: "Driving Licence")],
            claims: [
                mdocNamespace: [
                    "family_name": MddlClaimMeta(
                        display: [MddlClaimDisplay(locale: locale, name: "Family Name")],
                        mandatory: true,
                        valueType: "tstr"
                    ),
                ],
            ]
        )

        let metadata = CredentialUtils.buildMdocMetadata(offer: offer, mddlSchema: schema)
        XCTAssertEqual(metadata.name, "Driving Licence")
        XCTAssertEqual(metadata.doctype, mdocDocType)
        XCTAssertNil(metadata.vct)
        XCTAssertEqual(metadata.claims?.count, 1)
        XCTAssertEqual(metadata.claims?.first?.path, [mdocNamespace, "family_name"])
        XCTAssertEqual(metadata.claims?.first?.label, "Family Name")
        XCTAssertEqual(metadata.claims?.first?.mandatory, true)
    }

    func testBuildMdocMetadataFallsBackToOfferWhenNoMddlSchema() {
        let offer = CredentialOffer(
            credentialConfigurationId: "mdl",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Driving Licence (offer)",
            issuerName: "Test Issuer",
            backgroundColor: "#1a365d"
        )
        let metadata = CredentialUtils.buildMdocMetadata(offer: offer)
        XCTAssertEqual(metadata.name, "Driving Licence (offer)")
        XCTAssertEqual(metadata.backgroundColor, "#1a365d")
        XCTAssertNil(metadata.claims)
    }

    // Regression tests for #176: mdoc claims never carried an svgId, so no
    // mdoc claim could ever be substituted into an SVG rendering card.

    func testBuildMdocMetadataPopulatesSvgIdAndSvgTemplatesFromMddlSchemaRendering() {
        let offer = CredentialOffer(
            credentialConfigurationId: "photoid",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Photo ID (offer)",
            issuerName: "Test Issuer"
        )
        let locale = Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        let schema = MddlSchema(
            format: "mso_mdoc",
            doctype: "eu.europa.ec.eudi.photoid.1",
            display: [
                MddlDisplay(
                    locale: locale,
                    name: "Photo ID",
                    rendering: MddlRendering(svgTemplates: [MddlSvgTemplate(uri: "https://issuer.example.com/photoid.svg")])
                ),
            ],
            claims: [
                mdocNamespace: [
                    "portrait": MddlClaimMeta(
                        display: [MddlClaimDisplay(locale: locale, name: "Portrait")],
                        valueType: "bstr",
                        svgId: "portrait"
                    ),
                ],
            ]
        )

        let metadata = CredentialUtils.buildMdocMetadata(offer: offer, mddlSchema: schema)
        XCTAssertEqual(metadata.claims?.first?.svgId, "portrait")
        XCTAssertEqual(metadata.svgTemplates?.count, 1)
        XCTAssertEqual(metadata.svgTemplates?.first?.uri, "https://issuer.example.com/photoid.svg")
    }

    func testExtractMdocClaimsTurnsAJpegPortraitByteStringIntoADataUri() {
        let jpegBytes: [UInt8] = [0xFF, 0xD8, 0xFF, 0x00, 0x01, 0x02]
        let cred = StoredCredential(
            id: 6,
            format: "mso_mdoc",
            raw: buildMdocRaw(extraItems: [buildTaggedItemBytes(digestId: 2, elementIdentifier: "portrait", elementValue: jpegBytes)]),
            metadata: CredentialMetadata(
                doctype: mdocDocType,
                claims: [ClaimMeta(path: [mdocNamespace, "portrait"], label: "Portrait", svgId: "portrait")]
            ),
            batchId: 6,
            instanceId: 0
        )

        let claims = CredentialUtils.extractClaims(cred)
        let portrait = claims.first { $0.key == "\(mdocNamespace).portrait" }
        let expectedBase64 = Data(jpegBytes).base64EncodedString()
        // The generic display `value` stays the concise placeholder - only
        // `imageDataUri` carries the (potentially huge) base64 URI, so a
        // credential's Claims tab never renders a giant base64 blob for a
        // portrait (see `SvgTemplateRenderer`, which is the only consumer
        // of `imageDataUri`).
        XCTAssertEqual(portrait?.value, "<\(jpegBytes.count) bytes>")
        XCTAssertEqual(portrait?.imageDataUri, "data:image/jpeg;base64,\(expectedBase64)")
        XCTAssertFalse(portrait?.isUndecodableBytes ?? true)
        XCTAssertEqual(portrait?.svgId, "portrait")
    }

    func testExtractMdocClaimsTurnsAPngPortraitByteStringIntoADataUri() {
        let pngBytes: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]
        let cred = StoredCredential(
            id: 7,
            format: "mso_mdoc",
            raw: buildMdocRaw(extraItems: [buildTaggedItemBytes(digestId: 2, elementIdentifier: "portrait", elementValue: pngBytes)]),
            metadata: nil,
            batchId: 7,
            instanceId: 0
        )

        let claims = CredentialUtils.extractClaims(cred)
        let portrait = claims.first { $0.key == "\(mdocNamespace).portrait" }
        let expectedBase64 = Data(pngBytes).base64EncodedString()
        XCTAssertEqual(portrait?.value, "<\(pngBytes.count) bytes>")
        XCTAssertEqual(portrait?.imageDataUri, "data:image/png;base64,\(expectedBase64)")
        XCTAssertFalse(portrait?.isUndecodableBytes ?? true)
    }

    func testExtractMdocClaimsLeavesAnUndecodableByteStringAsTheNBytesPlaceholder() {
        // JPEG 2000 codestream magic bytes - deliberately NOT decoded, per
        // #176's "Decision: JPEG 2000" (no image-decoding dependency added
        // to the SDK, despite UIImage/ImageIO being able to decode JP2
        // natively; issuers targeting SVG cards must transcode JP2 themselves).
        let jp2Bytes: [UInt8] = [0xFF, 0x4F, 0xFF, 0x51, 0x00, 0x00]
        let cred = StoredCredential(
            id: 8,
            format: "mso_mdoc",
            raw: buildMdocRaw(extraItems: [buildTaggedItemBytes(digestId: 2, elementIdentifier: "portrait", elementValue: jp2Bytes)]),
            metadata: nil,
            batchId: 8,
            instanceId: 0
        )

        let claims = CredentialUtils.extractClaims(cred)
        let portrait = claims.first { $0.key == "\(mdocNamespace).portrait" }
        XCTAssertEqual(portrait?.value, "<\(jp2Bytes.count) bytes>")
        XCTAssertNil(portrait?.imageDataUri)
        XCTAssertTrue(portrait?.isUndecodableBytes ?? false)
    }

    // MARK: - eligibleInstances / CredentialConsumptionPolicy

    private func consumptionCredential(
        id: Int64,
        batchId: Int64 = 1,
        instanceId: Int = 0,
        format: String = "vc+sd-jwt",
        kid: String? = nil
    ) -> StoredCredential {
        StoredCredential(id: id, format: format, raw: "raw-\(id)", kid: kid, batchId: batchId, instanceId: instanceId)
    }

    private func presentationRecord(_ credentialIds: Int64...) -> PresentationRecord {
        PresentationRecord(
            id: credentialIds.reduce(0, +) + 1000,
            flowId: "flow",
            credentialIds: credentialIds,
            timestamp: 0
        )
    }

    func testEligibleInstancesNeverConsumeReturnsEveryInstanceRegardlessOfHistory() {
        let instances = [consumptionCredential(id: 1, instanceId: 0), consumptionCredential(id: 2, instanceId: 1)]
        let history = [presentationRecord(1), presentationRecord(2)]

        let result = CredentialUtils.eligibleInstances(instances: instances, policy: .neverConsume, presentationHistory: history, availableKeyIds: ["irrelevant-kid"])

        XCTAssertEqual(result, instances)
    }

    func testEligibleInstancesConsumeAllExcludesInstancesAlreadyPresented() {
        let used = consumptionCredential(id: 1, instanceId: 0)
        let unused = consumptionCredential(id: 2, instanceId: 1)
        let history = [presentationRecord(1)]

        let result = CredentialUtils.eligibleInstances(instances: [used, unused], policy: .consumeAll, presentationHistory: history, availableKeyIds: ["irrelevant-kid"])

        XCTAssertEqual(result, [unused])
    }

    func testEligibleInstancesConsumeAllWithNoHistoryEveryInstanceIsEligible() {
        let instances = [consumptionCredential(id: 1, instanceId: 0), consumptionCredential(id: 2, instanceId: 1)]

        let result = CredentialUtils.eligibleInstances(instances: instances, policy: .consumeAll, presentationHistory: [], availableKeyIds: ["irrelevant-kid"])

        XCTAssertEqual(result, instances)
    }

    func testEligibleInstancesConsumeAllAllInstancesUsedReturnsEmptyList() {
        let a = consumptionCredential(id: 1, instanceId: 0)
        let b = consumptionCredential(id: 2, instanceId: 1)
        let history = [presentationRecord(1), presentationRecord(2)]

        let result = CredentialUtils.eligibleInstances(instances: [a, b], policy: .consumeAll, presentationHistory: history, availableKeyIds: ["irrelevant-kid"])

        XCTAssertEqual(result, [])
    }

    func testEligibleInstancesConsumeNonZkpWithDefaultResolverConsumesStoredMdocLikeConsumeAll() {
        // A stored credential's own format is never "mso_mdoc_zk" - ZK-ness
        // lives in the matched query's format (see CredentialUtils.isZkpFormat's
        // doc comment) - so the default resolver treats every stored
        // instance as a raw disclosure and consumeNonZkp behaves like
        // consumeAll. Callers that know better pass isZkPresentation (below).
        let used = consumptionCredential(id: 1, instanceId: 0, format: "mso_mdoc")
        let unused = consumptionCredential(id: 2, instanceId: 1, format: "mso_mdoc")
        let history = [presentationRecord(1)]

        let result = CredentialUtils.eligibleInstances(instances: [used, unused], policy: .consumeNonZkp, presentationHistory: history, availableKeyIds: ["irrelevant-kid"])

        XCTAssertEqual(result, [unused])
    }

    func testIsZkpFormatRecognisesMsoMdocZkCaseInsensitively() {
        XCTAssertTrue(CredentialUtils.isZkpFormat("mso_mdoc_zk"))
        XCTAssertTrue(CredentialUtils.isZkpFormat("MSO_MDOC_ZK"))
        XCTAssertFalse(CredentialUtils.isZkpFormat("mso_mdoc"))
        XCTAssertFalse(CredentialUtils.isZkpFormat("dc+sd-jwt"))
    }

    func testEligibleInstancesConsumeNonZkpWithResolverReturningTrueKeepsUsedInstanceEligible() {
        // A real ZK presentation (per the caller's own resolver - see
        // eligibleInstances' isZkPresentation doc comment) is never
        // consumed under consumeNonZkp, even if it was already presented.
        let used = consumptionCredential(id: 1, instanceId: 0, format: "mso_mdoc")
        let history = [presentationRecord(1)]

        let result = CredentialUtils.eligibleInstances(
            instances: [used],
            policy: .consumeNonZkp,
            presentationHistory: history,
            availableKeyIds: ["irrelevant-kid"],
            isZkPresentation: { _ in true }
        )

        XCTAssertEqual(result, [used])
    }

    func testEligibleInstancesConsumeNonZkpWithResolverReturningFalseExcludesUsedInstance() {
        // A raw disclosure (per the caller's resolver) is consumed under
        // consumeNonZkp just like under consumeAll.
        let used = consumptionCredential(id: 1, instanceId: 0, format: "mso_mdoc")
        let unused = consumptionCredential(id: 2, instanceId: 1, format: "mso_mdoc")
        let history = [presentationRecord(1)]

        let result = CredentialUtils.eligibleInstances(
            instances: [used, unused],
            policy: .consumeNonZkp,
            presentationHistory: history,
            availableKeyIds: ["irrelevant-kid"],
            isZkPresentation: { _ in false }
        )

        XCTAssertEqual(result, [unused])
    }

    func testEligibleInstancesConsumeNonZkpResolverIsEvaluatedPerInstance() {
        // The resolver is evaluated per-instance, not once for the whole
        // batch - a zk instance and a raw instance already presented in the
        // same batch must be judged independently of each other.
        let zkUsed = consumptionCredential(id: 1, instanceId: 0, format: "mso_mdoc")
        let rawUsed = consumptionCredential(id: 2, instanceId: 1, format: "mso_mdoc")
        let history = [presentationRecord(1), presentationRecord(2)]

        let result = CredentialUtils.eligibleInstances(
            instances: [zkUsed, rawUsed],
            policy: .consumeNonZkp,
            presentationHistory: history,
            availableKeyIds: ["irrelevant-kid"],
            isZkPresentation: { $0.id == zkUsed.id }
        )

        XCTAssertEqual(result, [zkUsed])
    }

    func testEligibleInstancesConsumeAllIgnoresTheResolver() {
        // consumeAll consumes regardless of ZK-ness: a resolver claiming
        // every presentation is ZK must not resurrect a used instance.
        let used = consumptionCredential(id: 1, instanceId: 0, format: "mso_mdoc")
        let history = [presentationRecord(1)]

        let result = CredentialUtils.eligibleInstances(
            instances: [used],
            policy: .consumeAll,
            presentationHistory: history,
            availableKeyIds: ["irrelevant-kid"],
            isZkPresentation: { _ in true }
        )

        XCTAssertEqual(result, [])
    }

    // MARK: - eligibleInstances key-availability checks
    // A real, recurring bug (found via live proximity-presentation testing):
    // a credential whose signing key was silently lost (e.g. a sync that
    // never folded a software key into the persisted container) kept
    // reporting "available" under neverConsume forever, since the old
    // 3-arg eligibleInstances was entirely blind to key existence.

    func testEligibleInstancesNeverConsumeStillExcludesInstanceWhoseKeyIsMissing() {
        let hasKey = consumptionCredential(id: 1, instanceId: 0, kid: "kid-1")
        let missingKey = consumptionCredential(id: 2, instanceId: 1, kid: "kid-2")

        let result = CredentialUtils.eligibleInstances(
            instances: [hasKey, missingKey],
            policy: .neverConsume,
            presentationHistory: [],
            availableKeyIds: ["kid-1"]
        )

        XCTAssertEqual(result, [hasKey])
    }

    func testEligibleInstancesNilKidIsEligibleWhenSignerHoldsAnyKeyAtAll() {
        // A nil kid can't be matched against a specific availableKeyIds
        // entry, but as long as the signer holds *some* key, the low-level
        // "no specific kid" signing call shape can still succeed.
        let noKidBinding = consumptionCredential(id: 1, instanceId: 0, kid: nil)

        let result = CredentialUtils.eligibleInstances(
            instances: [noKidBinding],
            policy: .neverConsume,
            presentationHistory: [],
            availableKeyIds: ["some-other-kid"]
        )

        XCTAssertEqual(result, [noKidBinding])
    }

    func testEligibleInstancesNilKidIsExcludedWhenSignerHoldsNoKeysAtAll() {
        // With zero keys in the signer, a nil-kid credential is certain to
        // fail to sign exactly like a known-but-missing kid would, so it
        // must be excluded the same way.
        let noKidBinding = consumptionCredential(id: 1, instanceId: 0, kid: nil)

        let result = CredentialUtils.eligibleInstances(
            instances: [noKidBinding],
            policy: .neverConsume,
            presentationHistory: [],
            availableKeyIds: []
        )

        XCTAssertEqual(result, [])
    }

    func testEligibleInstancesConsumeAllExcludesInstanceThatIsBothUnusedAndKeyless() {
        // Consumption-eligible (never presented) but its key is gone -
        // both conditions are independently enforced.
        let keyless = consumptionCredential(id: 1, instanceId: 0, kid: "kid-1")

        let result = CredentialUtils.eligibleInstances(
            instances: [keyless],
            policy: .consumeAll,
            presentationHistory: [],
            availableKeyIds: []
        )

        XCTAssertEqual(result, [])
    }

    func testIsBelowRenewThresholdFiresUnderNeverConsumeOnceEveryKeyIsMissing() {
        // The policy never consumes, but with no usable key nothing is
        // eligible - the renewal trigger is the one user-facing signal that
        // something is wrong with this batch.
        let instances = [consumptionCredential(id: 1, instanceId: 0, kid: "kid-1")]

        XCTAssertTrue(CredentialUtils.isBelowRenewThreshold(instances: instances, policy: .neverConsume, presentationHistory: [], availableKeyIds: []))
    }

    // MARK: - PresentationRecord decoding

    func testPresentationRecordDecodesZkProofWhenPresent() throws {
        let json = """
        {"id": 7, "flow_id": "f", "credential_ids": [1, 2], "timestamp": 1000, "success": true, "zk_proof": true}
        """
        let record = try JSONDecoder().decode(PresentationRecord.self, from: Data(json.utf8))
        XCTAssertTrue(record.zkProof)
        XCTAssertEqual(record.credentialIds, [1, 2])
    }

    func testPresentationRecordDecodesOlderRecordWithoutZkProofAsFalse() throws {
        // A record persisted before zk_proof existed - or reloaded from the
        // encrypted container, which only carries the privatedata-spec's
        // normative fields (see JweKeystore.loadPresentations) - must still
        // decode, with every enrichment field at its default.
        let json = """
        {"id": 7, "flow_id": "", "credential_ids": [1], "timestamp": 1000}
        """
        let record = try JSONDecoder().decode(PresentationRecord.self, from: Data(json.utf8))
        XCTAssertFalse(record.zkProof)
        XCTAssertTrue(record.success)
        XCTAssertEqual(record.credentialNames, [])
        XCTAssertEqual(record.requestedClaims, [])
        XCTAssertNil(record.verifierName)
    }

    func testPresentationRecordRoundTripsZkProof() throws {
        let original = PresentationRecord(id: 9, flowId: "flow", credentialIds: [3], timestamp: 5, zkProof: true)
        let data = try JSONEncoder().encode(original)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["zk_proof"] as? Bool, true)
        XCTAssertEqual(try JSONDecoder().decode(PresentationRecord.self, from: data), original)
    }

    func testEligibleInstancesSigCountOfTwoOrMoreStillCountsAsUsedNotJustExactlyOne() {
        let overused = consumptionCredential(id: 1, instanceId: 0)
        let history = [presentationRecord(1), presentationRecord(1), presentationRecord(1)]

        let result = CredentialUtils.eligibleInstances(instances: [overused], policy: .consumeAll, presentationHistory: history, availableKeyIds: ["irrelevant-kid"])

        XCTAssertEqual(result, [])
    }

    // MARK: - groupIntoFamilies

    func testGroupIntoFamiliesRepresentativeIsTheInstanceZeroMember() {
        let credentials = [
            consumptionCredential(id: 41, batchId: 500, instanceId: 0),
            consumptionCredential(id: 42, batchId: 500, instanceId: 1),
            consumptionCredential(id: 43, batchId: 500, instanceId: 2),
        ]

        let result = CredentialUtils.groupIntoFamilies(credentials)

        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result.first?.representative.id, 41)
        XCTAssertEqual(result.first?.instances.count, 3)
    }

    func testGroupIntoFamiliesSkipsABatchMissingItsInstanceZeroMember() {
        // A batch missing an instanceId==0 member must be skipped, not
        // fall back to an arbitrary member - matching groupForDisplay's
        // own convention exactly, so the two grouping functions never
        // disagree about which batches are representable.
        let credentials = [
            consumptionCredential(id: 51, batchId: 600, instanceId: 1),
            consumptionCredential(id: 52, batchId: 600, instanceId: 2),
        ]

        let result = CredentialUtils.groupIntoFamilies(credentials)

        XCTAssertTrue(result.isEmpty)
    }

    func testGroupIntoFamiliesStandaloneCredentialBecomesItsOwnOneInstanceFamily() {
        let cred = consumptionCredential(id: 61, batchId: 700, instanceId: 0)

        let result = CredentialUtils.groupIntoFamilies([cred])

        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result.first?.representative, cred)
        XCTAssertEqual(result.first?.instances, [cred])
    }

    // MARK: - isBelowRenewThreshold (credential re-issuance/renewal plan §4.3)

    func testIsBelowRenewThresholdFalseWhenEligibleCountExceedsDefaultThreshold() {
        let instances = [consumptionCredential(id: 1, instanceId: 0), consumptionCredential(id: 2, instanceId: 1)]

        XCTAssertFalse(CredentialUtils.isBelowRenewThreshold(instances: instances, policy: .consumeAll, presentationHistory: [], availableKeyIds: ["irrelevant-kid"]))
    }

    func testIsBelowRenewThresholdTrueWhenEligibleCountDropsToDefaultThresholdOfZero() {
        let a = consumptionCredential(id: 1, instanceId: 0)
        let b = consumptionCredential(id: 2, instanceId: 1)
        let history = [presentationRecord(1), presentationRecord(2)]

        XCTAssertTrue(CredentialUtils.isBelowRenewThreshold(instances: [a, b], policy: .consumeAll, presentationHistory: history, availableKeyIds: ["irrelevant-kid"]))
    }

    func testIsBelowRenewThresholdNeverConsumeNeverFiresSinceEveryInstanceStaysEligible() {
        // .neverConsume makes eligibleInstances always return every instance
        // regardless of history, so the threshold can never be crossed - see
        // isBelowRenewThreshold's own doc comment.
        let instances = [consumptionCredential(id: 1, instanceId: 0)]
        let history = [presentationRecord(1), presentationRecord(1), presentationRecord(1)]

        XCTAssertFalse(CredentialUtils.isBelowRenewThreshold(instances: instances, policy: .neverConsume, presentationHistory: history, availableKeyIds: ["irrelevant-kid"]))
    }

    func testIsBelowRenewThresholdRespectsACustomThreshold() {
        let a = consumptionCredential(id: 1, instanceId: 0)
        let b = consumptionCredential(id: 2, instanceId: 1)
        let history = [presentationRecord(1)]

        // 1 eligible instance remains (b) - at or below a threshold of 1, but not 0.
        XCTAssertTrue(CredentialUtils.isBelowRenewThreshold(instances: [a, b], policy: .consumeAll, presentationHistory: history, availableKeyIds: ["irrelevant-kid"], threshold: 1))
        XCTAssertFalse(CredentialUtils.isBelowRenewThreshold(instances: [a, b], policy: .consumeAll, presentationHistory: history, availableKeyIds: ["irrelevant-kid"], threshold: 0))
    }

    // MARK: - computeAttributeDiff (AttributeDiffService-equivalent, ISSU_59)

    private func claim(_ key: String, _ value: String, label: String? = nil) -> DisplayClaim {
        DisplayClaim(key: key, label: label ?? key, value: value)
    }

    func testComputeAttributeDiffNoChangesWhenBeforeAndAfterAreIdentical() {
        let before = [claim("given_name", "Alex"), claim("family_name", "Doe")]

        let diff = CredentialUtils.computeAttributeDiff(before: before, after: before)

        XCTAssertTrue(diff.changed.isEmpty)
        XCTAssertTrue(diff.added.isEmpty)
        XCTAssertTrue(diff.removed.isEmpty)
        XCTAssertFalse(diff.hasChanges)
    }

    func testComputeAttributeDiffDetectsAChangedValueByKeyNotListPosition() {
        // VCTM claim ordering isn't guaranteed stable across a renewal (see
        // computeAttributeDiff's own doc comment) - reversing order here
        // pins that matching is by key, not position.
        let before = [claim("given_name", "Alex"), claim("age", "30")]
        let after = [claim("age", "31"), claim("given_name", "Alex")]

        let diff = CredentialUtils.computeAttributeDiff(before: before, after: after)

        XCTAssertEqual(diff.changed, [AttributeChange(key: "age", label: "age", oldValue: "30", newValue: "31")])
        XCTAssertTrue(diff.added.isEmpty)
        XCTAssertTrue(diff.removed.isEmpty)
        XCTAssertTrue(diff.hasChanges)
    }

    func testComputeAttributeDiffDetectsAnAddedClaim() {
        let before = [claim("given_name", "Alex")]
        let after = [claim("given_name", "Alex"), claim("nationality", "SE")]

        let diff = CredentialUtils.computeAttributeDiff(before: before, after: after)

        XCTAssertEqual(diff.added, [claim("nationality", "SE")])
        XCTAssertTrue(diff.changed.isEmpty)
        XCTAssertTrue(diff.removed.isEmpty)
        XCTAssertTrue(diff.hasChanges)
    }

    func testComputeAttributeDiffDetectsARemovedClaim() {
        let before = [claim("given_name", "Alex"), claim("nationality", "SE")]
        let after = [claim("given_name", "Alex")]

        let diff = CredentialUtils.computeAttributeDiff(before: before, after: after)

        XCTAssertEqual(diff.removed, [claim("nationality", "SE")])
        XCTAssertTrue(diff.changed.isEmpty)
        XCTAssertTrue(diff.added.isEmpty)
        XCTAssertTrue(diff.hasChanges)
    }

    func testComputeAttributeDiffCombinesChangedAddedAndRemovedInOneCall() {
        let before = [claim("given_name", "Alex"), claim("age", "30"), claim("nationality", "SE")]
        let after = [claim("given_name", "Alex"), claim("age", "31"), claim("email", "a@example.com")]

        let diff = CredentialUtils.computeAttributeDiff(before: before, after: after)

        XCTAssertEqual(diff.changed, [AttributeChange(key: "age", label: "age", oldValue: "30", newValue: "31")])
        XCTAssertEqual(diff.added, [claim("email", "a@example.com")])
        XCTAssertEqual(diff.removed, [claim("nationality", "SE")])
        XCTAssertTrue(diff.hasChanges)
    }

    func testComputeAttributeDiffToleratesDuplicateKeysWithoutCrashing() {
        // extractClaims can produce duplicate DisplayClaim.key values (e.g.
        // duplicated VCTM paths) - this must not crash (a real Copilot
        // review finding: Dictionary(uniqueKeysWithValues:) traps on a
        // duplicate key), and must resolve deterministically to the first
        // occurrence.
        let before = [claim("given_name", "Alex"), claim("given_name", "AlexDuplicate")]
        let after = [claim("given_name", "Alex")]

        let diff = CredentialUtils.computeAttributeDiff(before: before, after: after)

        XCTAssertFalse(diff.hasChanges)
    }
}
