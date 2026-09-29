// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class MddlSchemaFetcherTests: XCTestCase {

    private let sampleMddlSchemaJson = """
    {
      "format": "mso_mdoc",
      "doctype": "org.iso.18013.5.1.mDL",
      "display": [
        { "locale": "en", "name": "Driving Licence" }
      ]
    }
    """

    func testParseMddlSchemaParsesValidJson() {
        let fetcher = MddlSchemaFetcher()
        let schema = fetcher.parseMddlSchema(sampleMddlSchemaJson)

        XCTAssertNotNil(schema)
        XCTAssertEqual(schema?.format, "mso_mdoc")
        XCTAssertEqual(schema?.doctype, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(schema?.display?.first?.name, "Driving Licence")
    }

    func testParseMddlSchemaDefaultsRequiredKeyStorageToNilWhenAbsent() {
        let fetcher = MddlSchemaFetcher()
        let schema = fetcher.parseMddlSchema(sampleMddlSchemaJson)

        XCTAssertNil(schema?.requiredKeyStorage, "absent attestation_los must mean no requirement declared")
    }

    func testParseMddlSchemaParsesAttestationLosAsRequiredKeyStorage() {
        let json = """
        {
          "format": "mso_mdoc",
          "doctype": "org.iso.18013.5.1.mDL",
          "attestation_los": "iso_18045_moderate"
        }
        """
        let fetcher = MddlSchemaFetcher()
        let schema = fetcher.parseMddlSchema(json)

        XCTAssertEqual(schema?.requiredKeyStorage, "iso_18045_moderate")
    }

    /// Regression test for #176 fix review: `CredentialUtilsTests` only
    /// constructs `MddlSchema`/`MddlClaimMeta` programmatically, so a
    /// `CodingKeys` mismatch against real issuer JSON (e.g. `svg_templates`,
    /// `color_scheme`, `svg_id`) would never be caught by any test. This
    /// decodes the actual raw JSON shape (mirroring `vc`'s
    /// `pkg/mdoc/schema.go`) through the real fetch path.
    func testParseMddlSchemaDecodesSvgTemplatesAndSvgIdFromRawJson() {
        let json = """
        {
          "format": "mso_mdoc",
          "doctype": "eu.europa.ec.eudi.photoid.1",
          "display": [
            {
              "locale": "en",
              "name": "Photo ID",
              "rendering": {
                "svg_templates": [
                  { "uri": "https://issuer.example.com/photoid.svg", "properties": { "color_scheme": "light" } }
                ]
              }
            }
          ],
          "claims": {
            "org.iso.23220.photoid.1": {
              "portrait": { "value_type": "bstr", "svg_id": "portrait" }
            }
          }
        }
        """
        let fetcher = MddlSchemaFetcher()
        let schema = fetcher.parseMddlSchema(json)

        XCTAssertEqual(schema?.display?.first?.rendering?.svgTemplates?.first?.uri, "https://issuer.example.com/photoid.svg")
        XCTAssertEqual(schema?.display?.first?.rendering?.svgTemplates?.first?.properties?.colorScheme, "light")
        XCTAssertEqual(schema?.claims?["org.iso.23220.photoid.1"]?["portrait"]?.svgId, "portrait")
    }

    func testParseMddlSchemaReturnsNilForInvalidJson() {
        let fetcher = MddlSchemaFetcher()
        XCTAssertNil(fetcher.parseMddlSchema("not json"))
        XCTAssertNil(fetcher.parseMddlSchema(""))
    }

    func testFetchFromTypeMetadataEndpoint() async {
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            if url == "https://issuer.example.com/type-metadata/mdl" {
                return self.sampleMddlSchemaJson
            }
            return nil
        })

        let schema = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")

        XCTAssertNotNil(schema)
        XCTAssertEqual(schema?.doctype, "org.iso.18013.5.1.mDL")
    }

    func testFetchReturnsNilWhenNotFound() async {
        let fetcher = MddlSchemaFetcher(httpGet: { _ in nil })

        let schema = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")

        XCTAssertNil(schema)
    }

    // MARK: - Registry-service strategy (go-wallet-backend's TS11-backed registry)

    func testFetchUsesRegistryStrategyFirstWhenAvailable() async {
        var calledUrls: [String] = []
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            calledUrls.append(url)
            // Confirmed live: the generic `vct` query param name is used for
            // mdoc doctypes too - same handler/store serves both formats.
            if url == "https://wallet.example.com/registry/type-metadata?vct=org.iso.18013.5.1.mDL" {
                return self.sampleMddlSchemaJson
            }
            XCTFail("registry strategy should short-circuit before issuer-direct fallback: \(url)")
            return nil
        })

        let schema = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.mDL",
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(schema)
        XCTAssertEqual(schema?.doctype, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(calledUrls, ["https://wallet.example.com/registry/type-metadata?vct=org.iso.18013.5.1.mDL"])
    }

    func testFetchFallsBackToIssuerDirectWhenRegistryHasNoEntry() async {
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            if url.hasPrefix("https://wallet.example.com/registry") {
                return nil
            }
            if url == "https://issuer.example.com/type-metadata/mdl" {
                return self.sampleMddlSchemaJson
            }
            return nil
        })

        let schema = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.mDL",
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(schema, "must fall through to the issuer-direct strategy when the registry has no entry")
    }

    func testFetchSkipsRegistryStrategyWhenRegistryUrlIsNil() async {
        var calledUrls: [String] = []
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            calledUrls.append(url)
            if url == "https://issuer.example.com/type-metadata/mdl" {
                return self.sampleMddlSchemaJson
            }
            return nil
        })

        let schema = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.mDL",
            registryUrl: nil
        )

        XCTAssertNotNil(schema)
        XCTAssertEqual(calledUrls, ["https://issuer.example.com/type-metadata/mdl"], "no registry lookup should ever be attempted")
    }

    func testFetchSkipsRegistryStrategyWhenDoctypeIsNil() async {
        var calledUrls: [String] = []
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            calledUrls.append(url)
            if url == "https://issuer.example.com/type-metadata/mdl" {
                return self.sampleMddlSchemaJson
            }
            return nil
        })

        let schema = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: nil,
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(schema)
        XCTAssertEqual(calledUrls, ["https://issuer.example.com/type-metadata/mdl"], "no registry lookup should ever be attempted")
    }

    // MARK: - In-memory TTL cache

    func testFetchCachesSuccessfulResultWithinTtl() async {
        var callCount = 0
        let fetcher = MddlSchemaFetcher(httpGet: { _ in
            callCount += 1
            return self.sampleMddlSchemaJson
        }, cacheTtlSeconds: 1800)

        let first = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")
        let second = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")

        XCTAssertNotNil(first)
        XCTAssertNotNil(second)
        XCTAssertEqual(callCount, 1, "second call within TTL must be served from cache, not hit the network again")
    }

    func testFetchDoesNotServeCacheForDifferentParameters() async {
        var callCount = 0
        let fetcher = MddlSchemaFetcher(httpGet: { _ in
            callCount += 1
            return self.sampleMddlSchemaJson
        }, cacheTtlSeconds: 1800)

        _ = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")
        _ = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "photoId")
        _ = await fetcher.fetch(issuerUrl: "https://other-issuer.example.com", scope: "mdl")

        XCTAssertEqual(callCount, 3, "different scope/issuerUrl must never be served from another key's cache entry")
    }

    func testFetchDoesNotServeCacheForDifferentDoctypeOrRegistryUrl() async {
        var callCount = 0
        let fetcher = MddlSchemaFetcher(httpGet: { _ in
            callCount += 1
            return self.sampleMddlSchemaJson
        }, cacheTtlSeconds: 1800)

        _ = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.mDL",
            registryUrl: "https://wallet.example.com/registry"
        )
        _ = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.other",
            registryUrl: "https://wallet.example.com/registry"
        )
        _ = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.mDL",
            registryUrl: "https://other-wallet.example.com/registry"
        )

        XCTAssertEqual(callCount, 3, "different doctype/registryUrl must never be served from another key's cache entry")
    }

    func testFetchRefetchesAfterTtlExpires() async {
        var callCount = 0
        let fetcher = MddlSchemaFetcher(httpGet: { _ in
            callCount += 1
            return self.sampleMddlSchemaJson
        }, cacheTtlSeconds: 0.05)

        _ = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")
        try? await Task.sleep(nanoseconds: 150_000_000) // 150ms > 50ms TTL
        _ = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")

        XCTAssertEqual(callCount, 2, "a call after TTL expiry must hit the network again")
    }

    func testFetchNeverCachesAFailedLookup() async {
        var callCount = 0
        let fetcher = MddlSchemaFetcher(httpGet: { _ in
            callCount += 1
            return nil
        }, cacheTtlSeconds: 1800)

        let first = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")
        let second = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")

        XCTAssertNil(first)
        XCTAssertNil(second)
        XCTAssertEqual(callCount, 2, "a nil result must never be cached - every call must retry all strategies fresh")
    }
}
