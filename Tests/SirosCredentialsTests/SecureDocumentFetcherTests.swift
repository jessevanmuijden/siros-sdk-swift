// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import SirosCredentials

/// A URLProtocol that answers from a closure and records what it was asked.
final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    enum Behaviour {
        case ok(Data, contentLength: Int64? = nil)
        case chunks([Data])
        case oneChunk(Data)
        case redirect(String)
        case status(Int)
        case never
    }
    nonisolated(unsafe) static var behaviour: Behaviour = .ok(Data())
    nonisolated(unsafe) static var seen: [URLRequest] = []
    private static let lock = NSLock()

    static func reset(_ b: Behaviour) { lock.lock(); behaviour = b; seen = []; lock.unlock() }
    static var requests: [URLRequest] { lock.lock(); defer { lock.unlock() }; return seen }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        Self.lock.lock(); Self.seen.append(request); let b = Self.behaviour; Self.lock.unlock()
        let url = request.url!
        func respond(_ status: Int, headers: [String: String] = [:]) {
            client?.urlProtocol(self, didReceive: HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!, cacheStoragePolicy: .notAllowed)
        }
        switch b {
        case .ok(let data, let length):
            respond(200, headers: length.map { ["Content-Length": String($0)] } ?? ["Content-Length": String(data.count)])
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        case .chunks(let parts):
            respond(200)
            for part in parts { client?.urlProtocol(self, didLoad: part) }
            client?.urlProtocolDidFinishLoading(self)
        case .oneChunk(let data):
            respond(200)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        case .redirect(let location):
            // A real redirect: if the session follows it, the target is requested next and answered.
            #if os(Linux)
            // swift-corelibs-foundation cannot drive a URLProtocol redirect; the delegate is tested directly.
            respond(302, headers: ["Location": location])
            client?.urlProtocolDidFinishLoading(self)
            #else
            if Self.requests.count > 1 {
                respond(200, headers: ["Content-Length": "2"])
                client?.urlProtocol(self, didLoad: Data("{}".utf8))
                client?.urlProtocolDidFinishLoading(self)
            } else {
                let target = URL(string: location)!
                let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": location])!
                client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
            }
            #endif
        case .status(let code):
            respond(code)
            client?.urlProtocolDidFinishLoading(self)
        case .never:
            break
        }
    }
}

final class SecureDocumentFetcherTests: XCTestCase {
    private let publicResolver: PublicHostPolicy.Resolver = { _ in ["93.184.216.34"] }
    private let url = URL(string: "https://docs.example/labels.json")!

    private func fetcher(timeout: TimeInterval = 5, resolver: PublicHostPolicy.Resolver? = nil) -> SecureDocumentFetcher {
        SecureDocumentFetcher(timeout: timeout, resolver: resolver ?? publicResolver, configure: { $0.protocolClasses = [StubURLProtocol.self] })
    }

    func testFetchesADocumentAndSendsNothingOfTheWallets() async throws {
        StubURLProtocol.reset(.ok(Data("{}".utf8)))
        // Wallet-side state that must never reach the document host.
        let cookie = try XCTUnwrap(HTTPCookie(properties: [.domain: "docs.example", .path: "/", .name: "session", .value: "WALLET-SESSION", .secure: "TRUE"]))
        HTTPCookieStorage.shared.setCookie(cookie)
        defer { HTTPCookieStorage.shared.deleteCookie(cookie) }
        let data = await fetcher().fetch(url, maxBytes: 1024)
        XCTAssertEqual(data, Data("{}".utf8))
        let request = try XCTUnwrap(StubURLProtocol.requests.first)
        let headers = request.allHTTPHeaderFields ?? [:]
        XCTAssertNil(headers["Authorization"])
        XCTAssertNil(headers["Cookie"])
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.url, url)
    }

    func testTheSessionConfigurationCarriesNoCredentialsCookiesOrCache() {
        let c = SecureDocumentFetcher.makeConfiguration(timeout: 7)
        XCTAssertNil(c.httpCookieStorage)
        XCTAssertFalse(c.httpShouldSetCookies)
        XCTAssertEqual(c.httpCookieAcceptPolicy, .never)
        XCTAssertNil(c.urlCredentialStorage)
        XCTAssertNil(c.urlCache)
        XCTAssertNil(c.httpAdditionalHeaders)
        XCTAssertEqual(c.timeoutIntervalForRequest, 7)
        XCTAssertEqual(c.timeoutIntervalForResource, 7)
    }

    func testOnlyHttpsToAPublicHostIsFetched() async {
        StubURLProtocol.reset(.ok(Data("{}".utf8)))
        let refused = [
            "http://docs.example/x.json", "ftp://docs.example/x", "file:///etc/passwd", "https://user:pw@docs.example/x",
            "https://127.0.0.1/x", "https://[::1]/x", "https://10.0.0.5/x", "https://169.254.169.254/latest/meta-data",
            "https://192.168.1.1/x", "https://localhost/x", "https://intranet/x", "https://printer.local/x",
        ]
        for text in refused {
            let result = await fetcher().fetch(URL(string: text)!, maxBytes: 1024)
            XCTAssertNil(result, text)
        }
        XCTAssertTrue(StubURLProtocol.requests.isEmpty, "no request was even made")
    }

    func testANameThatResolvesToAPrivateAddressIsRefused() async {
        StubURLProtocol.reset(.ok(Data("{}".utf8)))
        for resolved in [["10.1.2.3"], ["127.0.0.1"], ["93.184.216.34", "169.254.169.254"], ["::1"], ["fe80::1"], []] {
            let r = await fetcher(resolver: { _ in resolved }).fetch(url, maxBytes: 1024)
            XCTAssertNil(r, "\(resolved)")
        }
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }

    func testRedirectsAreNotFollowed() async {
        StubURLProtocol.reset(.redirect("https://127.0.0.1/secret"))
        let result = await fetcher().fetch(url, maxBytes: 1024)
        XCTAssertNil(result)
        XCTAssertEqual(StubURLProtocol.requests.count, 1, "the redirect target was never requested")
    }

    /// The delegate refuses every redirect, whatever the platform's session does with it.
    func testTheDelegateRefusesEveryRedirect() {
        let delegate = FetchDelegate(maxBytes: 100)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: URLRequest(url: url))
        let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: nil, headerFields: ["Location": "https://127.0.0.1/x"])!
        var offered: URLRequest?? = .none
        delegate.urlSession(session, task: task, willPerformHTTPRedirection: response, newRequest: URLRequest(url: URL(string: "https://127.0.0.1/x")!)) { offered = .some($0) }
        XCTAssertNotNil(offered, "the completion handler was called")
        XCTAssertNil(offered ?? nil, "with nil: the redirect is not followed")
    }

    func testTheSizeCapIsEnforcedWhileStreamingAndOnDeclaredLength() async {
        StubURLProtocol.reset(.chunks([Data(repeating: 0x41, count: 600), Data(repeating: 0x41, count: 600)]))
        let streamed = await fetcher().fetch(url, maxBytes: 1000)
        XCTAssertNil(streamed, "a body that grows past the cap is refused")
        StubURLProtocol.reset(.ok(Data("{}".utf8), contentLength: 5_000_000))
        let declared = await fetcher().fetch(url, maxBytes: 1000)
        XCTAssertNil(declared, "a declared length over the cap is refused up front")
        StubURLProtocol.reset(.chunks([Data(repeating: 0x41, count: 400), Data(repeating: 0x41, count: 600)]))
        let exact = await fetcher().fetch(url, maxBytes: 1000)
        XCTAssertEqual(exact?.count, 1000, "exactly the cap is allowed")
    }

    /// One callback larger than the cap is refused without being retained.
    func testASingleOversizedChunkIsRefused() async {
        StubURLProtocol.reset(.oneChunk(Data(repeating: 0x41, count: 50_000)))
        let result = await fetcher().fetch(url, maxBytes: 1000)
        XCTAssertNil(result)
    }

    /// A resolver that never answers cannot hold the fetch past its deadline.
    func testAHungResolverIsCoveredByTheDeadline() async {
        StubURLProtocol.reset(.ok(Data("{}".utf8)))
        let hung: PublicHostPolicy.Resolver = { _ in await withCheckedContinuation { (_: CheckedContinuation<[String], Never>) in } }
        let started = Date()
        let result = await fetcher(timeout: 0.3, resolver: hung).fetch(url, maxBytes: 1000)
        XCTAssertNil(result)
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }

    /// Only the wallet's own backend is fetched with headers and without the public-host rule.
    func testOwnBackendMayUseHeadersAndAPrivateHttpHostButNothingElseMay() async throws {
        StubURLProtocol.reset(.ok(Data("{}".utf8)))
        let backend = URL(string: "http://192.168.1.5:8080/registry/type-metadata?vct=x")!
        let data = await fetcher().fetch(backend, maxBytes: 100, headers: ["Authorization": "Bearer wallet"], ownBackend: true)
        XCTAssertEqual(data, Data("{}".utf8))
        XCTAssertEqual(StubURLProtocol.requests.first?.value(forHTTPHeaderField: "Authorization"), "Bearer wallet")
        // The same request to a document-supplied location is refused: private/http, and headers.
        StubURLProtocol.reset(.ok(Data("{}".utf8)))
        let notBackend = await fetcher().fetch(backend, maxBytes: 100, headers: ["Authorization": "Bearer wallet"])
        XCTAssertNil(notBackend)
        let withHeaders = await fetcher().fetch(url, maxBytes: 100, headers: ["Authorization": "Bearer wallet"])
        XCTAssertNil(withHeaders, "headers are never sent to a document-supplied location")
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }

    func testNon200AndTimeoutAndCancellationFail() async {
        StubURLProtocol.reset(.status(404))
        let missing = await fetcher().fetch(url, maxBytes: 1000)
        XCTAssertNil(missing)
        StubURLProtocol.reset(.never)
        let started = Date()
        let slow = await fetcher(timeout: 0.4).fetch(url, maxBytes: 1000)
        XCTAssertNil(slow)
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
        StubURLProtocol.reset(.never)
        let f = fetcher(timeout: 30)
        let task = Task { await f.fetch(url, maxBytes: 1000) }
        try? await Task.sleep(nanoseconds: 150_000_000)
        task.cancel()
        let cancelledAt = Date()
        let cancelled = await task.value
        XCTAssertNil(cancelled)
        XCTAssertLessThan(Date().timeIntervalSince(cancelledAt), 3, "cancelling the awaiting task releases it at once")
    }
}

final class PublicHostPolicyTests: XCTestCase {
    func testAddressRanges() {
        let denied = ["0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.255", "192.168.0.1",
                      "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
                      "::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "2001:db8::1",
                      "64:ff9b::7f00:1", "2002:7f00:1::1"]
        for text in denied {
            let address = PublicHostPolicy.parseAddress(text)
            XCTAssertNotNil(address, text)
            XCTAssertFalse(address.map(PublicHostPolicy.isPublic) ?? true, text)
        }
        for text in ["93.184.216.34", "8.8.8.8", "172.32.0.1", "100.63.255.255", "2606:2800:220:1:248:1893:25c8:1946", "::ffff:8.8.8.8"] {
            XCTAssertTrue(PublicHostPolicy.parseAddress(text).map(PublicHostPolicy.isPublic) ?? false, text)
        }
    }

    func testHostNames() async {
        let good: PublicHostPolicy.Resolver = { _ in ["93.184.216.34"] }
        let allowed = await PublicHostPolicy.isAllowed(host: "docs.example.org", resolver: good)
        XCTAssertTrue(allowed)
        for host in ["", "localhost", "foo.localhost", "printer.local", "db.internal", "intranet", "docs.example.", "[::1]", "127.0.0.1"] {
            let result = await PublicHostPolicy.isAllowed(host: host, resolver: good)
            XCTAssertFalse(result, host)
        }
        let unresolvable = await PublicHostPolicy.isAllowed(host: "nope.example.org", resolver: { _ in [] })
        XCTAssertFalse(unresolvable)
    }

    /// A resolver that ignores cancellation and answers after the deadline must not lead to a request.
    func testALateResolverAnswerStartsNoRequest() async throws {
        final class Started: @unchecked Sendable { let l = NSLock(); var n = 0; func bump() { l.lock(); n += 1; l.unlock() } }
        let started = Started()
        let slow: PublicHostPolicy.Resolver = { _ in
            await withCheckedContinuation { (c: CheckedContinuation<[String], Never>) in
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.4) { c.resume(returning: ["93.184.216.34"]) }
            }
        }
        let fetcher = SecureDocumentFetcher(timeout: 0.1, resolver: slow, configure: { _ in started.bump() })
        let result = await fetcher.fetch(URL(string: "https://docs.example.com/a.json")!, maxBytes: 100)
        XCTAssertNil(result)
        try await Task.sleep(nanoseconds: 800_000_000)
        XCTAssertEqual(started.n, 0, "no session was configured, so no request started")
    }
}
