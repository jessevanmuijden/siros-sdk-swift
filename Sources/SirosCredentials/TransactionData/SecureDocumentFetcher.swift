// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Fetches a document an attacker can influence the location of (a schema,
/// claim or label document, or type metadata, referenced by SCA metadata).
///
/// Known limit: the public-address check is a preflight; the connection resolves
/// the name again, so a name that answers differently to the two lookups (DNS
/// rebinding) is not stopped here. It is bounded by the other measures (no
/// redirects, no credentials, size and time caps, and the integrity pins the
/// issuer can put on referenced documents); closing it needs connection-level
/// address pinning, which `URLSession` does not offer.
///
/// What it guarantees:
/// - https only, to a public host (see ``PublicHostPolicy``);
/// - a FRESH ephemeral session per fetch: no cookie jar, no credential store,
///   no cache, no wallet token or any header of the wallet's own, and HTTP
///   authentication challenges are cancelled, never answered;
/// - redirects are NOT followed (a redirect could name a private address or
///   another host); a redirect response is a failure;
/// - a hard size cap, enforced while the body streams in (the transfer is
///   cancelled as soon as the cap is exceeded, and a larger declared
///   `Content-Length` is refused up front), and a hard time cap.
public final class SecureDocumentFetcher: @unchecked Sendable {
    private let timeout: TimeInterval
    private let resolver: PublicHostPolicy.Resolver
    private let configure: (@Sendable (URLSessionConfiguration) -> Void)?

    /// - Parameters:
    ///   - resolver: host resolution for the public-address check (tests inject one).
    ///   - configure: lets tests add a `URLProtocol`; production passes none.
    public init(
        timeout: TimeInterval = 10,
        resolver: @escaping PublicHostPolicy.Resolver = PublicHostPolicy.systemResolver,
        configure: (@Sendable (URLSessionConfiguration) -> Void)? = nil
    ) {
        self.timeout = timeout
        self.resolver = resolver
        self.configure = configure
    }

    /// The session configuration every fetch uses.
    public static func makeConfiguration(timeout: TimeInterval) -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.urlCredentialStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpAdditionalHeaders = nil
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        return config
    }

    /// The document at `url`, or `nil` for any refusal or failure. The time cap
    /// covers everything, host resolution included, and releases the caller on
    /// time even if a resolver or the transport never answers.
    ///
    /// - Parameters:
    ///   - headers: sent as given. EMPTY for every attacker-influenced location;
    ///     only the wallet's own backend is ever fetched with headers.
    ///   - ownBackend: skips the https and public-host rules for the wallet's
    ///     own configured backend (which may be a private or development host).
    ///     Never set for a location that came from a document.
    public func fetch(_ url: URL, maxBytes: Int, headers: [String: String] = [:], ownBackend: Bool = false) async -> Data? {
        await withDeadline(timeout, fallback: nil) { await self.fetchWithoutDeadline(url, maxBytes: maxBytes, headers: headers, ownBackend: ownBackend) }
    }

    private func fetchWithoutDeadline(_ url: URL, maxBytes: Int, headers: [String: String], ownBackend: Bool) async -> Data? {
        guard let host = url.host, url.user == nil, url.password == nil, maxBytes > 0 else { return nil }
        if !ownBackend {
            guard url.scheme?.lowercased() == "https", headers.isEmpty,
                  await PublicHostPolicy.isAllowed(host: host, resolver: resolver) else { return nil }
        } else {
            guard ["https", "http"].contains(url.scheme?.lowercased() ?? "") else { return nil }
        }
        // A resolver that ignores cancellation can return after the deadline released the caller: do not
        // go on to open a connection for a request nobody is waiting for any more.
        guard !Task.isCancelled else { return nil }
        let config = Self.makeConfiguration(timeout: timeout)
        configure?(config)
        let delegate = FetchDelegate(maxBytes: maxBytes)
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        // The hard time cap does not rely on the transport's own timeouts.
        let limit = timeout
        let timer = Task {
            try? await Task.sleep(nanoseconds: UInt64(max(limit, 0) * 1_000_000_000))
            delegate.cancel()
        }
        defer { timer.cancel(); session.invalidateAndCancel() }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Data?, Never>) in
                delegate.start(session.dataTask(with: request), continuation: continuation)
            }
        } onCancel: {
            delegate.cancel()
        }
    }
}

final class FetchDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let maxBytes: Int
    private let lock = NSLock()
    private var buffer = Data()
    private var continuation: CheckedContinuation<Data?, Never>?
    private var task: URLSessionDataTask?
    private var failed = false
    private var cancelledEarly = false

    init(maxBytes: Int) { self.maxBytes = maxBytes }

    func start(_ task: URLSessionDataTask, continuation: CheckedContinuation<Data?, Never>) {
        lock.lock()
        if cancelledEarly { lock.unlock(); continuation.resume(returning: nil); return }
        self.continuation = continuation
        self.task = task
        lock.unlock()
        task.resume()
    }

    func cancel() {
        lock.lock()
        cancelledEarly = true
        let task = self.task
        lock.unlock()
        task?.cancel()
        finish(nil)
    }

    private func finish(_ data: Data?) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: data)
    }

    private func fail(_ task: URLSessionTask) {
        lock.lock(); failed = true; lock.unlock()
        task.cancel()
        finish(nil)
    }

    func urlSession(_: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              http.expectedContentLength <= Int64(maxBytes) else {
            completionHandler(.cancel)
            fail(dataTask)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        // Checked BEFORE appending: one large callback must not allocate past the cap.
        let tooBig = buffer.count + data.count > maxBytes
        if !tooBig { buffer.append(data) }
        lock.unlock()
        if tooBig { fail(dataTask) }
    }

    /// Redirects are never followed.
    func urlSession(_: URLSession, task: URLSessionTask, willPerformHTTPRedirection _: HTTPURLResponse,
                    newRequest _: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
        fail(task)
    }

    /// Server trust is evaluated by the system; any other challenge (HTTP
    /// authentication) is cancelled, never answered.
    func urlSession(_: URLSession, task _: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == "NSURLAuthenticationMethodServerTrust" {
            completionHandler(.performDefaultHandling, nil)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    func urlSession(_: URLSession, task _: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let ok = error == nil && !failed
        let data = buffer
        lock.unlock()
        finish(ok ? data : nil)
    }
}
