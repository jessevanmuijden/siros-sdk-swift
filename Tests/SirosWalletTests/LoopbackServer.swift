// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

/// A one-shot HTTP/1.1 server on the loopback interface, so the real transport
/// can be driven with a chosen status and body.
///
/// Deliberately not a `URLProtocol` stub: registering one affects
/// `URLSession.shared` process-wide, and on Linux it does not take effect once
/// the shared session has been used by an earlier test - which passes in
/// isolation and fails in the full suite. A real socket has neither problem.
final class LoopbackServer: @unchecked Sendable {
    private let listenFd: Int32
    let port: UInt16

    init(status: Int, body: String) throws {
        // SOCK_STREAM is an enum on Glibc and a plain Int32 on Darwin.
        #if canImport(Glibc)
        let streamType = Int32(SOCK_STREAM.rawValue)
        #else
        let streamType = SOCK_STREAM
        #endif
        listenFd = socket(AF_INET, streamType, 0)
        guard listenFd >= 0 else { throw Failure.socket }
        var yes: Int32 = 1
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0 // any free port
        addr.sin_addr = in_addr(s_addr: UInt32(0x7F00_0001).bigEndian) // 127.0.0.1
        let fd = listenFd
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(fd, 1) == 0 else { close(fd); throw Failure.bind }

        var actual = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        port = UInt16(bigEndian: actual.sin_port)

        Thread.detachNewThread {
            let conn = accept(fd, nil, nil)
            guard conn >= 0 else { return }
            var buf = [UInt8](repeating: 0, count: 4096)
            _ = recv(conn, &buf, buf.count, 0) // consume the request line + headers
            let payload = Data(body.utf8)
            let head = """
            HTTP/1.1 \(status) \(HTTPURLResponse.localizedString(forStatusCode: status))\r
            Content-Type: application/json\r
            Content-Length: \(payload.count)\r
            Connection: close\r
            \r

            """
            var out = Data(head.utf8)
            out.append(payload)
            out.withUnsafeBytes { _ = send(conn, $0.baseAddress, out.count, 0) }
            close(conn)
        }
    }

    func stop() { close(listenFd) }

    enum Failure: Error { case socket, bind }
}
