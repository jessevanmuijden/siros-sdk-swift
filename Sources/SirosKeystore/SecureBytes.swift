// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A short-lived secret (a PIN or passphrase) held in a buffer THIS TYPE owns and
/// explicitly zeroes, instead of `Data`/`String`.
///
/// `Data` and `String` cannot be reliably wiped: their storage is copy-on-write and
/// ARC-managed, so a `let`, a closure capture, or an internal copy the standard
/// library makes while reading or converting the value can keep the bytes alive in
/// memory this type never sees and cannot reach, for as long as the allocator
/// chooses not to reuse that page. `SecureBytes` fixes the one thing Swift *can*
/// give a guarantee about: ONE buffer, allocated and freed by this type, is
/// positively overwritten with zero the moment ``wipe()`` runs (on `deinit`, or
/// sooner when the caller is done with it) rather than left for ARC to collect
/// whenever it gets around to it.
///
/// ## What this does NOT fix
///
/// This is a best-effort mitigation, not a guarantee that the secret never
/// appears in memory outside this buffer. In particular:
///
/// - Every call that hands the secret to an existing `Data`-typed API (this
///   SDK's own ``ScaSignFlow/classifySecret(_:)``, or the UniFFI-generated FFI
///   call in `UniFFISigner`) necessarily makes an ordinary, unwipeable `Data`
///   copy for that call - `SecureBytes` cannot change the signature of code it
///   does not own. Keep each such copy as short-lived and unnamed as possible
///   (an expression, not a `let`) so ARC drops it as soon as the call returns;
///   this does not make it wiped, only not retained.
///   See ``dataCopy()``'s doc comment.
/// - Crossing the UniFFI/Rust FFI boundary (`FfiConverterData.write`, in the
///   generated `siros_wscd_manager.swift`) appends the PIN's bytes into a
///   growable `[UInt8]` `RustBuffer` one `Array.append` at a time; any
///   reallocation Swift's `Array` performs while that buffer grows makes an
///   intermediate copy this type has no way to reach or wipe. Once the call
///   returns, the Rust side owns its own copy, zeroed (or not) under its own
///   contract - entirely outside what this Swift SDK can audit or control.
/// - The page lock is best-effort and MUST NOT be relied on. The buffer lives in
///   its own anonymous `mmap` region, rounded up to whole pages and shared with
///   no other allocation, and that region is `mlock`ed. Because the region is
///   exclusively this instance's, `munlock` on wipe cannot drop swap protection
///   from any other live buffer (`mlock`/`munlock` are page-granular and not
///   reference-counted, so locking ordinary heap ranges would not give that).
///   But the lock can still fail (no `RLIMIT_MEMLOCK` budget, no permission,
///   sandbox) and that failure is deliberately not surfaced - a wipe must happen
///   either way - and a lock never stops another process with sufficient
///   privilege from reading this process's memory. If the region cannot be
///   mapped at all, an ordinary unlocked heap buffer is used instead.
///
/// `SecureBytes` is `@unchecked Sendable`: every mutating access is
/// lock-protected, and the type's only shared state is the buffer itself.
public final class SecureBytes: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: UnsafeMutableBufferPointer<UInt8>?
    /// Length of the private `mmap` region backing `buffer`, or `0` when the
    /// buffer is an ordinary heap allocation (empty secret, or `mmap` failed).
    private var mappedLength = 0

    private static var pageSize: Int {
        let size = sysconf(Int32(_SC_PAGESIZE))
        return size > 0 ? size : 4096
    }

    /// Allocates a zero-filled buffer of `count` bytes and lets `fill` write the
    /// secret straight into it, so no intermediate plaintext copy is created.
    private init(count: Int, fill: (UnsafeMutableBufferPointer<UInt8>) -> Void) {
        if count == 0 {
            buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: 0)
            return
        }
        let page = SecureBytes.pageSize
        let length = ((count + page - 1) / page) * page
        #if canImport(Darwin)
        let anon = MAP_ANON
        #else
        let anon = MAP_ANONYMOUS
        #endif
        let raw = mmap(nil, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | anon, -1, 0)
        if let raw, raw != UnsafeMutableRawPointer(bitPattern: -1) {
            // Best-effort: asks the OS not to swap these pages. The region is ours alone, so
            // unlocking it on wipe cannot affect any other buffer. A failure is not reported.
            _ = mlock(raw, length)
            mappedLength = length
            buffer = UnsafeMutableBufferPointer(start: raw.bindMemory(to: UInt8.self, capacity: count), count: count)
        } else {
            let heap = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: count)
            heap.initialize(repeating: 0)
            buffer = heap
        }
        fill(buffer!)
    }

    /// Copies `bytes` into a freshly allocated buffer this instance owns.
    public convenience init(_ bytes: [UInt8]) {
        self.init(count: bytes.count) { dst in
            bytes.withUnsafeBufferPointer { src in
                if let base = dst.baseAddress, let from = src.baseAddress { base.update(from: from, count: src.count) }
            }
        }
    }

    /// Copies the UTF-8 encoding of `string` into a freshly allocated buffer
    /// (no intermediate `Array`). `string` itself is an ordinary Swift `String`
    /// and is NOT wiped by this initializer - only use this where the secret
    /// already exists as a `String` for a reason outside this type's control (a
    /// test fixture, or a host's `WscdAuthProvider` implementation).
    public convenience init(utf8 string: String) {
        let utf8 = string.utf8
        self.init(count: utf8.count) { dst in
            let copied: Void? = utf8.withContiguousStorageIfAvailable { src in
                if let base = dst.baseAddress, let from = src.baseAddress { base.update(from: from, count: src.count) }
            }
            if copied == nil {
                for (i, byte) in utf8.enumerated() { dst[i] = byte }
            }
        }
    }

    /// Copies `data` directly into a freshly allocated buffer (no intermediate
    /// `Array`). `data` itself is an ordinary `Data` and is NOT wiped by this
    /// initializer - this is the one for wrapping a `Data` this SDK did not
    /// allocate and cannot reach after (a host's
    /// `WscdAuthProvider.requestPin(pluginId:)` result, see `UniFFISigner.swift`),
    /// as early as possible after receiving it.
    public convenience init(_ data: Data) {
        self.init(count: data.count) { dst in
            data.withUnsafeBytes { src in
                if let base = dst.baseAddress, let from = src.baseAddress {
                    UnsafeMutableRawPointer(base).copyMemory(from: from, byteCount: src.count)
                }
            }
        }
    }

    /// The number of bytes held, or `0` once wiped.
    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return buffer?.count ?? 0
    }

    /// Whether `wipe()` has already run.
    public var isWiped: Bool {
        lock.lock(); defer { lock.unlock() }
        return buffer == nil
    }

    /// Copies the held bytes out as `Data`, for the one call that needs a
    /// `Data`-typed argument - this copy is an ORDINARY `Data`, not tracked or
    /// wiped by this type (see the type's doc comment on residual exposure).
    /// Returns empty `Data` once wiped.
    public func dataCopy() -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let buffer else { return Data() }
        return Data(buffer)
    }

    /// Overwrites the buffer with zero and releases it. Idempotent: safe to
    /// call more than once, including after `deinit` has already run it.
    public func wipe() {
        lock.lock(); defer { lock.unlock() }
        guard let buffer else { return }
        if mappedLength > 0, let base = buffer.baseAddress {
            // Zero the whole region (including the page tail), then release it. Safe to
            // munlock: no other allocation shares these pages.
            memset(base, 0, mappedLength)
            _ = munlock(base, mappedLength)
            _ = munmap(base, mappedLength)
            mappedLength = 0
        } else {
            buffer.update(repeating: 0)
            buffer.deallocate()
        }
        self.buffer = nil
    }

    deinit { wipe() }
}
