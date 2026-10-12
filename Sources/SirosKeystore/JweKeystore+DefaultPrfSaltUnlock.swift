// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

#if canImport(CryptoKit)
extension JweKeystore {
    /// Forwards to the `prfSalt`-carrying overload with a fresh random salt -
    /// this method's exact prior behavior - for callers with no real salt to
    /// offer (e.g. unlock-after-resume, where `encryptedContainer` is never
    /// empty so no salt is ever persisted from it anyway). See
    /// `KeystoreManager.unlock(prfOutput:encryptedContainer:hkdfSalt:hkdfInfo:prfSalt:)`'s
    /// doc comment for why a brand-new container needs the real salt instead.
    public func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws {
        var prfSalt = Data(count: 32)
        // swiftlint:disable:next force_unwrapping
        prfSalt.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        try await unlock(
            prfOutput: prfOutput, encryptedContainer: encryptedContainer,
            hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo, prfSalt: prfSalt
        )
    }
}
#endif
