// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SirosCredentials
import SirosKeystore

#if os(iOS)
extension SirosWallet {
    /// Assembles `init`'s mdoc+BBS ZK proof-system registry and the
    /// residency they share - split out of `init` itself to keep
    /// `SirosWallet.swift` under SwiftLint's `file_length` error threshold.
    static func makeIOSZkProofSystemRegistry(
        config: WalletConfig,
        credentialStore: CredentialStore,
        zkCircuitClient: ZkCircuitClient,
        bbsHolderStateVault: BbsHolderStateVault?
    ) -> (registry: ZkProofSystemRegistry, residency: ZkProverResidency) {
        // BbsProofSystem (like Longfellow/Vega) is iOS-only - its native
        // zk-cred-bbs XCFramework ships iOS slices only, so the type itself
        // does not exist outside `#if os(iOS)` (see BbsProofSystem.swift's
        // own gating comment).
        //
        // `bbsHolderStateVault` is `self.bbsHolderStateVault` from `init` -
        // constructed there unconditionally whenever the keystore conforms
        // to `ExtensionStore` (NOT gated on `config.bbsCredentialTypes`,
        // because `deleteCredential`/`deleteRenewalSourceBatch` need it too,
        // to satisfy `BbsHolderStateVault.remove`'s cleanup contract even
        // after BBS credential types stop being configured - see that
        // property's own doc comment). This function only DECIDES whether
        // to register `BbsProofSystem` with it - registration additionally
        // requires `config.bbsCredentialTypes` to be non-empty, since an
        // empty set is "this deployment issues no BBS credentials", not
        // "support nothing in particular" (see `WalletConfig.bbsCredentialTypes`'s
        // doc comment: `BbsProofSystem.supportedCredentialTypes` maps
        // straight from this set, and `ZkProofSystemRegistry.resolve`
        // requires that set to already contain the requested credential
        // type before `matchingSpec` is even consulted, so an empty set
        // would make `resolve` reject every BBS request regardless of
        // whether the system were registered at all - registering it
        // anyway would just needlessly advertise the system id via
        // `registeredSystemIds` with nothing it can ever actually serve).
        //
        // The proof system keys on the JWP itself (all it has at
        // presentation time); the vault keys on credential id (privatedata-
        // spec §6.1.1 requires an entry key to name a tracked entity) - this
        // closure is the join between the two, same as Kotlin's.
        var bbsProofSystem: BbsProofSystem?
        if !config.bbsCredentialTypes.isEmpty, let bbsHolderStateVault {
            let bbsHolderStateStore: BbsHolderStateStore = { issuedJwp in
                guard let credential = await credentialStore.getAll().first(where: { $0.raw == issuedJwp }) else {
                    return nil
                }
                return await bbsHolderStateVault.get(credentialId: String(credential.id))
            }
            bbsProofSystem = BbsProofSystem(
                holderState: bbsHolderStateStore,
                supportedVcts: config.bbsCredentialTypes
            )
        }

        // One residency shared by every mdoc ZK proof system constructed
        // here - see `ZkProverResidency`'s own doc comment for why. BBS has
        // no native prover/residency concept at all (no XCFramework, no
        // large resident artifact - see `BbsProofSystem`'s own doc comment),
        // so it is appended after, not threaded through the residency.
        let zkProverResidency = ZkProverResidency()
        var zkSystems: [ZkProofSystem] = [
            LongfellowZkProofSystem(zkCircuitClient: zkCircuitClient, residency: zkProverResidency),
            VegaProofSystem(zkCircuitClient: zkCircuitClient, residency: zkProverResidency),
        ]
        if let bbsProofSystem { zkSystems.append(bbsProofSystem) }
        return (ZkProofSystemRegistry(systems: zkSystems), zkProverResidency)
    }
}
#endif
