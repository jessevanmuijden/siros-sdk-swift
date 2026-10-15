// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

extension SirosWallet {
    /// Runtime switch for EC TS12 payment-SCA `transaction_data` handling.
    /// Default `false` (`WalletConfig.transactionDataEnabled`). Readable and
    /// writable at any time from any thread; a change applies to flows
    /// started after it, a flow already in progress keeps the setting it
    /// started with. WMP offers capabilities per session, so a change takes
    /// effect on the WMP transport at the next session (reconnect).
    public var transactionDataEnabled: Bool {
        get { lock.lock(); defer { lock.unlock() }; return transactionDataEnabledValue }
        set { lock.lock(); transactionDataEnabledValue = newValue; lock.unlock() }
    }

    /// The consent handler that shows a transaction to the user (EC TS12
    /// section 3.3). Without one the wallet cannot show the transaction, so
    /// TS12 handling behaves as disabled: nothing is declared and requests
    /// carrying `transaction_data` are refused.
    public var transactionConsentHandler: (any TransactionConsentHandler)? {
        get { lock.lock(); defer { lock.unlock() }; return transactionConsentHandlerStorage }
        set { lock.lock(); transactionConsentHandlerStorage = newValue; lock.unlock() }
    }

    /// Whether a consent handler is registered.
    var transactionConsentHandlerRegistered: Bool { transactionConsentHandler != nil }

    /// Supplies the authentication factors applied for a presentation (TS12
    /// `amr`). The default is conservative and cannot satisfy SCA on its own;
    /// see ``InterimAuthenticationFactorsProvider``.
    public var authenticationFactorsProvider: any AuthenticationFactorsProvider {
        get { lock.lock(); defer { lock.unlock() }; return authenticationFactorsProviderStorage }
        set { lock.lock(); authenticationFactorsProviderStorage = newValue; lock.unlock() }
    }

    /// Preferred language for transaction labels (BCP 47). Safe to change at any time.
    public var transactionDataLocale: String {
        get { lock.lock(); defer { lock.unlock() }; return transactionDataLocaleStorage }
        set { lock.lock(); transactionDataLocaleStorage = newValue; lock.unlock() }
    }

    /// Effective enablement: the flag is on AND a consent handler is
    /// registered. Without a handler the wallet cannot show the transaction,
    /// so it behaves as disabled.
    var transactionDataEffectivelyEnabled: Bool {
        lock.lock(); defer { lock.unlock() }
        return transactionDataEnabledValue && transactionConsentHandlerStorage != nil
    }

    /// `flow_start.features` for a flow started now (legacy engine).
    var transactionDataEngineFeatures: [String]? {
        TransactionDataDeclaration.engineFeatures(enabled: transactionDataEffectivelyEnabled)
    }

    /// `capabilities_offered` for a WMP session created now.
    var transactionDataWmpCapabilities: [String: AnyCodable]? {
        TransactionDataDeclaration.wmpCapabilitiesOffered(enabled: transactionDataEffectivelyEnabled)
    }
}
