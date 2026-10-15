// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import LocalAuthentication
import SirosCredentials

/// Authentication factors for EC TS12 payment confirmations, verified for THIS
/// operation with the device's biometrics (inherence). The possession factor
/// comes from where the key lives (the SDK derives it); a software key has
/// none, so a transaction needs a remote or hardware-backed WSCD key as well.
///
/// The SDK decides what the factors mean; this only runs the platform check
/// and reports which biometry the platform says it was.
enum SampleAuthenticationFactors {
    static func provider() -> InterimAuthenticationFactorsProvider {
        InterimAuthenticationFactorsProvider(
            verifiedThisOperation: { _ in await verifyBiometrics() },
            canVerifyAnotherCategory: { _ in LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) }
        )
    }

    private static func verifyBiometrics() async -> [AuthenticationFactor] {
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil),
              (try? await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: L10n.string("transactionConsent.biometricReason"))) == true
        else { return [] }
        switch context.biometryType {
        case .faceID: return [AuthenticationFactor(.inherence, "face_device")]
        case .touchID: return [AuthenticationFactor(.inherence, "fingerprint_device")]
        default: return [AuthenticationFactor(.inherence, "other")]
        }
    }
}
