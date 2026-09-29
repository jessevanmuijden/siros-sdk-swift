// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

#if canImport(AVFoundation)
import AVFoundation
#endif

/// QR code scanner using the device camera.
struct QRScannerView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var pasteUri = ""
    /// Non-nil the instant a code is decoded, until the delayed handoff below
    /// fires. Drives the checkmark/flash overlay - see `handleDetectedCode`.
    @State private var detectedCode: String?
    /// The pending delayed handoff scheduled by `handleDetectedCode`, if any -
    /// cancelled in `onDisappear` so a scan detected right before the user
    /// navigates away can't fire afterwards and call `viewModel.handleQrResult`,
    /// which would incorrectly close whatever screen is showing BY THEN (a
    /// real Copilot-review finding: `handleQrResult`'s unconditional
    /// `closeActivate()` closes Activate regardless of its current mode, so a
    /// stale scan could dismiss an unrelated, later-opened screen).
    @State private var pendingHandoff: DispatchWorkItem?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ZStack {
                    #if targetEnvironment(simulator)
                    simulatorFallback
                    #else
                    CameraQRScanner { code in
                        handleDetectedCode(code)
                    }
                    #endif

                    // Viewfinder overlay
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(detectedCode == nil ? Color.white : SirosTheme.brand, lineWidth: 3)
                        .frame(width: 250, height: 250)
                        .shadow(radius: 8)

                    if detectedCode != nil {
                        detectionOverlay
                    }
                }

                // Paste URI fallback (always visible, like Kotlin)
                VStack(spacing: 8) {
                    Text(L10n.string("qr.manualInput"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack {
                        TextField("openid-credential-offer://...", text: $pasteUri)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                        Button(L10n.string("qr.pasteButton")) {
                            let trimmed = pasteUri.trimmingCharacters(in: .whitespacesAndNewlines)
                            guard !trimmed.isEmpty else { return }
                            viewModel.handleQrResult(trimmed)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(pasteUri.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
                .padding()
                .background(.regularMaterial)
            }
            .ignoresSafeArea(edges: .top)
            .navigationTitle(L10n.string("qr.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("common.cancel")) { viewModel.closeActivate() }
                }
            }
        }
        .onDisappear {
            pendingHandoff?.cancel()
            pendingHandoff = nil
        }
    }

    /// Brief flash + checkmark shown over the viewfinder the instant a code
    /// is decoded, so a successful scan has *some* visible confirmation
    /// before the scanner screen closes - previously the screen just closed
    /// with nothing to confirm the scan actually registered.
    private var detectionOverlay: some View {
        ZStack {
            Color.white.opacity(0.18)
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 72))
                .foregroundStyle(.white, SirosTheme.brand)
                .shadow(radius: 8)
        }
        .frame(width: 250, height: 250)
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .transition(.opacity.combined(with: .scale(scale: 0.9)))
        .allowsHitTesting(false)
    }

    /// Fires the instant `CameraQRScanner` decodes a code (camera capture is
    /// already stopped by then - see `QRScannerViewController.hasScanned`).
    /// Shows the checkmark/flash overlay immediately, then delays the actual
    /// handoff to `handleQrResult` (which closes this screen) so the overlay
    /// is visible for at least one frame first. Guarded by `detectedCode` so
    /// a second metadata callback (shouldn't happen given `hasScanned`, but
    /// cheap to guard) can't schedule a duplicate handoff.
    private func handleDetectedCode(_ code: String) {
        guard detectedCode == nil else { return }
        withAnimation(.easeOut(duration: 0.15)) {
            detectedCode = code
        }
        let handoff = DispatchWorkItem { [self] in
            // Don't pre-filter by classification here - handleQrResult
            // already classifies and, deliberately, treats an unclassified
            // URI as a presentation request attempt (covers bare
            // reference-URL QR codes with no recognized scheme/query shape,
            // e.g. some verifiers' "Link" pages). A stricter gate here would
            // silently drop those before handleQrResult's own fallback ever
            // runs.
            viewModel.handleQrResult(code)
        }
        pendingHandoff = handoff
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35, execute: handoff)
    }

    private var simulatorFallback: some View {
        VStack(spacing: 16) {
            Image(systemName: "camera.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text(L10n.string("qr.simulatorUnavailable"))
                .font(.headline)
            Text(L10n.string("qr.simulatorFallbackHint"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.black.opacity(0.8))
    }
}

// MARK: - Camera QR Scanner (UIKit bridge)

#if canImport(UIKit) && canImport(AVFoundation)
import UIKit

struct CameraQRScanner: UIViewControllerRepresentable {
    let onCodeScanned: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let vc = QRScannerViewController()
        vc.onCodeScanned = onCodeScanned
        return vc
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}
}

final class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCodeScanned: ((String) -> Void)?
    private let captureSession = AVCaptureSession()
    private var hasScanned = false

    override func viewDidLoad() {
        super.viewDidLoad()

        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video),
              let videoInput = try? AVCaptureDeviceInput(device: videoCaptureDevice),
              captureSession.canAddInput(videoInput) else {
            return
        }

        captureSession.addInput(videoInput)

        let metadataOutput = AVCaptureMetadataOutput()
        guard captureSession.canAddOutput(metadataOutput) else { return }
        captureSession.addOutput(metadataOutput)
        metadataOutput.setMetadataObjectsDelegate(self, queue: .main)
        metadataOutput.metadataObjectTypes = [.qr]

        let previewLayer = AVCaptureVideoPreviewLayer(session: captureSession)
        previewLayer.frame = view.layer.bounds
        previewLayer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(previewLayer)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.captureSession.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if captureSession.isRunning {
            captureSession.stopRunning()
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !hasScanned,
              let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let stringValue = object.stringValue else {
            return
        }
        hasScanned = true
        captureSession.stopRunning()
        onCodeScanned?(stringValue)
    }
}
#endif
