//
//  SecureEnclaveDemoView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Demonstrates the Secure Enclave for hardware-backed transaction signing.

import SwiftUI
import CryptoKit
import Security
import LocalAuthentication

// MARK: - Secure Enclave Key Manager

final class SEKeyManager {

    static let keyTag = "com.fintech.demo.transaction-signing-key"
        .data(using: .utf8)!

    enum KeySource { case secureEnclave, softwareFallback }

    struct ManagedKey {
        let source: KeySource
        let publicKeyRaw: Data
        fileprivate let _signingFunction: (Data) throws -> Data
    }

    private static var cachedKey: ManagedKey?

    static func loadOrCreate() throws -> ManagedKey {
        if let cached = cachedKey { return cached }

        if SecureEnclave.isAvailable {
            return try createSecureEnclaveKey()
        } else {
            return createSoftwareKey()
        }
    }

    private static func createSecureEnclaveKey() throws -> ManagedKey {
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        )!

        let privKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let managed = ManagedKey(
            source:       .secureEnclave,
            publicKeyRaw: privKey.publicKey.rawRepresentation,
            _signingFunction: { data in
                let sig = try privKey.signature(for: data)
                return sig.derRepresentation
            }
        )
        cachedKey = managed
        return managed
    }

    private static func createSoftwareKey() -> ManagedKey {
        let privKey = P256.Signing.PrivateKey()
        let managed = ManagedKey(
            source:       .softwareFallback,
            publicKeyRaw: privKey.publicKey.rawRepresentation,
            _signingFunction: { data in
                let sig = try privKey.signature(for: data)
                return sig.derRepresentation
            }
        )
        cachedKey = managed
        return managed
    }

    static func sign(data: Data, using key: ManagedKey) throws -> Data {
        try key._signingFunction(data)
    }

    static func deleteKey() {
        cachedKey = nil
        let query: [CFString: Any] = [
            kSecClass:              kSecClassKey,
            kSecAttrApplicationTag: keyTag
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - View

struct SecureEnclaveDemoView: View {
    @State private var vm = SecureEnclaveViewModel()
    @State private var showDetail = false
    private let accent = Color(red: 0.10, green: 0.80, blue: 0.55)  // green

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {
                    DemoHeader(
                        icon: "🏰",
                        title: "Secure Enclave",
                            subtitle: "Hardware Transaction Signing · P-256 ECDSA",
                            accentColor: accent
                        )

                        VStack(spacing: 14) {

                            // Simulator warning
                            if !SecureEnclave.isAvailable {
                                InfoCallout(
                                    text: "Running on Simulator — Secure Enclave unavailable. " +
                                          "Demo uses software P-256 key. On a real iPhone/iPad, " +
                                          "this generates a hardware-bound key and triggers Face ID on every signing operation.",
                                    icon: "exclamationmark.triangle.fill",
                                    accent: .ftAmber
                                )
                            }

                            InfoCallout(
                                text: "The Secure Enclave is a dedicated security coprocessor with its own " +
                                      "encrypted memory and boot ROM. Private keys generated inside NEVER leave the hardware — " +
                                      "not even the main CPU can read them. Signing happens inside the enclave; " +
                                      "only the signature exits.",
                                icon: "cpu",
                                accent: accent
                            )

                            StepIndicator(
                                steps: ["Gen Key", "Build Tx", "Sign (SE)", "Verify"],
                                currentStep: vm.currentStep,
                                accent: accent
                            )
                            .padding(.vertical, 4)

                            // Step 0
                            if vm.currentStep == 0 {
                                SectionCard(title: "Secure Enclave Key", icon: "🔑", accent: accent) {
                                    InfoCallout(
                                        text: "The key pair is generated ONCE during device registration. " +
                                              "The public key is uploaded to FinTech servers. " +
                                              "The private key never leaves the Secure Enclave chip.",
                                        icon: "person.crop.circle.badge.plus",
                                        accent: accent
                                    )
                                }

                                PrimaryButton(
                                    label: "① Generate / Load SE Key Pair",
                                    icon: "cpu",
                                    accent: accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.loadKey() } }
                            }

                            // Step 1: Key info
                            if vm.currentStep >= 1 {
                                SectionCard(title: "① Key Pair — Properties", icon: "🗝️", accent: accent) {
                                    VStack(spacing: 12) {
                                        ResultBanner(
                                            success: !vm.keySource.contains("⚠"),
                                            message: vm.keySource
                                        )
                                        CryptoOutputBox(
                                            label: "Public Key (64 bytes — stored on FinTech server)",
                                            value: vm.publicKeyHex,
                                            accent: accent
                                        )
                                        CryptoOutputBox(
                                            label: "Key Properties",
                                            value: vm.keyProperties,
                                            accent: .ftTextDim
                                        )
                                        InfoCallout(
                                            text: "The data representation of an SE key is an OPAQUE HANDLE — " +
                                                  "not the raw key material. Storing it in Keychain allows you to " +
                                                  "'reconnect' to the SE key across app launches without regenerating.",
                                            icon: "info.circle",
                                            accent: accent
                                        )
                                    }
                                }

                                SectionCard(title: "② Transaction Details", icon: "💸", accent: accent) {
                                    VStack(spacing: 12) {
                                        AmountField(text: $vm.amountBDT)

                                        HStack(spacing: 10) {
                                            Image(systemName: "phone.fill")
                                                .foregroundStyle(Color.ftTextDim)
                                                .frame(width: 20)
                                            TextField("Receiver wallet", text: $vm.receiverWallet)
                                                .font(.system(size: 14, design: .monospaced))
                                                .foregroundStyle(Color.ftText)
                                                .tint(accent)
                                        }
                                        .padding(12)
                                        .background(Color.ftSurface2)
                                        .clipShape(RoundedRectangle(cornerRadius: 10))

                                        PrimaryButton(
                                            label: "② Build Transaction Payload",
                                            icon: "doc.text.fill",
                                            accent: accent,
                                            isLoading: vm.isProcessing
                                        ) { vm.buildTransaction() }
                                    }
                                }
                            }

                            // Step 2: Canonical bytes
                            if vm.currentStep >= 2 {
                                SectionCard(title: "② Canonical Transaction", icon: "📄", accent: accent) {
                                    VStack(spacing: 12) {
                                        CryptoOutputBox(
                                            label: "Canonical bytes (what gets signed)",
                                            value: vm.canonicalBytes,
                                            accent: accent
                                        )
                                        CryptoOutputBox(
                                            label: "Hex representation of canonical bytes",
                                            value: vm.canonicalHex,
                                            accent: .ftTextDim
                                        )
                                        InfoCallout(
                                            text: "The canonical representation is pipe-separated with all fields in fixed order. " +
                                                  "Amount is integer paisa (never floating point). " +
                                                  "Server must reconstruct the EXACT same bytes for verification.",
                                            icon: "info.circle",
                                            accent: accent
                                        )
                                    }
                                }

                                FlowArrow(
                                    label: SecureEnclave.isAvailable
                                        ? "→ Face ID unlocks SE key → Signs inside hardware"
                                        : "→ Software P-256 signing (Simulator)",
                                    accent: accent
                                )

                                PrimaryButton(
                                    label: SecureEnclave.isAvailable
                                        ? "③ Sign Transaction (Face ID Required)"
                                        : "③ Sign Transaction (Software Key)",
                                    icon: SecureEnclave.isAvailable ? "faceid" : "signature",
                                    accent: accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.signTransaction() } }
                            }

                            // Step 3: Signature
                            if vm.currentStep >= 3 {
                                SectionCard(title: "③ ECDSA P-256 Signature", icon: "✍️", accent: accent) {
                                    VStack(spacing: 12) {
                                        ResultBanner(success: vm.signingSuccess, message: vm.signingMessage)

                                        if vm.signingSuccess {
                                            CryptoOutputBox(
                                                label: "DER-encoded ECDSA signature (sent in request header)",
                                                value: vm.signatureHex,
                                                accent: accent
                                            )
                                            InfoCallout(
                                                text: "ECDSA P-256 produces a (r, s) pair — each 32 bytes. " +
                                                      "DER-encoded, the signature is ~70-72 bytes. " +
                                                      "This signature, combined with the SE's hardware guarantee that biometrics " +
                                                      "were required, is cryptographic proof of user intent.",
                                                icon: "checkmark.seal",
                                                accent: accent
                                            )
                                        }
                                    }
                                }

                                // Tamper
                                SectionCard(title: "④ Tamper Simulation", icon: "⚠️", accent: .ftAmber) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text("Attacker modifies transaction amount")
                                                .font(.system(size: 13, weight: .semibold))
                                                .foregroundStyle(Color.ftText)
                                            Text("Signature covers original bytes — mismatch")
                                                .font(.system(size: 11, design: .monospaced))
                                                .foregroundStyle(Color.ftTextDim)
                                        }
                                        Spacer()
                                        Toggle("", isOn: $vm.tamperMode)
                                            .tint(.ftRed)
                                    }
                                }

                                FlowArrow(label: "→ Server verifies ECDSA signature", accent: accent)

                                PrimaryButton(
                                    label: vm.tamperMode ? "Verify Tampered Tx →" : "④ Server Verify Signature →",
                                    icon: vm.tamperMode ? "exclamationmark.triangle.fill" : "checkmark.shield.fill",
                                    accent: vm.tamperMode ? .ftRed : accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.verifySignature() } }
                            }

                            // Step 4: Verification result
                            if vm.currentStep >= 4 {
                                SectionCard(
                                    title: "④ Server Verification",
                                    icon: "🖥️",
                                    accent: vm.verifySuccess ? .ftGreen : .ftRed
                                ) {
                                    VStack(spacing: 12) {
                                        ResultBanner(success: vm.verifySuccess, message: vm.verifyMessage)

                                        if vm.verifySuccess {
                                            InfoCallout(
                                                text: "Transaction is cryptographically authenticated:\n" +
                                                      "• Signature produced by Secure Enclave on user's specific device\n" +
                                                      "• Face ID confirmed user's biometric presence\n" +
                                                      "• Canonical bytes cover all transaction fields\n" +
                                                      "• User CANNOT repudiate this transaction\n" +
                                                      "→ Server proceeds to process payment",
                                                icon: "checkmark.shield.fill",
                                                accent: .ftGreen
                                            )
                                        } else {
                                            InfoCallout(
                                                text: "Signature verification FAILED.\n" +
                                                      "Either the transaction was tampered after signing, " +
                                                      "or the signature does not belong to the registered device key.\n" +
                                                      "Server returns HTTP 422 and raises a fraud alert.",
                                                icon: "shield.slash.fill",
                                                accent: .ftRed
                                            )
                                        }
                                    }
                                }

                                HStack(spacing: 10) {
                                    PrimaryButton(
                                        label: "Reset",
                                        icon: "arrow.counterclockwise",
                                        accent: .ftTextDim
                                    ) { vm.reset() }

                                    PrimaryButton(
                                        label: "Delete Key",
                                        icon: "trash",
                                        accent: .ftRed
                                    ) { vm.deleteAndReset() }
                                }
                            }

                        }
                        .padding(.horizontal, 16)
                        .padding(.bottom, 32)
                    }
                }
            }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink(destination: TopicDetailView(topic: TopicDetails.secureEnclave)) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 18))
                        .foregroundStyle(accent)
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
