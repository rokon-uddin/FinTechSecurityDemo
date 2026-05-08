//
//  AESGCMDemoView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Demonstrates AES-256-GCM encryption of a payment transaction payload.

import SwiftUI

struct AESGCMDemoView: View {
    @State private var vm = AESGCMViewModel()
    @State private var showDetail = false

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {

                        DemoHeader(
                            icon: "🔐",
                            title: "AES-256-GCM Encryption",
                            subtitle: "Payment Payload Encryption",
                            accentColor: .ftAccent
                        )

                        VStack(spacing: 14) {

                            // ── Explanation ──────────────────────────────
                            InfoCallout(
                                text: "AES-GCM provides Authenticated Encryption with Associated Data (AEAD). " +
                                      "Confidentiality + integrity in a single operation. " +
                                      "The 16-byte authentication tag detects any tampering — even a single flipped bit.",
                                icon: "lightbulb",
                                accent: .ftAccent
                            )

                            // ── Step progress ────────────────────────────
                            StepIndicator(
                                steps: ["Build Payload", "Encrypt", "Server Decrypt"],
                                currentStep: vm.currentStep,
                                accent: .ftAccent
                            )
                            .padding(.vertical, 4)

                            // ── Input form ───────────────────────────────
                            SectionCard(title: "Transaction Input", icon: "📤", accent: .ftAccent) {
                                VStack(spacing: 12) {
                                    AmountField(text: $vm.amountBDT)

                                    HStack(spacing: 10) {
                                        Image(systemName: "phone.fill")
                                            .foregroundStyle(Color.ftTextDim)
                                            .frame(width: 20)
                                        TextField("Receiver wallet", text: $vm.receiverWallet)
                                            .font(.system(size: 14, design: .monospaced))
                                            .foregroundStyle(Color.ftText)
                                            .tint(.ftAccent)
                                    }
                                    .padding(12)
                                    .background(Color.ftSurface2)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))

                                    HStack(spacing: 10) {
                                        Image(systemName: "note.text")
                                            .foregroundStyle(Color.ftTextDim)
                                            .frame(width: 20)
                                        TextField("Note", text: $vm.note)
                                            .font(.system(size: 14))
                                            .foregroundStyle(Color.ftText)
                                            .tint(.ftAccent)
                                    }
                                    .padding(12)
                                    .background(Color.ftSurface2)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))
                                }
                            }

                            // ── Encrypt button ────────────────────────────
                            if vm.currentStep == 0 {
                                PrimaryButton(
                                    label: "Encrypt Transaction",
                                    icon: "lock.fill",
                                    accent: .ftAccent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.encrypt() } }
                            }

                            // ── Step 1: Plaintext + Ciphertext ────────────
                            if vm.currentStep >= 1 {
                                // Original plaintext
                                SectionCard(title: "① Plaintext Payload (before encrypt)", icon: "📄", accent: .ftTextDim) {
                                    CryptoOutputBox(
                                        label: "JSON payload (what gets encrypted)",
                                        value: vm.plaintextJSON,
                                        accent: .ftTextDim
                                    )
                                }

                                FlowArrow(label: "AES-256-GCM seal()", accent: .ftAccent)

                                // Encrypted envelope
                                SectionCard(title: "② Encrypted Envelope", icon: "📦", accent: .ftAccent) {
                                    VStack(spacing: 12) {
                                        InfoCallout(
                                            text: "The nonce is random and unique per encryption. " +
                                                  "Ciphertext is same length as plaintext (stream cipher mode). " +
                                                  "Tag authenticates both the nonce and ciphertext.",
                                            icon: "info.circle",
                                            accent: .ftAmber
                                        )

                                        CryptoOutputBox(
                                            label: "Nonce (12 bytes — random, never reuse)",
                                            value: vm.nonce,
                                            accent: .ftAccent
                                        )
                                        CryptoOutputBox(
                                            label: "Ciphertext (same length as plaintext)",
                                            value: vm.ciphertext,
                                            accent: .ftAccent
                                        )
                                        CryptoOutputBox(
                                            label: "Auth Tag (16 bytes — detects tampering)",
                                            value: vm.authTag,
                                            accent: .ftAmber
                                        )
                                        CryptoOutputBox(
                                            label: "Key Info (preview only — never log full key)",
                                            value: vm.keyPreview,
                                            accent: .ftTextDim
                                        )
                                    }
                                }

                                // Tamper toggle
                                SectionCard(title: "③ Tamper Simulation", icon: "⚠️", accent: .ftAmber) {
                                    VStack(spacing: 10) {
                                        HStack {
                                            VStack(alignment: .leading, spacing: 3) {
                                                Text("Simulate MITM tampering")
                                                    .font(.system(size: 13, weight: .semibold))
                                                    .foregroundStyle(Color.ftText)
                                                Text("XOR first byte of ciphertext → tag mismatch")
                                                    .font(.system(size: 11, design: .monospaced))
                                                    .foregroundStyle(Color.ftTextDim)
                                            }
                                            Spacer()
                                            Toggle("", isOn: $vm.tamperMode)
                                                .tint(.ftRed)
                                        }
                                        if vm.tamperMode {
                                            ResultBanner(
                                                success: false,
                                                message: "⚠ Tamper mode ON — server will reject this envelope. The auth tag won't match the modified ciphertext."
                                            )
                                        }
                                    }
                                }

                                FlowArrow(label: "POST /api/transaction", accent: .ftAccent)

                                PrimaryButton(
                                    label: vm.tamperMode ? "Send Tampered Envelope →" : "Send to Mock Server →",
                                    icon: vm.tamperMode ? "exclamationmark.triangle.fill" : "paperplane.fill",
                                    accent: vm.tamperMode ? .ftRed : .ftAccent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.sendToServer() } }
                            }

                            // ── Step 2: Server result ─────────────────────
                            if vm.currentStep >= 2 {
                                SectionCard(title: "④ Server Decrypt Result", icon: "🖥️", accent: vm.serverSuccess ? .ftGreen : .ftRed) {
                                    VStack(spacing: 10) {
                                        ResultBanner(success: vm.serverSuccess, message: vm.serverResult)

                                        if vm.serverSuccess {
                                            InfoCallout(
                                                text: "Server successfully decrypted and authenticated the payload. " +
                                                      "The 16-byte GCM tag verified that: (a) the ciphertext was not modified, " +
                                                      "(b) the nonce was not changed, (c) the payload came from a holder of the shared key.",
                                                icon: "checkmark.shield",
                                                accent: .ftGreen
                                            )
                                        } else {
                                            InfoCallout(
                                                text: "GCM authentication failure. AES.GCM.open() threw CryptoKitError.authenticationFailure. " +
                                                      "Even a single flipped bit anywhere in the ciphertext or tag makes the authentication tag fail.",
                                                icon: "shield.slash",
                                                accent: .ftRed
                                            )
                                        }
                                    }
                                }

                                PrimaryButton(
                                    label: "Reset Demo",
                                    icon: "arrow.counterclockwise",
                                    accent: .ftTextDim
                                ) { vm.reset() }
                            }

                        }
                        .padding(.horizontal, 16)
                        .padding(.bottom, 32)
                    }
                }
            }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink(destination: TopicDetailView(topic: TopicDetails.aesGCM)) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 18))
                        .foregroundStyle(Color.ftAccent)
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
