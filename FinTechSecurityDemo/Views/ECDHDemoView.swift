//
//  ECDHDemoView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Demonstrates ECDH (Elliptic Curve Diffie-Hellman) key agreement.

import SwiftUI
import CryptoKit

struct ECDHDemoView: View {
    @State private var vm = ECDHViewModel()
    @State private var showDetail = false
    private let accent = Color(red: 0.30, green: 0.70, blue: 1.0)   // sky blue

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                    VStack(spacing: 16) {
                        DemoHeader(
                            icon: "🔄",
                            title: "ECDH Key Agreement",
                            subtitle: "Session Key Establishment · P-256",
                            accentColor: accent
                        )

                        VStack(spacing: 14) {

                            InfoCallout(
                                text: "ECDH lets two parties compute the SAME shared secret without ever transmitting it. " +
                                      "Based on the Elliptic Curve Discrete Logarithm Problem — impossible to compute the shared secret " +
                                      "from only the public keys (would require more operations than atoms in the observable universe on P-256).",
                                icon: "lightbulb",
                                accent: accent
                            )

                            StepIndicator(
                                steps: ["Gen Keys", "Exchange", "Derive Key", "Encrypt"],
                                currentStep: vm.currentStep,
                                accent: accent
                            )
                            .padding(.vertical, 4)

                            // ── Step 0 ─────────────────────────────────
                            if vm.currentStep == 0 {
                                SectionCard(title: "Scenario: PIN Change Session", icon: "🔑", accent: accent) {
                                    InfoCallout(
                                        text: "User wants to change their FinTech PIN. " +
                                              "This is high-sensitivity — we establish an E2E encrypted channel " +
                                              "via ECDH before transmitting the new PIN, " +
                                              "so even FinTech's own infrastructure cannot read it in transit.",
                                        icon: "person.badge.shield.checkmark.fill",
                                        accent: accent
                                    )
                                }

                                PrimaryButton(
                                    label: "① Generate Client Key Pair",
                                    icon: "key.fill",
                                    accent: accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.generateClientKeys() } }
                            }

                            // ── Step 1: Client keys ────────────────────
                            if vm.currentStep >= 1 {
                                SectionCard(title: "① Client Ephemeral Key Pair", icon: "📱", accent: accent) {
                                    VStack(spacing: 10) {
                                        InfoCallout(
                                            text: "Ephemeral = generated fresh for this session only. " +
                                                  "The private key is discarded after key agreement — " +
                                                  "this is what gives us Perfect Forward Secrecy.",
                                            icon: "clock.arrow.2.circlepath",
                                            accent: accent
                                        )
                                        FieldRow(
                                            label: "Private Key (ephemeral — NEVER transmitted)",
                                            value: vm.clientPrivKeyPreview,
                                            mono: true,
                                            valueColor: .ftRed
                                        )
                                        CryptoOutputBox(
                                            label: "Public Key (P-256 uncompressed, 64 bytes) — sent to server",
                                            value: vm.clientPubKeyHex,
                                            accent: accent
                                        )
                                    }
                                }

                                FlowArrow(label: "→ Client sends public key to server", accent: accent)

                                PrimaryButton(
                                    label: "② Perform Key Exchange with Server",
                                    icon: "arrow.triangle.2.circlepath",
                                    accent: accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.performKeyExchange() } }
                            }

                            // ── Step 2: Key agreement result ──────────
                            if vm.currentStep >= 2 {

                                // Visual key exchange diagram
                                SectionCard(title: "② Key Agreement — Both Sides", icon: "🤝", accent: accent) {
                                    VStack(spacing: 12) {

                                        // Client side
                                        HStack(spacing: 12) {
                                            ZStack {
                                                RoundedRectangle(cornerRadius: 8)
                                                    .fill(Color.ftSurface2)
                                                    .frame(height: 60)
                                                VStack(spacing: 3) {
                                                    Text("📱 CLIENT")
                                                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                                                        .foregroundStyle(accent)
                                                    Text("clientPrivKey ×")
                                                        .font(.system(size: 9, design: .monospaced))
                                                        .foregroundStyle(Color.ftTextDim)
                                                    Text("serverPubKey")
                                                        .font(.system(size: 9, design: .monospaced))
                                                        .foregroundStyle(Color.ftTextDim)
                                                }
                                            }

                                            Text("=")
                                                .font(.system(size: 20, weight: .bold))
                                                .foregroundStyle(Color.ftAccent)

                                            ZStack {
                                                RoundedRectangle(cornerRadius: 8)
                                                    .fill(Color.ftSurface2)
                                                    .frame(height: 60)
                                                VStack(spacing: 3) {
                                                    Text("🖥️ SERVER")
                                                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                                                        .foregroundStyle(Color.ftAmber)
                                                    Text("serverPrivKey ×")
                                                        .font(.system(size: 9, design: .monospaced))
                                                        .foregroundStyle(Color.ftTextDim)
                                                    Text("clientPubKey")
                                                        .font(.system(size: 9, design: .monospaced))
                                                        .foregroundStyle(Color.ftTextDim)
                                                }
                                            }
                                        }

                                        Text("Both compute: abG (the same point on the curve)")
                                            .font(.system(size: 11, design: .monospaced))
                                            .foregroundStyle(Color.ftTextDim)
                                            .multilineTextAlignment(.center)

                                        Divider().background(Color.ftBorder)

                                        CryptoOutputBox(
                                            label: "Server public key received",
                                            value: vm.serverPubKeyHex,
                                            accent: .ftAmber
                                        )
                                        FieldRow(
                                            label: "Session ID (used as HKDF context — binds key to session)",
                                            value: vm.sessionId,
                                            mono: true,
                                            valueColor: .ftTextDim
                                        )
                                    }
                                }

                                FlowArrow(label: "HKDF-SHA256(sharedSecret, salt, sessionId) → 256-bit AES key", accent: accent)

                                SectionCard(title: "③ Derived Session Keys", icon: "🗝️", accent: .ftGreen) {
                                    VStack(spacing: 12) {
                                        CryptoOutputBox(
                                            label: "Client derived key (256 bits)",
                                            value: vm.clientDerivedKeyHex,
                                            accent: accent
                                        )
                                        CryptoOutputBox(
                                            label: "Server derived key (256 bits) [shown for demo only]",
                                            value: vm.serverDerivedKeyHex,
                                            accent: .ftAmber
                                        )

                                        if vm.keysMatch {
                                            ResultBanner(
                                                success: true,
                                                message: "✓ Keys MATCH. Both sides computed the identical 256-bit AES session key without ever transmitting it."
                                            )
                                        } else {
                                            ResultBanner(
                                                success: false,
                                                message: "✗ Key mismatch — ECDH parameters differ."
                                            )
                                        }

                                        InfoCallout(
                                            text: "Why HKDF instead of using the raw ECDH output? " +
                                                  "The raw shared secret has mathematical structure. HKDF 'randomises' it " +
                                                  "into a uniform bit string suitable for use as an AES key. " +
                                                  "The session ID in sharedInfo ensures this key is unique to this session.",
                                            icon: "info.circle",
                                            accent: accent
                                        )
                                    }
                                }

                                if vm.currentStep == 2 {
                                    SectionCard(title: "Demo: Encrypt PIN Change", icon: "🔐", accent: .ftAccent) {
                                        VStack(spacing: 10) {
                                            HStack(spacing: 10) {
                                                Image(systemName: "lock.rotation")
                                                    .foregroundStyle(Color.ftTextDim)
                                                TextField("PIN payload", text: $vm.pinPayload)
                                                    .font(.system(size: 14, design: .monospaced))
                                                    .foregroundStyle(Color.ftText)
                                                    .tint(.ftAccent)
                                            }
                                            .padding(12)
                                            .background(Color.ftSurface2)
                                            .clipShape(RoundedRectangle(cornerRadius: 10))

                                            PrimaryButton(
                                                label: "④ Encrypt PIN with Session Key",
                                                icon: "lock.fill",
                                                accent: .ftAccent,
                                                isLoading: vm.isProcessing
                                            ) { Task { vm.encryptWithSessionKey() } }
                                        }
                                    }
                                }
                            }

                            // ── Step 3: Encryption result ─────────────
                            if vm.currentStep >= 3 {
                                SectionCard(title: "④ PIN Change Encryption", icon: "🔒", accent: .ftAccent) {
                                    VStack(spacing: 12) {
                                        FieldRow(
                                            label: "Original payload",
                                            value: vm.pinPayload,
                                            mono: true,
                                            valueColor: .ftText
                                        )
                                        CryptoOutputBox(
                                            label: "Encrypted (AES-GCM with ECDH session key) — sent to server",
                                            value: vm.encryptedPIN,
                                            accent: .ftAccent
                                        )
                                        FieldRow(
                                            label: "Server decrypted (using its session key copy)",
                                            value: vm.decryptedPIN,
                                            mono: true,
                                            valueColor: .ftGreen
                                        )
                                        ResultBanner(
                                            success: vm.encryptionSuccess,
                                            message: vm.encryptionSuccess
                                                ? "✓ E2E encrypted PIN change complete. The PIN transited the network as AES-GCM ciphertext, decryptable only by the server holding the ECDH-derived session key."
                                                : "✗ Encryption failed."
                                        )
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
                NavigationLink(destination: TopicDetailView(topic: TopicDetails.ecdh)) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 18))
                        .foregroundStyle(accent)
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
