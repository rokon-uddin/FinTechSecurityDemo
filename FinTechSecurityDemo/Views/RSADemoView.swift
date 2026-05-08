//
//  RSADemoView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Demonstrates RSA-OAEP for secure key transport (key wrapping).

import SwiftUI

struct RSADemoView: View {
    @State private var vm = RSAViewModel()
    @State private var showDetail = false
    private let accent = Color(red: 0.70, green: 0.45, blue: 1.0)   // purple

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                    VStack(spacing: 16) {
                        DemoHeader(
                            icon: "🔑",
                            title: "RSA-OAEP Key Wrapping",
                            subtitle: "Secure Key Transport · RSA-2048",
                            accentColor: accent
                        )

                        VStack(spacing: 14) {

                            InfoCallout(
                                text: "RSA is used for KEY WRAPPING — encrypting a small symmetric key " +
                                      "(AES-256, 32 bytes) so only the server's private key can decrypt it. " +
                                      "Never use RSA to encrypt large data directly — it's slow and limited to ~190 bytes at 2048-bit. " +
                                      "Pattern: RSA wraps AES key → AES encrypts data.",
                                icon: "lightbulb",
                                accent: accent
                            )

                            // OAEP vs PKCS#1 warning
                            InfoCallout(
                                text: "⚠ Always use RSA-OAEP (not PKCS#1 v1.5). " +
                                      "PKCS#1 v1.5 is vulnerable to Bleichenbacher's padding oracle attack (1998) " +
                                      "which can recover plaintext with adaptive chosen-ciphertext queries. " +
                                      "OAEP uses probabilistic padding — immune to this attack.",
                                icon: "exclamationmark.triangle.fill",
                                accent: .ftRed
                            )

                            StepIndicator(
                                steps: ["Server Key", "Wrap AES", "Unwrap", "Encrypt Data"],
                                currentStep: vm.currentStep,
                                accent: accent
                            )
                            .padding(.vertical, 4)

                            // Step 0
                            if vm.currentStep == 0 {
                                PrimaryButton(
                                    label: "① Inspect Server RSA Public Key",
                                    icon: "magnifyingglass",
                                    accent: accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.inspectServerKey() } }
                            }

                            // Step 1: Server key info
                            if vm.currentStep >= 1 {
                                SectionCard(title: "① Server RSA-2048 Public Key", icon: "🖥️", accent: accent) {
                                    CryptoOutputBox(
                                        label: "Key info (from pinned certificate)",
                                        value: vm.serverPubKeyInfo,
                                        accent: accent
                                    )
                                }

                                PrimaryButton(
                                    label: "② Generate AES Key & RSA-OAEP Wrap",
                                    icon: "key.fill",
                                    accent: accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.generateAndWrapKey() } }
                            }

                            // Step 2: Wrapped key
                            if vm.currentStep >= 2 {
                                SectionCard(title: "② AES-256 Key + RSA-OAEP Wrap", icon: "📦", accent: accent) {
                                    VStack(spacing: 12) {
                                        CryptoOutputBox(
                                            label: "Original AES-256 key (32 bytes — NEVER transmitted raw)",
                                            value: vm.clientAESKeyHex,
                                            accent: .ftAmber
                                        )
                                        FieldRow(
                                            label: "Key purpose",
                                            value: vm.clientAESKeyPurpose,
                                            valueColor: .ftTextDim
                                        )

                                        Divider().background(Color.ftBorder)

                                        CryptoOutputBox(
                                            label: "RSA-OAEP wrapped key (\(vm.wrappedKeySizeBytes) bytes = RSA-2048 block size)",
                                            value: vm.wrappedKeyBase64,
                                            accent: accent
                                        )
                                        InfoCallout(
                                            text: "The wrapped key is \(vm.wrappedKeySizeBytes) bytes — exactly the RSA-2048 key size. " +
                                                  "RSA output is always exactly one block (key size). " +
                                                  "OAEP padding means: same input → different output each time (probabilistic).",
                                            icon: "info.circle",
                                            accent: accent
                                        )
                                    }
                                }

                                FlowArrow(label: "→ Client sends wrapped key to server", accent: accent)

                                PrimaryButton(
                                    label: "③ Server Unwraps with Private Key",
                                    icon: "lock.open.fill",
                                    accent: accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.serverUnwrap() } }
                            }

                            // Step 3: Unwrap result
                            if vm.currentStep >= 3 {
                                SectionCard(
                                    title: "③ Server RSA-OAEP Unwrap",
                                    icon: "🖥️",
                                    accent: vm.serverSuccess ? .ftGreen : .ftRed
                                ) {
                                    VStack(spacing: 12) {
                                        ResultBanner(success: vm.serverSuccess, message: vm.serverMessage)

                                        if vm.serverSuccess {
                                            CryptoOutputBox(
                                                label: "Server recovered AES key",
                                                value: vm.serverRecoveredHex,
                                                accent: .ftGreen
                                            )

                                            HStack {
                                                VStack(alignment: .leading) {
                                                    Text("Keys match?")
                                                        .font(.system(size: 11, design: .monospaced))
                                                        .foregroundStyle(Color.ftTextDim)
                                                    Text(vm.keysMatch ? "✓ IDENTICAL" : "✗ MISMATCH")
                                                        .font(.system(size: 14, weight: .bold, design: .monospaced))
                                                        .foregroundStyle(vm.keysMatch ? Color.ftGreen : Color.ftRed)
                                                }
                                                Spacer()
                                                Image(systemName: vm.keysMatch ? "checkmark.circle.fill" : "xmark.circle.fill")
                                                    .font(.system(size: 28))
                                                    .foregroundStyle(vm.keysMatch ? Color.ftGreen : Color.ftRed)
                                            }
                                        }
                                    }
                                }

                                if vm.serverSuccess && vm.currentStep == 3 {
                                    SectionCard(title: "Demo: Encrypt Card Token Data", icon: "💳", accent: .ftAccent) {
                                        VStack(spacing: 10) {
                                            HStack(spacing: 10) {
                                                Image(systemName: "creditcard.fill")
                                                    .foregroundStyle(Color.ftTextDim)
                                                TextField("Card token data", text: $vm.demoPlaintext)
                                                    .font(.system(size: 11, design: .monospaced))
                                                    .foregroundStyle(Color.ftText)
                                                    .tint(.ftAccent)
                                            }
                                            .padding(12)
                                            .background(Color.ftSurface2)
                                            .clipShape(RoundedRectangle(cornerRadius: 10))

                                            PrimaryButton(
                                                label: "④ Encrypt with Wrapped AES Key",
                                                icon: "lock.fill",
                                                accent: .ftAccent,
                                                isLoading: vm.isProcessing
                                            ) { Task { vm.encryptWithWrappedKey() } }
                                        }
                                    }
                                }
                            }

                            // Step 4: Encryption with the wrapped key
                            if vm.currentStep >= 4 {
                                SectionCard(title: "④ Card Token Encryption Result", icon: "🔒", accent: .ftAccent) {
                                    VStack(spacing: 12) {
                                        FieldRow(label: "Original data", value: vm.demoPlaintext, mono: true)
                                        CryptoOutputBox(
                                            label: "Encrypted (AES-GCM, key transported via RSA)",
                                            value: vm.demoEncrypted,
                                            accent: .ftAccent
                                        )
                                        FieldRow(
                                            label: "Server decrypted",
                                            value: vm.demoDecrypted,
                                            mono: true,
                                            valueColor: .ftGreen
                                        )
                                        InfoCallout(
                                            text: "Complete RSA + AES hybrid encryption flow:\n" +
                                                  "1. Client generates AES-256 key\n" +
                                                  "2. Client RSA-OAEP wraps the AES key with server pubkey\n" +
                                                  "3. Client encrypts card data with AES-GCM\n" +
                                                  "4. Server RSA-OAEP unwraps → gets AES key\n" +
                                                  "5. Server AES-GCM decrypts card data\n" +
                                                  "→ Card number never transmitted in plaintext",
                                            icon: "checkmark.shield.fill",
                                            accent: .ftGreen
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
                NavigationLink(destination: TopicDetailView(topic: TopicDetails.rsa)) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 18))
                        .foregroundStyle(accent)
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
