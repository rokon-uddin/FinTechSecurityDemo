//
//  HMACDemoView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Demonstrates HMAC-SHA256 for API request signing.

import SwiftUI

struct HMACDemoView: View {
    @State private var vm = HMACViewModel()
    @State private var showDetail = false
    private let accent = Color(red: 0.95, green: 0.50, blue: 0.10)   // orange

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                    VStack(spacing: 16) {
                        DemoHeader(
                            icon: "✍️",
                            title: "HMAC-SHA256 Request Signing",
                            subtitle: "API Authenticity & Tamper Detection",
                            accentColor: accent
                        )

                        VStack(spacing: 14) {

                            InfoCallout(
                                text: "HMAC (Hash-based Message Authentication Code) proves a request came from " +
                                      "a party holding the shared secret, and that it was not modified in transit. " +
                                      "Used in FinTech for every API call via the X-FinTech-Signature header.",
                                icon: "lightbulb",
                                accent: accent
                            )

                            StepIndicator(
                                steps: ["Build Request", "Sign (HMAC)", "Server Verify"],
                                currentStep: vm.currentStep,
                                accent: accent
                            )
                            .padding(.vertical, 4)

                            // Input
                            SectionCard(title: "Transfer Details", icon: "💸", accent: accent) {
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
                                }
                            }

                            if vm.currentStep == 0 {
                                PrimaryButton(
                                    label: "Build & Sign Request",
                                    icon: "signature",
                                    accent: accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.buildAndSign() } }
                            }

                            if vm.currentStep >= 1 {

                                // Canonical request
                                SectionCard(title: "① Canonical Request String", icon: "📝", accent: accent) {
                                    VStack(spacing: 10) {
                                        InfoCallout(
                                            text: "The canonical request is a deterministic string covering: " +
                                                  "METHOD + PATH + TIMESTAMP + NONCE + SHA256(body). " +
                                                  "Both client and server must produce identical bytes. " +
                                                  "TIMESTAMP prevents replay attacks older than 5 minutes.",
                                            icon: "info.circle",
                                            accent: .ftAmber
                                        )
                                        CryptoOutputBox(
                                            label: "canonical_request (signed with HMAC)",
                                            value: vm.canonicalRequest,
                                            accent: accent
                                        )
                                    }
                                }

                                FlowArrow(label: "HMAC-SHA256(secret, canonical_request)", accent: accent)

                                // HMAC output
                                SectionCard(title: "② HMAC-SHA256 Signature", icon: "🔏", accent: accent) {
                                    VStack(spacing: 10) {
                                        CryptoOutputBox(
                                            label: "X-FinTech-Signature header value (hex)",
                                            value: vm.hmacSignature,
                                            accent: accent
                                        )
                                        InfoCallout(
                                            text: "This 64-character hex string (256 bits) is sent as an HTTP header. " +
                                                  "Server uses HMAC.isValidAuthenticationCode() for constant-time comparison — " +
                                                  "prevents timing attacks that could leak signature bytes.",
                                            icon: "clock.badge.checkmark",
                                            accent: .ftAccent
                                        )
                                        CryptoOutputBox(
                                            label: "Request body (sent separately in HTTP body)",
                                            value: vm.requestBodyJSON,
                                            accent: .ftTextDim
                                        )
                                    }
                                }

                                // Tamper toggle
                                SectionCard(title: "③ Tamper Simulation", icon: "⚠️", accent: .ftAmber) {
                                    VStack(spacing: 10) {
                                        HStack {
                                            VStack(alignment: .leading, spacing: 3) {
                                                Text("MITM modifies amount to ৳999,999")
                                                    .font(.system(size: 13, weight: .semibold))
                                                    .foregroundStyle(Color.ftText)
                                                Text("Signature still covers original amount")
                                                    .font(.system(size: 11, design: .monospaced))
                                                    .foregroundStyle(Color.ftTextDim)
                                            }
                                            Spacer()
                                            Toggle("", isOn: $vm.tamperAmount)
                                                .tint(.ftRed)
                                        }
                                        if vm.tamperAmount {
                                            ResultBanner(
                                                success: false,
                                                message: "⚠ Tamper ON — body hash will mismatch. Server will reject."
                                            )
                                        }
                                    }
                                }

                                FlowArrow(label: "POST /api/v3/transfer + X-FinTech-Signature header", accent: accent)

                                PrimaryButton(
                                    label: vm.tamperAmount ? "Send Tampered Request →" : "Send Signed Request →",
                                    icon: vm.tamperAmount ? "exclamationmark.triangle.fill" : "paperplane.fill",
                                    accent: vm.tamperAmount ? .ftRed : accent,
                                    isLoading: vm.isProcessing
                                ) { Task { vm.sendToServer() } }
                            }

                            if vm.currentStep >= 2 {
                                SectionCard(
                                    title: "④ Server Verification Result",
                                    icon: "🖥️",
                                    accent: vm.serverSuccess ? .ftGreen : .ftRed
                                ) {
                                    VStack(spacing: 10) {
                                        ResultBanner(success: vm.serverSuccess, message: vm.serverResultMsg)

                                        if vm.serverSuccess {
                                            InfoCallout(
                                                text: "HMAC verified. The request body matches the signature. " +
                                                      "Server is confident this request:\n" +
                                                      "• Came from a holder of the shared HMAC secret\n" +
                                                      "• Was NOT modified after signing\n" +
                                                      "• Is within the 5-minute replay window",
                                                icon: "checkmark.shield",
                                                accent: .ftGreen
                                            )
                                        } else {
                                            InfoCallout(
                                                text: "HMAC verification FAILED.\n" +
                                                      "The body received by the server was different from what was signed. " +
                                                      "Server returns HTTP 403 and logs a security event. " +
                                                      "Even changing a single character in the body produces a completely different HMAC.",
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
                NavigationLink(destination: TopicDetailView(topic: TopicDetails.hmac)) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 18))
                        .foregroundStyle(accent)
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
