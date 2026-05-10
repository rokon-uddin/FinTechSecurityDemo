//
//  PaymentFlowStepViews.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/8/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//

import SwiftUI

// MARK: - Security Topic Badge

private struct TopicBadge: View {
    let topics: [String]
    let accent: Color

    var body: some View {
        ScrollView(.horizontal) {
            HStack(spacing: 6) {
                ForEach(topics, id: \.self) { topic in
                    Text(topic)
                        .font(.system(size: 8, weight: .semibold, design: .monospaced))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(accent.opacity(0.12))
                        .clipShape(Capsule())
                }
            }
        }
        .scrollIndicators(.hidden)
    }
}

// MARK: - Step 0: Device Security

struct DeviceSecurityStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 1, title: "Device Security Pre-Flight",
                topics: [
                    "Jailbreak Detection", "Biometric Enrollment",
                    "Environment Check", "App Attest",
                ],
                side: .client, accent: accent
            )

            SectionCard(title: "Security Checks", icon: "🛡️", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Before any sensitive operation: detect jailbreak (Cydia, Substrate, sandbox escape), validate environment (Secure Enclave, debugger), and verify biometric enrollment hasn't changed (LAContext.evaluatedPolicyDomainState).",
                        icon: "shield.lefthalf.filled",
                        accent: accent
                    )

                    if vm.deviceSecurityPassed || !vm.deviceCheckSummary.isEmpty {
                        VStack(spacing: 8) {
                            ForEach(
                                Array(vm.deviceCheckSummary.enumerated()), id: \.offset
                            ) { _, check in
                                HStack {
                                    Text(check.label)
                                        .font(
                                            .system(
                                                size: 11, weight: .medium,
                                                design: .monospaced))
                                        .foregroundStyle(Color.ftTextDim)
                                    Spacer()
                                    Text(check.status)
                                        .font(
                                            .system(
                                                size: 11, weight: .semibold,
                                                design: .monospaced))
                                        .foregroundStyle(
                                            check.status.hasPrefix("✓")
                                                ? Color.ftGreen
                                                : Color.ftAmber)
                                }
                            }
                        }
                        .padding(10)
                        .background(Color.ftSurface2)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }

                    PrimaryButton(
                        label: "Run Security Checks",
                        icon: "shield.checkered",
                        accent: accent,
                        isLoading: vm.isProcessing
                    ) {
                        vm.performDeviceSecurityCheck()
                    }
                }
            }
        }
    }
}

// MARK: - Step 1: Login

struct LoginStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 2, title: "Login & Authentication",
                topics: ["Session Management", "JWT Tokens", "Credential Validation"],
                side: .both, accent: accent
            )

            SectionCard(title: "Authenticate", icon: "🔑", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Client sends credentials → Server validates → Returns JWT access token (15-min, memory) + refresh token (7-day, Keychain). Demo: 01800000001 / 1234",
                        icon: "lightbulb",
                        accent: accent
                    )

                    VStack(alignment: .leading, spacing: 4) {
                        Text("WALLET NUMBER")
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundStyle(Color.ftTextDimmer)
                            .tracking(1)
                        TextField("01XXXXXXXXX", text: $vm.walletInput)
                            .font(.system(size: 14, design: .monospaced))
                            .foregroundStyle(Color.ftText)
                            .keyboardType(.phonePad)
                            .padding(10)
                            .background(Color.ftSurface2)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("PIN")
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundStyle(Color.ftTextDimmer)
                            .tracking(1)
                        SecureField("PIN", text: $vm.pinInput)
                            .font(.system(size: 14, design: .monospaced))
                            .foregroundStyle(Color.ftText)
                            .keyboardType(.numberPad)
                            .padding(10)
                            .background(Color.ftSurface2)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }

                    PrimaryButton(
                        label: "Login",
                        icon: "arrow.right.circle.fill",
                        accent: accent,
                        isLoading: vm.isProcessing
                    ) {
                        Task { await vm.performLogin() }
                    }
                }
            }
        }
    }
}

// MARK: - Step 2: Session Inspection

struct SessionStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 3, title: "Session Token Inspection",
                topics: ["JWT Claims", "Token Storage", "Refresh Rotation"],
                side: .client, accent: accent
            )

            SectionCard(title: "JWT Access Token", icon: "🎫", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Client decodes JWT payload (no signature verification needed on client — server issued it). Access token lives in memory only; refresh token in Keychain with ThisDeviceOnly.",
                        icon: "info.circle",
                        accent: accent
                    )

                    if let claims = vm.sessionClaims {
                        FieldRow(label: "Subject (sub)", value: claims.sub, mono: true)
                        FieldRow(label: "Session ID", value: claims.sessionId, mono: true)
                        FieldRow(label: "Device ID", value: claims.deviceId, mono: true, truncate: true)
                        FieldRow(label: "Roles", value: claims.roles.joined(separator: ", "), mono: true)
                        FieldRow(label: "Issued (iat)", value: "\(claims.iat)", mono: true)
                        FieldRow(label: "Expires (exp)", value: "\(claims.exp)", mono: true)
                    }

                    if !vm.accessTokenPreview.isEmpty {
                        CryptoOutputBox(label: "Access Token (JWT)", value: vm.accessTokenPreview, accent: accent)
                    }

                    PrimaryButton(
                        label: "Continue to Key Exchange",
                        icon: "arrow.right.circle.fill",
                        accent: accent
                    ) {
                        vm.inspectSession()
                    }
                }
            }
        }
    }
}

// MARK: - Step 3: ECDH Key Exchange

struct KeyExchangeStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 4, title: "ECDH Key Exchange",
                topics: ["ECDH P-256", "HKDF", "Perfect Forward Secrecy", "Ephemeral Keys"],
                side: .both, accent: accent
            )

            SectionCard(title: "Establish Encrypted Channel", icon: "🤝", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Both sides generate ephemeral P-256 key pairs, exchange public keys, and compute the same shared secret via ECDH. HKDF derives TWO 256-bit keys with domain separation: one for AES-GCM encryption, one for HMAC signing. Ephemeral keys = Perfect Forward Secrecy.",
                        icon: "lock.rotation",
                        accent: accent
                    )

                    PrimaryButton(
                        label: "Perform Key Exchange",
                        icon: "arrow.triangle.2.circlepath",
                        accent: accent
                    ) {
                        vm.performKeyExchange()
                    }
                }
            }
        }
    }
}

// MARK: - Step 4: Payment Input

struct PaymentInputStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 5, title: "Build Payment Transaction",
                topics: ["Nonce (Anti-Replay)", "Integer Money", "Canonical Bytes"],
                side: .both, accent: accent
            )

            SectionCard(title: "Payment Details", icon: "💸", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Server issues a single-use nonce (prevents replay). Amount stored as integer paisa (no floating-point errors). Canonical byte format ensures client and server produce identical signing input.",
                        icon: "info.circle",
                        accent: accent
                    )

                    VStack(alignment: .leading, spacing: 4) {
                        Text("RECEIVER WALLET")
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundStyle(Color.ftTextDimmer)
                            .tracking(1)
                        TextField("01XXXXXXXXX", text: $vm.receiverWallet)
                            .font(.system(size: 14, design: .monospaced))
                            .foregroundStyle(Color.ftText)
                            .keyboardType(.phonePad)
                            .padding(10)
                            .background(Color.ftSurface2)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }

                    AmountField(text: $vm.amountText)

                    VStack(alignment: .leading, spacing: 4) {
                        Text("NOTE")
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundStyle(Color.ftTextDimmer)
                            .tracking(1)
                        TextField("Payment note", text: $vm.paymentNote)
                            .font(.system(size: 14))
                            .foregroundStyle(Color.ftText)
                            .padding(10)
                            .background(Color.ftSurface2)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }

                    PrimaryButton(
                        label: "Build Transaction",
                        icon: "doc.text.fill",
                        accent: accent
                    ) {
                        vm.buildPayment()
                    }
                }
            }
        }
    }
}

// MARK: - Step 5: Card Tokenization

struct TokenizationStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 6, title: "PCI-DSS Card Tokenization",
                topics: ["PCI-DSS", "Tokenization", "Secure Card Input", "Keychain"],
                side: .both, accent: accent
            )

            SectionCard(title: "Tokenize Card", icon: "💳", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Raw card data enters a gateway-managed secure UI (not your app code). Gateway returns a useless token. PCI scope drops from SAQ D (300+ requirements) to SAQ A (~20). Your app never sees the real PAN.",
                        icon: "creditcard.and.123",
                        accent: .ftAmber
                    )

                    VStack(alignment: .leading, spacing: 4) {
                        Text("CARD NUMBER (GATEWAY UI)")
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundStyle(Color.ftTextDimmer)
                            .tracking(1)
                        TextField("4242 4242 4242 4242", text: $vm.cardNumber)
                            .font(.system(size: 14, design: .monospaced))
                            .foregroundStyle(Color.ftText)
                            .keyboardType(.numberPad)
                            .padding(10)
                            .background(Color.ftSurface2)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }

                    FieldRow(label: "CVV", value: "••• (handled by gateway SDK)", mono: true)
                    FieldRow(label: "Expiry", value: "12/2027", mono: true)

                    PrimaryButton(
                        label: "Tokenize Card",
                        icon: "creditcard.fill",
                        accent: accent,
                        isLoading: vm.isProcessing
                    ) {
                        Task { await vm.tokenizeCard() }
                    }
                }
            }
        }
    }
}

// MARK: - Step 6: Transaction Signing

struct SigningStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 7, title: "Secure Enclave Signing",
                topics: ["ECDSA P-256", "Secure Enclave", "Biometric Auth", "Non-Repudiation"],
                side: .client, accent: accent
            )

            SectionCard(title: "Sign Transaction", icon: "✍️", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Transaction's canonical bytes are sent INTO the Secure Enclave. Signing happens in hardware — the private key NEVER exits the chip. Face ID / Touch ID required. The signature is cryptographic proof the user authorized this exact transaction.",
                        icon: "cpu",
                        accent: accent
                    )

                    if let tx = vm.builtTransaction {
                        FieldRow(label: "Transaction ID", value: tx.id.uuidString, mono: true)
                        FieldRow(label: "Amount", value: tx.amount.description, mono: true)
                        FieldRow(label: "Receiver", value: tx.receiverWallet.rawValue, mono: true)
                        FieldRow(label: "Canonical Bytes", value: "\(tx.canonicalBytes.count) bytes", mono: true)
                    }

                    if !SecureEnclave.isAvailable {
                        InfoCallout(
                            text: "Simulator: using software P-256 key (no Secure Enclave hardware). Same API, no hardware guarantee.",
                            icon: "exclamationmark.triangle",
                            accent: .ftAmber
                        )
                    }

                    PrimaryButton(
                        label: "Sign with Biometric",
                        icon: "faceid",
                        accent: accent,
                        isLoading: vm.isProcessing
                    ) {
                        Task { await vm.signTransaction() }
                    }
                }
            }
        }
    }
}

// MARK: - Step 7: Encryption + HMAC

struct EncryptionStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 8, title: "AES-GCM Encryption + HMAC",
                topics: ["AES-256-GCM", "HMAC-SHA256", "AEAD", "Request Integrity"],
                side: .client, accent: accent
            )

            SectionCard(title: "Encrypt & Sign Request", icon: "🔐", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Transaction payload encrypted with AES-256-GCM using the ECDH-derived session key. GCM's auth tag detects any tampering. Then HMAC-SHA256 signs the entire request body for request-level integrity. Two layers: AES-GCM (payload) + HMAC (request).",
                        icon: "lock.shield",
                        accent: accent
                    )

                    FieldRow(label: "Encryption Key", value: "ECDH session key (step 2)", mono: true)
                    FieldRow(label: "Algorithm", value: "AES-256-GCM (AEAD)", mono: true)
                    FieldRow(label: "HMAC Key", value: "ECDH-derived (HKDF, \"fintech-hmac-v1\")", mono: true)

                    PrimaryButton(
                        label: "Encrypt + HMAC Sign",
                        icon: "lock.fill",
                        accent: accent
                    ) {
                        vm.encryptAndSubmit()
                    }
                }
            }
        }
    }
}

// MARK: - Step 8: TLS Transmit

struct TLSTransmitStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 9, title: "TLS 1.3 Secure Transmission",
                topics: ["TLS 1.3", "Certificate Pinning", "Ephemeral Session", "ECDHE"],
                side: .both, accent: accent
            )

            SectionCard(title: "Transmit Encrypted Payload", icon: "🌐", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "HTTPS over TLS 1.3 with ECDHE key exchange. Certificate pinning validates the server's SPKI hash against a known value — prevents MITM even with compromised CAs. URLSessionConfiguration.ephemeral ensures zero disk cache.",
                        icon: "lock.shield",
                        accent: accent
                    )

                    FieldRow(
                        label: "TLS Version", value: "1.3 (RFC 8446)", mono: true)
                    FieldRow(
                        label: "Cipher Suite",
                        value: "TLS_AES_256_GCM_SHA384", mono: true)
                    FieldRow(
                        label: "Session Config",
                        value: "URLSessionConfiguration.ephemeral",
                        mono: true)
                    FieldRow(
                        label: "Cert Pinning", value: "SPKI SHA-256",
                        mono: true)

                    if let envelope = vm.encryptedEnvelope {
                        FieldRow(
                            label: "Payload",
                            value: "\(envelope.ciphertext.count) bytes (encrypted)",
                            mono: true)
                    }

                    PrimaryButton(
                        label: "Transmit via TLS 1.3",
                        icon: "arrow.up.circle.fill",
                        accent: accent
                    ) {
                        vm.simulateTLSTransmit()
                    }
                }
            }
        }
    }
}

// MARK: - Step 9: Server Verification

struct VerificationStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 10, title: "Server Verification Pipeline",
                topics: [
                    "HMAC Verify", "Nonce Check", "Timestamp",
                    "ECDSA Verify", "AES-GCM Decrypt",
                ],
                side: .server, accent: accent
            )

            SectionCard(title: "5-Check Verification", icon: "🏦", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Server runs 5 checks: (1) HMAC verifies request integrity, (2) Nonce confirms first-use (anti-replay), (3) Timestamp within 5-min window, (4) ECDSA P-256 signature proves authorization, (5) AES-GCM decrypts + verifies payload.",
                        icon: "checkmark.shield",
                        accent: accent
                    )

                    if !vm.hmacSignatureHex.isEmpty {
                        FieldRow(
                            label: "HMAC to verify",
                            value: String(vm.hmacSignatureHex.prefix(32)) + "...",
                            mono: true)
                    }
                    if !vm.signatureHex.isEmpty {
                        FieldRow(
                            label: "ECDSA signature",
                            value: String(vm.signatureHex.prefix(32)) + "...",
                            mono: true)
                    }
                    if let tx = vm.builtTransaction {
                        FieldRow(
                            label: "Timestamp",
                            value: String(tx.timestampUnix),
                            mono: true)
                    }

                    PrimaryButton(
                        label: "Run Server Verification",
                        icon: "server.rack",
                        accent: Color(red: 0.70, green: 0.50, blue: 0.95)
                    ) {
                        vm.verifyOnServer()
                    }
                }
            }
        }
    }
}

// MARK: - Step 10: Response & Cleanup

struct ResponseCleanupStepView: View {
    @Bindable var vm: PaymentFlowViewModel
    let accent: Color

    var body: some View {
        VStack(spacing: 12) {
            stepHeader(
                step: 11, title: "Response & Secure Cleanup",
                topics: [
                    "Encrypted Response", "PCI Audit Trail",
                    "Secure Memory Wipe", "Data Lifecycle",
                ],
                side: .both, accent: accent
            )

            SectionCard(
                title: "Finalize & Wipe", icon: "🧹", accent: accent
            ) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "Server response is AES-GCM encrypted (same session key). After decryption: PCI Req 10 audit event logged (no CHD), then ALL sensitive data wiped from memory — plaintext, session keys, ECDH private key, HMAC buffers. memset_s() guarantees zeroing.",
                        icon: "trash.slash",
                        accent: accent
                    )

                    if let result = vm.verificationResult {
                        FieldRow(
                            label: "Server Result",
                            value: result.overallSuccess ? "✓ APPROVED" : "✗ REJECTED",
                            mono: true,
                            valueColor: result.overallSuccess
                                ? .ftGreen : .ftRed)
                    }

                    PrimaryButton(
                        label: "Decrypt Response & Wipe Memory",
                        icon: "checkmark.circle.fill",
                        accent: accent
                    ) {
                        vm.handleResponseAndCleanup()
                    }
                }
            }
        }
    }
}

// MARK: - Step Header Helper

private func stepHeader(
    step: Int,
    title: String,
    topics: [String],
    side: StepLogEntry.ExecutionSide,
    accent: Color
) -> some View {
    VStack(alignment: .leading, spacing: 6) {
        HStack {
            Text("STEP \(step) OF 11")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundStyle(accent)
                .tracking(2)
            Spacer()
            SideBadge(side: side)
        }

        Text(title)
            .font(.system(size: 16, weight: .bold, design: .rounded))
            .foregroundStyle(Color.ftText)

        TopicBadge(topics: topics, accent: accent)
    }
}

// MARK: - CryptoKit import for SecureEnclave check

import CryptoKit
