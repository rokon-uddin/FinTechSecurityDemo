//
//  PaymentFeatureViews.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// OTP (SMS-style) + TOTP (RFC 6238) + HOTP explanation demo.

import SwiftUI
import CryptoKit

public struct OTPDemoView: View {

    @State private var vm: OTPViewModel
    @State private var selectedTab = 0
    @State private var showDetail = false

    public init(vm: OTPViewModel) { self._vm = State(initialValue: vm) }

    private let accent = Color(red: 0.30, green: 0.80, blue: 1.0)

    public var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {

                    DemoHeader(
                        icon: "📱",
                        title: "OTP · TOTP · HOTP",
                        subtitle: "RFC 4226 + RFC 6238 · From First Principles",
                        accentColor: accent
                    )

                        VStack(spacing: 14) {

                            // ── Tab selector ─────────────────────────────
                            HStack(spacing: 0) {
                                tabButton(title: "OTP (SMS)", idx: 0)
                                tabButton(title: "TOTP (Auth App)", idx: 1)
                                tabButton(title: "Algorithms", idx: 2)
                            }
                            .background(Color.ftSurface2)
                            .clipShape(RoundedRectangle(cornerRadius: 8))

                            // ── Wallet input (shared) ─────────────────────
                            HStack(spacing: 10) {
                                Image(systemName: "phone.fill")
                                    .foregroundStyle(Color.ftTextDim)
                                    .frame(width: 20)
                                TextField("Wallet number", text: $vm.walletInput)
                                    .font(.system(size: 14, design: .monospaced))
                                    .foregroundStyle(Color.ftText)
                                    .tint(accent)
                            }
                            .padding(12)
                            .background(Color.ftSurface2)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.ftBorder, lineWidth: 1))

                            switch selectedTab {
                            case 0: otpSection
                            case 1: totpSection
                            default: algorithmSection
                            }
                        }
                        .padding(.horizontal, 16)
                        .padding(.bottom, 32)
                    }
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink(destination: TopicDetailView(topic: TopicDetails.otpTotp)) {
                        Image(systemName: "info.circle")
                            .font(.system(size: 18))
                            .foregroundStyle(accent)
                    }
                }
            }
            .onDisappear { vm.stopTimer() }
            .preferredColorScheme(.dark)
    }

    // MARK: - OTP Section (SMS-style)

    @ViewBuilder
    private var otpSection: some View {
        InfoCallout(
            text: "SMS OTP: server generates a random 6-digit code, sends via SMS. " +
                  "Valid for 5 minutes, single-use, 3-attempt limit before lockout. " +
                  "Weakness: SIM swapping, SS7 interception. Prefer TOTP for in-app flows.",
            icon: "lightbulb",
            accent: accent
        )

        // Generate
        PrimaryButton(
            label: "Generate OTP (Mock SMS Send)",
            icon: "message.fill",
            accent: accent,
            isLoading: vm.isLoadingOTP
        ) { Task { await vm.generateOTP() } }

        if let otp = vm.generatedOTP {
            SectionCard(title: "Generated OTP (shown for demo only)", icon: "🔢", accent: accent) {
                VStack(spacing: 12) {
                    InfoCallout(
                        text: "In production: this code is sent via SMS only — never shown in the app. " +
                              "It's displayed here so you can enter it below for validation.",
                        icon: "exclamationmark.triangle",
                        accent: .ftAmber
                    )

                    // Large code display
                    HStack(spacing: 8) {
                        ForEach(Array(otp.code.enumerated()), id: \.offset) { _, char in
                            Text(String(char))
                                .font(.system(size: 28, weight: .bold, design: .monospaced))
                                .foregroundStyle(accent)
                                .frame(width: 40, height: 48)
                                .background(Color.ftSurface2)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                        }
                    }
                    .frame(maxWidth: .infinity)

                    HStack {
                        Label("Single-use", systemImage: "1.circle")
                        Spacer()
                        Label(
                            "Expires in \(otp.secondsRemaining)s",
                            systemImage: "clock"
                        )
                        Spacer()
                        Label("Max 3 attempts", systemImage: "xmark.circle")
                    }
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color.ftTextDim)
                }
            }

            SectionCard(title: "Validate OTP", icon: "✅", accent: .ftGreen) {
                VStack(spacing: 12) {
                    TextField("Enter OTP code", text: $vm.otpCodeInput)
                        .font(.system(size: 24, weight: .bold, design: .monospaced))
                        .multilineTextAlignment(.center)
                        .foregroundStyle(Color.ftText)
                        .tint(accent)
                        .keyboardType(.numberPad)
                        .padding(14)
                        .background(Color.ftSurface2)
                        .clipShape(RoundedRectangle(cornerRadius: 10))

                    PrimaryButton(
                        label: "Validate",
                        icon: "checkmark.circle",
                        accent: .ftGreen
                    ) { Task { await vm.validateOTP() } }

                    if !vm.otpValidationMsg.isEmpty {
                        ResultBanner(
                            success: vm.otpValid == true,
                            message: vm.otpValidationMsg
                        )
                    }
                }
            }
        }
    }

    // MARK: - TOTP Section

    @ViewBuilder
    private var totpSection: some View {
        InfoCallout(
            text: "TOTP (RFC 6238): time-based counter = floor(unix_time / 30). " +
                  "Both app and server compute HMAC-SHA1(secret, counter) independently. " +
                  "No network call needed — just clock synchronization. ±1 window for skew.",
            icon: "lightbulb",
            accent: accent
        )

        if vm.totpConfig == nil {
            PrimaryButton(
                label: "Enroll TOTP (Generate Secret)",
                icon: "qrcode",
                accent: accent
            ) { vm.enrollTOTP() }
        } else {
            // Live code display
            SectionCard(title: "Live TOTP Code", icon: "🕐", accent: accent) {
                VStack(spacing: 14) {

                    // Code display with countdown ring
                    ZStack {
                        // Progress ring
                        Circle()
                            .stroke(Color.ftSurface2, lineWidth: 6)
                            .frame(width: 100, height: 100)
                        Circle()
                            .trim(from: 0, to: CGFloat(vm.totpSecondsLeft) / 30.0)
                            .stroke(accent, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                            .frame(width: 100, height: 100)
                            .rotationEffect(.degrees(-90))
                            .animation(.linear(duration: 1), value: vm.totpSecondsLeft)

                        VStack(spacing: 2) {
                            Text(vm.currentTOTP)
                                .font(.system(size: 24, weight: .bold, design: .monospaced))
                                .foregroundStyle(accent)
                            Text("\(vm.totpSecondsLeft)s")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Color.ftTextDim)
                        }
                    }
                    .frame(maxWidth: .infinity)

                    CryptoOutputBox(
                        label: "Algorithm internals",
                        value: """
                        counter = floor(\(Int(Date.now.timeIntervalSince1970)) / 30) = \(Int(Date.now.timeIntervalSince1970 / 30))
                        HMAC-SHA1(secret, counter) → truncate → mod 10^6
                        """,
                        accent: .ftTextDim
                    )

                    if let url = vm.enrollmentURL {
                        CryptoOutputBox(
                            label: "otpauth:// URI (scan with Google Authenticator)",
                            value: url.absoluteString,
                            accent: accent
                        )
                    }
                }
            }

            SectionCard(title: "Validate TOTP", icon: "✅", accent: .ftGreen) {
                VStack(spacing: 12) {
                    TextField("Enter TOTP code", text: $vm.totpInput)
                        .font(.system(size: 24, weight: .bold, design: .monospaced))
                        .multilineTextAlignment(.center)
                        .foregroundStyle(Color.ftText)
                        .tint(accent)
                        .keyboardType(.numberPad)
                        .padding(14)
                        .background(Color.ftSurface2)
                        .clipShape(RoundedRectangle(cornerRadius: 10))

                    PrimaryButton(
                        label: "Validate Code",
                        icon: "checkmark.circle",
                        accent: .ftGreen
                    ) { vm.validateTOTP() }

                    if !vm.totpValidationMsg.isEmpty {
                        ResultBanner(
                            success: vm.totpValid == true,
                            message: vm.totpValidationMsg
                        )
                    }
                }
            }
        }
    }

    // MARK: - Algorithm comparison

    @ViewBuilder
    private var algorithmSection: some View {
        SectionCard(title: "HOTP vs TOTP", icon: "⚖️", accent: accent) {
            VStack(spacing: 10) {
                algorithmRow(
                    algo: "HOTP (RFC 4226)",
                    counter: "Incrementing integer",
                    sync: "Manual — counter desync risk",
                    use: "Hardware tokens, offline use",
                    color: .ftAmber
                )
                Divider().background(Color.ftBorder)
                algorithmRow(
                    algo: "TOTP (RFC 6238)",
                    counter: "floor(time / 30)",
                    sync: "Clock — ±30s tolerance",
                    use: "Authenticator apps, FinTech in-app",
                    color: .ftGreen
                )
            }
        }

        SectionCard(title: "Security Properties", icon: "🔒", accent: .ftAccent) {
            VStack(spacing: 10) {
                propertyRow("Single-use", "Each code valid once — server tracks used codes",
                            icon: "1.circle", color: .ftGreen)
                propertyRow("Time-limited", "30-second window — limits brute force window",
                            icon: "clock", color: .ftGreen)
                propertyRow("Shared secret", "HMAC key known to both app and server",
                            icon: "key", color: .ftAmber)
                propertyRow("No network", "TOTP works offline — clock sync only",
                            icon: "wifi.slash", color: .ftGreen)
                propertyRow("SMS weakness", "SIM swap, SS7 attacks on SMS OTP",
                            icon: "exclamationmark.triangle", color: .ftRed)
                propertyRow("Clock skew", "±1 window (±30s) tolerated by validation",
                            icon: "clock.badge.checkmark", color: .ftAccent)
            }
        }
    }

    // MARK: - Tab button

    @ViewBuilder
    private func tabButton(title: String, idx: Int) -> some View {
        Button {
            withAnimation(.easeInOut(duration: 0.2)) { selectedTab = idx }
        } label: {
            Text(title)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(selectedTab == idx ? Color.ftDark : Color.ftTextDim)
                .padding(.vertical, 10)
                .frame(maxWidth: .infinity)
                .background(selectedTab == idx ? accent : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private func algorithmRow(
        algo: String, counter: String, sync: String, use: String, color: Color
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(algo)
                .font(.system(size: 13, weight: .bold, design: .monospaced))
                .foregroundStyle(color)
            row("Counter", counter)
            row("Sync",    sync)
            row("Use case",use)
        }
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label + ":")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(Color.ftTextDimmer)
                .frame(width: 60, alignment: .leading)
            Text(value)
                .font(.system(size: 11))
                .foregroundStyle(Color.ftTextDim)
        }
    }

    @ViewBuilder
    private func propertyRow(_ title: String, _ desc: String, icon: String, color: Color) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .foregroundStyle(color)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color.ftText)
                Text(desc)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.ftTextDim)
            }
        }
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// Views/TransactionSigningView.swift
// MARK: ─────────────────────────────────────────────────────────────────────

public struct TransactionSigningView: View {

    @State private var vm: TransactionSigningViewModel
    @State private var showDetail = false

    public init(vm: TransactionSigningViewModel) { self._vm = State(initialValue: vm) }

    private let accent = Color(red: 0.10, green: 0.80, blue: 0.55)

    public var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {

                    DemoHeader(
                        icon: "✍️",
                        title: "Transaction Signing",
                        subtitle: "P-256 ECDSA · Non-Repudiation · SE",
                        accentColor: accent
                        )

                        VStack(spacing: 14) {

                            if !SecureEnclave.isAvailable {
                                InfoCallout(
                                    text: "Simulator detected — using software P-256 key. " +
                                          "On a real device this uses the Secure Enclave and triggers Face ID.",
                                    icon: "exclamationmark.triangle.fill",
                                    accent: .ftAmber
                                )
                            }

                            InfoCallout(
                                text: "Non-repudiation: the user cannot deny authorizing this transaction because " +
                                      "only the Secure Enclave on their specific device, confirmed by Face ID, " +
                                      "could have produced the ECDSA signature for the registered public key.",
                                icon: "lightbulb",
                                accent: accent
                            )

                            StepIndicator(
                                steps: ["Register Key", "Build Tx", "Sign", "Verify"],
                                currentStep: vm.stepIndex,
                                accent: accent
                            )

                            // ── Step 0: Register key ─────────────────────
                            if vm.stepIndex == 0 {
                                PrimaryButton(
                                    label: "① Register Signing Key (Secure Enclave)",
                                    icon: "cpu",
                                    accent: accent,
                                    isLoading: vm.isLoading
                                ) { Task { await vm.registerKey() } }
                            }

                            // ── Key info ─────────────────────────────────
                            if let info = vm.keyInfo {
                                SectionCard(title: "① Key Registered", icon: "🗝️", accent: accent) {
                                    VStack(spacing: 10) {
                                        FieldRow(
                                            label: "Source",
                                            value: info.sourceDescription,
                                            valueColor: info.source == .secureEnclave ? .ftGreen : .ftAmber
                                        )
                                        FieldRow(label: "Algorithm", value: info.keyAlgorithm, mono: true)
                                        FieldRow(label: "Biometric protected", value: info.isProtected ? "Yes" : "No (Simulator)", valueColor: info.isProtected ? .ftGreen : .ftAmber)
                                        CryptoOutputBox(
                                            label: "Public key (sent to FinTech server at registration)",
                                            value: info.publicKeyData.hexString,
                                            accent: accent
                                        )
                                    }
                                }
                            }

                            // ── Step 1: Build transaction ─────────────────
                            if vm.stepIndex >= 1 {
                                SectionCard(title: "② Transaction Details", icon: "💸", accent: accent) {
                                    VStack(spacing: 12) {
                                        AmountField(text: $vm.amountBDT)
                                        HStack(spacing: 10) {
                                            Image(systemName: "phone.fill")
                                                .foregroundStyle(Color.ftTextDim)
                                                .frame(width: 20)
                                            TextField("Receiver", text: $vm.receiverWallet)
                                                .font(.system(size: 14, design: .monospaced))
                                                .foregroundStyle(Color.ftText)
                                                .tint(accent)
                                        }
                                        .padding(12)
                                        .background(Color.ftSurface2)
                                        .clipShape(RoundedRectangle(cornerRadius: 10))

                                        PrimaryButton(
                                            label: "② Build Transaction",
                                            icon: "doc.text.fill",
                                            accent: accent
                                        ) { vm.buildTransaction() }
                                    }
                                }
                            }

                            // ── Step 2: Canonical bytes ────────────────────
                            if let tx = vm.currentTx, vm.stepIndex >= 2 {
                                SectionCard(title: "② Canonical Bytes (what gets signed)", icon: "📄", accent: accent) {
                                    VStack(spacing: 10) {
                                        InfoCallout(
                                            text: "Canonical format: txId|from|to|amountPaisa|timestamp|nonce|currency\n" +
                                                  "Amount is integer paisa — no floating-point ambiguity.\n" +
                                                  "Server reconstructs identical bytes for verification.",
                                            icon: "info.circle",
                                            accent: accent
                                        )
                                        FieldRow(label: "Amount (paisa — integer)", value: String(tx.amount.paisa), mono: true)
                                        FieldRow(label: "Server nonce (anti-replay)", value: tx.nonce, mono: true)
                                        CryptoOutputBox(
                                            label: "Canonical hex",
                                            value: tx.canonicalBytes.hexString,
                                            accent: accent
                                        )
                                    }
                                }

                                FlowArrow(
                                    label: SecureEnclave.isAvailable ? "→ Face ID gates SE signing" : "→ P-256 sign",
                                    accent: accent
                                )

                                PrimaryButton(
                                    label: SecureEnclave.isAvailable
                                        ? "③ Sign (Face ID required)"
                                        : "③ Sign Transaction",
                                    icon: SecureEnclave.isAvailable ? "faceid" : "signature",
                                    accent: accent,
                                    isLoading: vm.isLoading
                                ) { Task { await vm.signTransaction() } }
                            }

                            // ── Step 3: Signature ──────────────────────────
                            if let sig = vm.signature, vm.stepIndex >= 3 {
                                SectionCard(title: "③ ECDSA P-256 Signature", icon: "✍️", accent: accent) {
                                    VStack(spacing: 10) {
                                        CryptoOutputBox(
                                            label: "DER-encoded signature (\(sig.count) bytes)",
                                            value: sig.hexString,
                                            accent: accent
                                        )
                                        InfoCallout(
                                            text: "ECDSA produces an (r,s) pair — 32 bytes each. " +
                                                  "DER encoding adds ASN.1 structure → ~70-72 bytes total. " +
                                                  "This is sent as a header in the transfer request.",
                                            icon: "info.circle",
                                            accent: accent
                                        )
                                    }
                                }

                                SectionCard(title: "④ Tamper Simulation", icon: "⚠️", accent: .ftAmber) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text("Attacker changes receiver wallet")
                                                .font(.system(size: 13, weight: .semibold))
                                                .foregroundStyle(Color.ftText)
                                            Text("Signature covers original canonical bytes")
                                                .font(.system(size: 11, design: .monospaced))
                                                .foregroundStyle(Color.ftTextDim)
                                        }
                                        Spacer()
                                        Toggle("", isOn: $vm.tamperMode).tint(.ftRed)
                                    }
                                }

                                PrimaryButton(
                                    label: "④ Server Verify Signature",
                                    icon: "checkmark.shield.fill",
                                    accent: vm.tamperMode ? .ftRed : accent,
                                    isLoading: vm.isLoading
                                ) { Task { await vm.verifySignature() } }
                            }

                            // ── Step 4: Result ─────────────────────────────
                            if vm.stepIndex >= 4 {
                                ResultBanner(success: vm.isSuccess, message: vm.statusMessage)

                                if vm.verificationResult == true {
                                    InfoCallout(
                                        text: "Non-repudiation proof:\n" +
                                              "• Signature valid → transaction not tampered\n" +
                                              "• Key in Secure Enclave → only this device could sign\n" +
                                              "• Face ID required → user physically present\n" +
                                              "→ User CANNOT deny authorizing this transaction",
                                        icon: "checkmark.shield.fill",
                                        accent: accent
                                    )
                                }

                                HStack(spacing: 10) {
                                    PrimaryButton(label: "Reset", icon: "arrow.counterclockwise", accent: .ftTextDim) {
                                        vm.reset()
                                    }
                                    if vm.stepIndex < 2 {
                                        PrimaryButton(label: "Register Key", icon: "cpu", accent: accent) {
                                            Task { await vm.registerKey() }
                                        }
                                    }
                                }
                            } else if !vm.statusMessage.isEmpty {
                                ResultBanner(success: vm.isSuccess, message: vm.statusMessage)
                            }

                            // ── Audit log ─────────────────────────────────
                            if !vm.auditEvents.isEmpty {
                                SectionCard(title: "Audit Trail", icon: "📋", accent: .ftAmber) {
                                    VStack(alignment: .leading, spacing: 8) {
                                        ForEach(vm.auditEvents.prefix(6), id: \.timestamp) { event in
                                            HStack(alignment: .top, spacing: 8) {
                                                Image(systemName: event.category == .security ? "shield" : "pencil.circle")
                                                    .font(.system(size: 12))
                                                    .foregroundStyle(Color.ftAmber)
                                                Text(event.event)
                                                    .font(.system(size: 11))
                                                    .foregroundStyle(Color.ftText)
                                                Spacer()
                                                Text(timeStr(event.timestamp))
                                                    .font(.system(size: 9, design: .monospaced))
                                                    .foregroundStyle(Color.ftTextDimmer)
                                            }
                                        }
                                    }
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
                NavigationLink(destination: TopicDetailView(topic: TopicDetails.transactionSigning)) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 18))
                        .foregroundStyle(accent)
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func timeStr(_ date: Date) -> String {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f.string(from: date)
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// Views/SessionManagementView.swift
// MARK: ─────────────────────────────────────────────────────────────────────

public struct SessionManagementView: View {

    @State private var vm: SessionViewModel
    @State private var showDetail = false

    public init(vm: SessionViewModel) { self._vm = State(initialValue: vm) }

    private let accent = Color(red: 0.85, green: 0.55, blue: 1.0)

    public var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {

                    DemoHeader(
                        icon: "🕐",
                        title: "Session & JWT Management",
                        subtitle: "Token Rotation · Step-Up Auth · Actor Safety",
                        accentColor: accent
                    )

                    VStack(spacing: 14) {

                            InfoCallout(
                                text: "Three-token model:\n" +
                                      "• Access Token (JWT): 15-min, memory-only, sent with every request\n" +
                                      "• Refresh Token: 7-day, Keychain, single-use with rotation\n" +
                                      "• Step-Up Token: 2-min, required for high-value transactions",
                                icon: "lightbulb",
                                accent: accent
                            )

                            // ── Login ─────────────────────────────────────
                            SectionCard(title: "Login", icon: "🔑", accent: accent) {
                                VStack(spacing: 12) {
                                    HStack(spacing: 10) {
                                        Image(systemName: "phone.fill")
                                            .foregroundStyle(Color.ftTextDim)
                                            .frame(width: 20)
                                        TextField("Wallet (01800000001)", text: $vm.walletInput)
                                            .font(.system(size: 14, design: .monospaced))
                                            .foregroundStyle(Color.ftText)
                                            .tint(accent)
                                    }
                                    .padding(12)
                                    .background(Color.ftSurface2)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))

                                    HStack(spacing: 10) {
                                        Image(systemName: "lock.fill")
                                            .foregroundStyle(Color.ftTextDim)
                                            .frame(width: 20)
                                        SecureField("PIN (1234)", text: $vm.pinInput)
                                            .font(.system(size: 14, design: .monospaced))
                                            .foregroundStyle(Color.ftText)
                                            .tint(accent)
                                    }
                                    .padding(12)
                                    .background(Color.ftSurface2)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))

                                    PrimaryButton(
                                        label:     vm.isLoggedIn ? "Logged In ✓" : "Login",
                                        icon:      vm.isLoggedIn ? "checkmark.circle.fill" : "arrow.right.circle",
                                        accent:    vm.isLoggedIn ? .ftGreen : accent,
                                        isLoading: vm.isLoading
                                    ) { Task { await vm.login() } }
                                }
                            }

                            // ── Session state ─────────────────────────────
                            if let claims = vm.currentClaims {
                                SectionCard(title: "Active Session", icon: "✅", accent: .ftGreen) {
                                    VStack(spacing: 10) {
                                        FieldRow(label: "User ID (sub)", value: claims.sub, mono: true)
                                        FieldRow(label: "Session ID", value: claims.sessionId, mono: true)
                                        FieldRow(label: "Device ID", value: claims.deviceId, mono: true)
                                        FieldRow(
                                            label: "Roles",
                                            value: claims.roles.joined(separator: ", "),
                                            mono: true
                                        )
                                        if let exp = vm.tokenExpiry {
                                            FieldRow(
                                                label: "Access token expires",
                                                value: RelativeDateTimeFormatter().localizedString(for: exp, relativeTo: Date.now),
                                                valueColor: exp > Date.now ? .ftGreen : .ftRed
                                            )
                                        }
                                        if !vm.accessTokenPreview.isEmpty {
                                            CryptoOutputBox(
                                                label: "Access token (memory-only — never persisted to disk)",
                                                value: vm.accessTokenPreview,
                                                accent: .ftGreen
                                            )
                                        }
                                    }
                                }

                                // ── JWT anatomy ────────────────────────────
                                SectionCard(title: "JWT Structure", icon: "🧩", accent: accent) {
                                    VStack(spacing: 10) {
                                        InfoCallout(
                                            text: "JWT = base64url(header).base64url(payload).signature\n" +
                                                  "Payload is NOT encrypted — base64url decoded reveals all claims. " +
                                                  "NEVER put sensitive data (PIN, card number) in a JWT payload. " +
                                                  "Security comes from the SIGNATURE, not confidentiality.",
                                            icon: "info.circle",
                                            accent: accent
                                        )
                                        jwtPartBox(label: "Header", value: #"{"alg":"ES256","typ":"JWT"}"#, color: .ftRed)
                                        jwtPartBox(
                                            label: "Payload (claims — readable by anyone)",
                                            value: "sub, walletId, deviceId, exp, iat, roles, sessionId",
                                            color: .ftAmber
                                        )
                                        jwtPartBox(label: "Signature (ES256)", value: "ECDSA P-256 — proves token from auth server", color: .ftGreen)
                                    }
                                }

                                // ── Token refresh demo ─────────────────────
                                SectionCard(title: "Transparent Token Refresh", icon: "🔄", accent: accent) {
                                    VStack(spacing: 12) {
                                        InfoCallout(
                                            text: "The Actor-isolated SessionService serialises concurrent refresh calls. " +
                                                  "If 5 requests all see an expired token simultaneously, " +
                                                  "only ONE refresh is triggered — all 5 await the same Task. " +
                                                  "This eliminates the double-refresh race condition.",
                                            icon: "arrow.triangle.2.circlepath",
                                            accent: accent
                                        )
                                        PrimaryButton(
                                            label:     "Simulate API Call (auto-refresh if expired)",
                                            icon:      "network",
                                            accent:    accent,
                                            isLoading: vm.isLoading
                                        ) { Task { await vm.fetchWithAutoRefresh() } }
                                    }
                                }

                                // ── Step-up auth ───────────────────────────
                                SectionCard(title: "Step-Up Authentication", icon: "🆙", accent: .ftAmber) {
                                    VStack(spacing: 12) {
                                        InfoCallout(
                                            text: "Transactions above 500 BDT require a step-up auth token " +
                                                  "(2-minute TTL). This ensures a stolen session can't drain " +
                                                  "an account — the attacker also needs the user's biometric.",
                                            icon: "lock.badge.clock",
                                            accent: .ftAmber
                                        )
                                        PrimaryButton(
                                            label:     "Request Step-Up Token (₳500+ transfer)",
                                            icon:      "arrow.up.circle.fill",
                                            accent:    .ftAmber,
                                            isLoading: vm.isLoading
                                        ) { Task { await vm.stepUpAuth() } }

                                        if !vm.stepUpToken.isEmpty {
                                            FieldRow(
                                                label: "Step-up token (2-min TTL)",
                                                value: vm.stepUpToken,
                                                mono: true,
                                                valueColor: .ftAmber
                                            )
                                        }
                                    }
                                }

                                PrimaryButton(
                                    label: "Logout (Clear All Session Data)",
                                    icon:  "rectangle.portrait.and.arrow.right",
                                    accent: .ftRed
                                ) { Task { await vm.logout() } }
                            }

                            // ── Status messages ────────────────────────────
                            if !vm.statusMessage.isEmpty {
                                ResultBanner(success: vm.isSuccess, message: vm.statusMessage)
                            }

                            // ── Audit log ─────────────────────────────────
                            if !vm.auditEvents.isEmpty {
                                SectionCard(title: "Session Audit Log", icon: "📋", accent: .ftAmber) {
                                    VStack(alignment: .leading, spacing: 8) {
                                        ForEach(vm.auditEvents.prefix(8), id: \.timestamp) { event in
                                            HStack(alignment: .top, spacing: 8) {
                                                Image(systemName: "clock.arrow.circlepath")
                                                    .font(.system(size: 11))
                                                    .foregroundStyle(Color.ftAmber)
                                                Text(event.event)
                                                    .font(.system(size: 11))
                                                    .foregroundStyle(Color.ftText)
                                                Spacer()
                                                Text(timeStr(event.timestamp))
                                                    .font(.system(size: 9, design: .monospaced))
                                                    .foregroundStyle(Color.ftTextDimmer)
                                            }
                                        }
                                    }
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
                NavigationLink(destination: TopicDetailView(topic: TopicDetails.sessionManagement)) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 18))
                        .foregroundStyle(accent)
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    @ViewBuilder
    private func jwtPartBox(label: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .foregroundStyle(color)
                .textCase(.uppercase)
                .tracking(1)
            Text(value)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Color.ftTextDim)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(color.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 5))
        }
    }

    private func timeStr(_ date: Date) -> String {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f.string(from: date)
    }
}
