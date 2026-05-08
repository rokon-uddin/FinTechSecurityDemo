//
//  PaymentFlowView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/8/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//

import SwiftUI

struct PaymentFlowView: View {

    @State private var vm: PaymentFlowViewModel

    private let accent = Color(red: 0.20, green: 0.70, blue: 0.95)

    init(vm: PaymentFlowViewModel) {
        self._vm = State(initialValue: vm)
    }

    private let stepNames = [
        "Security", "Login", "Session", "ECDH", "Payment",
        "Token", "Sign", "Encrypt", "TLS", "Verify", "Cleanup",
    ]

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {
                    DemoHeader(
                        icon: "💳",
                        title: "Login → Payment Flow",
                        subtitle: "End-to-End Security · 11 Steps",
                        accentColor: accent
                    )

                    StepIndicator(
                        steps: stepNames,
                        currentStep: vm.currentStep,
                        accent: accent
                    )
                    .padding(.horizontal, 16)

                    if let error = vm.errorMessage {
                        ResultBanner(success: false, message: error)
                            .padding(.horizontal, 16)
                    }

                    ForEach(vm.stepLogs) { log in
                        CompletedStepCard(log: log, accent: accent)
                            .padding(.horizontal, 16)
                    }

                    if !vm.flowComplete {
                        currentStepView
                            .padding(.horizontal, 16)
                    } else {
                        flowCompleteSummary
                            .padding(.horizontal, 16)
                    }
                }
                .padding(.bottom, 40)
            }
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Current Step Router

    @ViewBuilder
    private var currentStepView: some View {
        switch vm.currentStep {
        case 0: DeviceSecurityStepView(vm: vm, accent: accent)
        case 1: LoginStepView(vm: vm, accent: accent)
        case 2: SessionStepView(vm: vm, accent: accent)
        case 3: KeyExchangeStepView(vm: vm, accent: accent)
        case 4: PaymentInputStepView(vm: vm, accent: accent)
        case 5: TokenizationStepView(vm: vm, accent: accent)
        case 6: SigningStepView(vm: vm, accent: accent)
        case 7: EncryptionStepView(vm: vm, accent: accent)
        case 8: TLSTransmitStepView(vm: vm, accent: accent)
        case 9: VerificationStepView(vm: vm, accent: accent)
        case 10: ResponseCleanupStepView(vm: vm, accent: accent)
        default: EmptyView()
        }
    }

    // MARK: - Flow Complete

    private var flowCompleteSummary: some View {
        VStack(spacing: 14) {
            if let result = vm.verificationResult {
                ResultBanner(
                    success: result.overallSuccess,
                    message: result.overallSuccess
                        ? "Payment flow complete! All 5 server-side checks passed.\n\(result.decryptedPreview)"
                        : "Verification failed — see logs above."
                )
            }

            SectionCard(title: "Security Topics Covered", icon: "📚", accent: accent) {
                VStack(alignment: .leading, spacing: 8) {
                    topicRow("Device Security", "Jailbreak detection, biometric enrollment, environment validation")
                    topicRow("Session Management", "JWT access/refresh tokens, token rotation (RFC 9700)")
                    topicRow("ECDH P-256", "Ephemeral key exchange, Perfect Forward Secrecy")
                    topicRow("HKDF-SHA256", "Key derivation with domain separation")
                    topicRow("PCI Tokenization", "Card data replaced with useless token")
                    topicRow("Secure Enclave", "Hardware-bound P-256 signing key")
                    topicRow("ECDSA P-256", "Transaction signature, non-repudiation")
                    topicRow("AES-256-GCM", "Authenticated encryption (AEAD)")
                    topicRow("HMAC-SHA256", "Request integrity, constant-time comparison")
                    topicRow("TLS 1.3", "Certificate pinning, ephemeral URLSession, ECDHE")
                    topicRow("Nonce + Timestamp", "Anti-replay: single-use nonce + 5-min window")
                    topicRow("Secure Cleanup", "Encrypted response, PCI audit trail, memory wipe")
                }
            }

            PrimaryButton(
                label: "Reset & Start Over",
                icon: "arrow.counterclockwise",
                accent: .ftAmber
            ) {
                vm.resetFlow()
            }
        }
    }

    private func topicRow(_ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Color.ftGreen)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .foregroundStyle(Color.ftText)
                Text(detail)
                    .font(.system(size: 10))
                    .foregroundStyle(Color.ftTextDim)
            }
        }
    }
}

// MARK: - Completed Step Card (Expandable)

struct CompletedStepCard: View {
    let log: StepLogEntry
    let accent: Color
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 10) {
                    ZStack {
                        Circle()
                            .fill(Color.ftGreen.opacity(0.2))
                            .frame(width: 28, height: 28)
                        Image(systemName: "checkmark")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(Color.ftGreen)
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Step \(log.stepNumber + 1): \(log.title)")
                            .font(.system(size: 12, weight: .bold, design: .rounded))
                            .foregroundStyle(Color.ftText)
                        HStack(spacing: 6) {
                            SideBadge(side: log.side)
                            ForEach(log.securityTopics.prefix(2), id: \.self) { topic in
                                Text(topic)
                                    .font(.system(size: 8, weight: .medium, design: .monospaced))
                                    .foregroundStyle(accent)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 2)
                                    .background(accent.opacity(0.1))
                                    .clipShape(Capsule())
                            }
                        }
                    }

                    Spacer()

                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Color.ftTextDim)
                }
                .padding(12)
            }
            .buttonStyle(.plain)

            if isExpanded {
                Divider().background(Color.ftBorder)
                expandedContent
                    .padding(12)
                    .transition(.opacity)
            }
        }
        .background(Color.ftSurface)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.ftGreen.opacity(0.2), lineWidth: 1)
        )
    }

    private var expandedContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            if !log.requestParams.isEmpty {
                Text("REQUEST")
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .foregroundStyle(Color.ftAmber)
                    .tracking(1.5)
                ForEach(Array(log.requestParams.enumerated()), id: \.offset) { _, param in
                    FieldRow(label: param.label, value: param.value, mono: true)
                }
            }

            if !log.responseData.isEmpty {
                Divider().background(Color.ftBorder)
                Text("RESPONSE")
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .foregroundStyle(Color.ftGreen)
                    .tracking(1.5)
                ForEach(Array(log.responseData.enumerated()), id: \.offset) { _, param in
                    FieldRow(label: param.label, value: param.value, mono: true)
                }
            }

            if !log.logLines.isEmpty {
                Divider().background(Color.ftBorder)
                Text("OSLOG TRACE")
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .foregroundStyle(accent)
                    .tracking(1.5)
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(log.logLines.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(logLineColor(line))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(white: 0, opacity: 0.3))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    private func logLineColor(_ line: String) -> Color {
        if line.contains("✓") || line.contains("SUCCESS") || line.contains("VALID") || line.contains("APPROVED") {
            return .ftGreen
        }
        if line.contains("✗") || line.contains("FAILED") || line.contains("INVALID") {
            return .ftRed
        }
        if line.contains("═══") {
            return .ftAmber
        }
        return .ftTextDim
    }
}

// MARK: - Side Badge

struct SideBadge: View {
    let side: StepLogEntry.ExecutionSide

    var body: some View {
        Text(side.rawValue)
            .font(.system(size: 7, weight: .bold, design: .monospaced))
            .foregroundStyle(sideColor)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(sideColor.opacity(0.15))
            .clipShape(Capsule())
    }

    private var sideColor: Color {
        switch side {
        case .client: return Color(red: 0.30, green: 0.70, blue: 0.95)
        case .server: return Color(red: 0.70, green: 0.50, blue: 0.95)
        case .both:   return Color.ftAccent
        }
    }
}
