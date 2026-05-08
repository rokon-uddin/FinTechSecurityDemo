//
//  PCITokenizationView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// PCI-DSS compliant card tokenization demo.
// Demonstrates: Req 3 (no PAN storage), Req 10 (audit log), token vs encryption.

import SwiftUI

public struct PCITokenizationView: View {

    @State private var vm: TokenizationViewModel
    @State private var showAuditLog = false
    @State private var showDetail = false

    public init(vm: TokenizationViewModel) {
        self._vm = State(initialValue: vm)
    }

    private let accent = Color(red: 0.92, green: 0.20, blue: 0.24)  // FinTech red

    public var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {

                        DemoHeader(
                            icon: "💳",
                            title: "PCI-DSS Tokenization",
                            subtitle: "Token replaces PAN · Req 3, 6, 10",
                            accentColor: accent
                        )

                        VStack(spacing: 14) {

                            // ── Concept explanation ─────────────────────
                            InfoCallout(
                                text: "Tokenization replaces a card number (PAN) with a random, " +
                                      "meaningless token. Even if your app is fully compromised, " +
                                      "attackers get useless tokens — not card numbers. " +
                                      "The real PAN lives only in the token vault on the payment gateway.",
                                icon: "lightbulb",
                                accent: accent
                            )

                            InfoCallout(
                                text: "PCI-DSS Req 3.4: Never store the full PAN. " +
                                      "If you must display card info, show only the last 4 digits. " +
                                      "This demo shows how raw card data (entered below) is " +
                                      "immediately tokenized — the app only ever stores the token.",
                                icon: "exclamationmark.shield",
                                accent: .ftAmber
                            )

                            // ── Card input ──────────────────────────────
                            SectionCard(title: "Card Input (SDK-managed in production)", icon: "💳", accent: accent) {
                                VStack(spacing: 12) {
                                    InfoCallout(
                                        text: "In production: raw card data is entered inside a PCI-validated " +
                                              "SDK iframe (Stripe, Adyen). Your code never receives the PAN. " +
                                              "Here we simulate that the SDK hands you a request object.",
                                        icon: "info.circle",
                                        accent: .ftTextDim
                                    )

                                    // PAN field — masked in production
                                    cardField(
                                        label:   "Card Number (PAN)",
                                        binding: $vm.pan,
                                        icon:    "creditcard",
                                        hint:    "4242424242424242",
                                        mono:    true
                                    )
                                    HStack(spacing: 12) {
                                        cardField(
                                            label:   "CVV",
                                            binding: $vm.cvv,
                                            icon:    "lock",
                                            hint:    "123",
                                            mono:    true
                                        )
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text("EXPIRY")
                                                .font(.system(size: 10, design: .monospaced))
                                                .foregroundStyle(Color.ftTextDimmer)
                                                .tracking(1.5)
                                            HStack {
                                                Picker("Month", selection: $vm.expiryMonth) {
                                                    ForEach(1...12, id: \.self) {
                                                        Text(String(format: "%02d", $0)).tag($0)
                                                    }
                                                }
                                                .pickerStyle(.wheel)
                                                .frame(height: 80)
                                                .clipped()

                                                Picker("Year", selection: $vm.expiryYear) {
                                                    ForEach(2025...2035, id: \.self) { Text(String($0)).tag($0) }
                                                }
                                                .pickerStyle(.wheel)
                                                .frame(height: 80)
                                                .clipped()
                                            }
                                        }
                                    }
                                    cardField(
                                        label:   "Cardholder Name",
                                        binding: $vm.cardHolder,
                                        icon:    "person",
                                        hint:    "FIRSTNAME LASTNAME",
                                        mono:    false
                                    )
                                }
                            }

                            // ── Tokenize button ─────────────────────────
                            PrimaryButton(
                                label:     "Tokenize Card",
                                icon:      "arrow.2.circlepath",
                                accent:    accent,
                                isLoading: vm.isLoading
                            ) {
                                Task { await vm.tokenizeCard() }
                            }

                            // ── Result message ──────────────────────────
                            if let msg = vm.successMessage {
                                ResultBanner(success: true, message: msg)
                            }
                            if let msg = vm.errorMessage {
                                ResultBanner(success: false, message: msg)
                            }

                            // ── Stored tokens ───────────────────────────
                            if !vm.storedTokens.isEmpty {
                                SectionCard(title: "Stored Tokens (Keychain)", icon: "🗝️", accent: .ftGreen) {
                                    VStack(spacing: 10) {
                                        InfoCallout(
                                            text: "These tokens are stored in Keychain — never on disk unencrypted. " +
                                                  "The app only knows the last 4 digits and brand. " +
                                                  "The full PAN is in the gateway's token vault.",
                                            icon: "checkmark.shield",
                                            accent: .ftGreen
                                        )
                                        ForEach(vm.storedTokens) { token in
                                            tokenCard(token)
                                        }
                                    }
                                }
                            }

                            // ── Encryption vs Tokenization ──────────────
                            SectionCard(title: "Encryption vs Tokenization", icon: "⚖️", accent: .ftAccent) {
                                VStack(spacing: 8) {
                                    comparisonRow(
                                        label: "Reversible",
                                        encrypt: "Yes (with key)",
                                        token:   "Only via vault"
                                    )
                                    comparisonRow(
                                        label: "Key compromise",
                                        encrypt: "All data exposed",
                                        token:   "Tokens still useless"
                                    )
                                    comparisonRow(
                                        label: "Storage",
                                        encrypt: "Encrypted blob",
                                        token:   "Random string"
                                    )
                                    comparisonRow(
                                        label: "PCI scope",
                                        encrypt: "In scope (CHD)",
                                        token:   "Out of scope"
                                    )
                                    comparisonRow(
                                        label: "App compromise",
                                        encrypt: "Key may be extractable",
                                        token:   "Tokens useless alone"
                                    )
                                }
                            }

                            // ── Audit log ───────────────────────────────
                            if !vm.pciAuditLog.isEmpty {
                                SectionCard(title: "PCI-DSS Audit Log (Req 10)", icon: "📋", accent: .ftAmber) {
                                    VStack(alignment: .leading, spacing: 8) {
                                        InfoCallout(
                                            text: "PCI Req 10: Log all access to CHD. " +
                                                  "Note: the raw PAN and CVV are NEVER in the log. " +
                                                  "Only safe metadata (lastFour, tokenId, event type).",
                                            icon: "info.circle",
                                            accent: .ftAmber
                                        )
                                        ForEach(vm.pciAuditLog.prefix(8), id: \.timestamp) { event in
                                            auditRow(event)
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
                NavigationLink(destination: TopicDetailView(topic: TopicDetails.pciTokenization)) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 18))
                        .foregroundStyle(accent)
                }
            }
        }
        .task { await vm.loadTokens() }
        .preferredColorScheme(.dark)
    }

    // MARK: - Subviews

    @ViewBuilder
    private func cardField(
        label: String, binding: Binding<String>,
        icon: String, hint: String, mono: Bool
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(Color.ftTextDimmer)
                .tracking(1)
                .textCase(.uppercase)
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 13))
                    .foregroundStyle(Color.ftTextDim)
                    .frame(width: 20)
                TextField(hint, text: binding)
                    .font(mono
                          ? .system(size: 13, design: .monospaced)
                          : .system(size: 13))
                    .foregroundStyle(Color.ftText)
                    .tint(accent)
            }
            .padding(12)
            .background(Color.ftSurface2)
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    @ViewBuilder
    private func tokenCard(_ token: PaymentToken) -> some View {
        HStack(spacing: 14) {
            // Card brand icon
            ZStack {
                RoundedRectangle(cornerRadius: 6)
                    .fill(Color.ftSurface2)
                    .frame(width: 44, height: 30)
                Text(brandEmoji(token.brand))
                    .font(.system(size: 18))
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(token.maskedPAN)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(Color.ftText)
                HStack(spacing: 8) {
                    Text("Token: \(token.id.prefix(16))...")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Color.ftTextDim)
                }
            }
            Spacer()

            // Delete button
            Button("Delete", systemImage: "trash") {
                Task { await vm.deleteToken(token) }
            }
            .font(.system(size: 13))
            .foregroundStyle(Color.ftRed.opacity(0.7))
            .labelStyle(.iconOnly)
        }
        .padding(10)
        .background(Color.ftSurface2)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    @ViewBuilder
    private func comparisonRow(label: String, encrypt: String, token: String) -> some View {
        HStack(spacing: 0) {
            Text(label)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(Color.ftTextDim)
                .frame(maxWidth: .infinity, alignment: .leading)
            Text(encrypt)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(Color.ftAmber)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
            Text(token)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(Color.ftGreen)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
        }
        .padding(.vertical, 4)
        Divider().background(Color.ftBorder)
    }

    @ViewBuilder
    private func auditRow(_ event: AuditEvent) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(categoryIcon(event.category))
                .font(.system(size: 12))
            VStack(alignment: .leading, spacing: 2) {
                Text(event.event)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color.ftText)
                if !event.metadata.isEmpty {
                    Text(event.metadata.map { "\($0.key): \($0.value)" }.joined(separator: " · "))
                        .font(.system(size: 9.5, design: .monospaced))
                        .foregroundStyle(Color.ftTextDim)
                        .lineLimit(2)
                }
            }
            Spacer()
            Text(timeString(event.timestamp))
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(Color.ftTextDimmer)
        }
        .padding(.vertical, 4)
    }

    // MARK: - Helpers

    private func brandEmoji(_ brand: CardBrand) -> String {
        switch brand {
        case .visa:       return "💳"
        case .mastercard: return "🔴"
        case .amex:       return "🔵"
        case .discover:   return "🟠"
        case .unknown:    return "💳"
        }
    }

    private func categoryIcon(_ cat: AuditEvent.Category) -> String {
        switch cat {
        case .authentication: return "🔑"
        case .transaction:    return "💸"
        case .tokenization:   return "🔄"
        case .security:       return "🛡️"
        case .session:        return "🕐"
        }
    }

    private func timeString(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: date)
    }
}
