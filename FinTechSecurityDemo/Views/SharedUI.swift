//
//  SharedUI.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Reusable SwiftUI components for all demo screens

import SwiftUI

// MARK: - Design Tokens

extension Color {
    static let ftPrimary    = Color(red: 0.92, green: 0.20, blue: 0.24)   // primary red
    static let ftDark       = Color(red: 0.06, green: 0.08, blue: 0.13)   // deep navy
    static let ftSurface    = Color(red: 0.10, green: 0.13, blue: 0.20)   // card bg
    static let ftSurface2   = Color(red: 0.14, green: 0.18, blue: 0.26)   // elevated surface
    static let ftAccent     = Color(red: 0.00, green: 0.83, blue: 0.67)   // teal accent
    static let ftAmber      = Color(red: 0.95, green: 0.65, blue: 0.10)   // warning amber
    static let ftBorder     = Color(white: 1, opacity: 0.08)
    static let ftText       = Color(white: 1, opacity: 0.90)
    static let ftTextDim    = Color(white: 1, opacity: 0.50)
    static let ftTextDimmer = Color(white: 1, opacity: 0.25)
    static let ftGreen      = Color(red: 0.24, green: 0.80, blue: 0.55)
    static let ftRed        = Color(red: 0.90, green: 0.30, blue: 0.30)
}

// MARK: - Screen Header

struct DemoHeader: View {
    let icon: String
    let title: String
    let subtitle: String
    let accentColor: Color

    var body: some View {
        VStack(spacing: 0) {
            // Top bar
            HStack {
                ZStack {
                    Circle()
                        .fill(accentColor.opacity(0.15))
                        .frame(width: 48, height: 48)
                    Text(icon)
                        .font(.system(size: 22))
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 18, weight: .bold, design: .rounded))
                        .foregroundStyle(Color.ftText)
                    Text(subtitle)
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundStyle(accentColor)
                        .textCase(.uppercase)
                        .tracking(1.5)
                }
                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.top, 16)
            .padding(.bottom, 16)

            Divider()
                .background(Color.ftBorder)
        }
        .background(Color.ftSurface)
    }
}

// MARK: - Section Card

struct SectionCard<Content: View>: View {
    let title: String
    let icon: String
    let accent: Color
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Section header
            HStack(spacing: 8) {
                Text(icon)
                    .font(.system(size: 14))
                Text(title)
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .textCase(.uppercase)
                    .tracking(1.5)
                    .foregroundStyle(accent)
                Spacer()
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(accent.opacity(0.08))

            Divider().background(Color.ftBorder)

            content
                .padding(14)
        }
        .background(Color.ftSurface)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.ftBorder, lineWidth: 1)
        )
    }
}

// MARK: - Labelled Field

struct FieldRow: View {
    let label: String
    let value: String
    var mono: Bool = false
    var accent: Color = .ftTextDim
    var valueColor: Color = .ftText
    var truncate: Bool = true

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(Color.ftTextDimmer)
                .textCase(.uppercase)
                .tracking(1)
            if truncate {
                Text(value)
                    .font(mono
                          ? .system(size: 11, design: .monospaced)
                          : .system(size: 13, weight: .medium))
                    .foregroundStyle(valueColor)
                    .lineLimit(2)
                    .truncationMode(.middle)
            } else {
                Text(value)
                    .font(mono
                          ? .system(size: 11, design: .monospaced)
                          : .system(size: 13, weight: .medium))
                    .foregroundStyle(valueColor)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// MARK: - Crypto Output Box

struct CryptoOutputBox: View {
    let label: String
    let value: String
    var accent: Color = .ftAccent
    var isError: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(label)
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundStyle(isError ? Color.ftRed : accent)
                    .textCase(.uppercase)
                    .tracking(1.5)
                Spacer()
                // Copy button
                Button {
                    UIPasteboard.general.string = value
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "doc.on.doc")
                            .font(.system(size: 10))
                        Text("copy")
                            .font(.system(size: 9, design: .monospaced))
                    }
                    .foregroundStyle(Color.ftTextDim)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.ftBorder)
                    .clipShape(Capsule())
                }
            }
            ScrollView(.horizontal) {
                Text(value)
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(isError ? Color.ftRed : Color.ftText)
                    .fixedSize(horizontal: true, vertical: false)
                    .padding(10)
            }
            .scrollIndicators(.hidden)
            .background(Color(white: 0, opacity: 0.25))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
    }
}

// MARK: - Result Banner

struct ResultBanner: View {
    let success: Bool
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: success ? "checkmark.seal.fill" : "xmark.seal.fill")
                .font(.system(size: 18))
                .foregroundStyle(success ? Color.ftGreen : Color.ftRed)
                .padding(.top, 1)
            Text(message)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(success ? Color.ftGreen : Color.ftRed)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background((success ? Color.ftGreen : Color.ftRed).opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke((success ? Color.ftGreen : Color.ftRed).opacity(0.3), lineWidth: 1)
        )
    }
}

// MARK: - Primary Action Button

struct PrimaryButton: View {
    let label: String
    let icon: String
    var accent: Color = .ftAccent
    var isLoading: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if isLoading {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .ftDark))
                        .scaleEffect(0.75)
                } else {
                    Image(systemName: icon)
                        .font(.system(size: 13, weight: .semibold))
                }
                Text(label)
                    .font(.system(size: 14, weight: .bold, design: .rounded))
            }
            .foregroundStyle(Color.ftDark)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(
                LinearGradient(
                    colors: [accent, accent.opacity(0.8)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .disabled(isLoading)
        .buttonStyle(.plain)
    }
}

// MARK: - Step Indicator

struct StepIndicator: View {
    let steps: [String]
    let currentStep: Int
    var accent: Color = .ftAccent

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(steps.enumerated()), id: \.offset) { idx, step in
                // Step circle
                ZStack {
                    Circle()
                        .fill(idx <= currentStep ? accent : Color.ftSurface2)
                        .frame(width: 24, height: 24)
                    if idx < currentStep {
                        Image(systemName: "checkmark")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(Color.ftDark)
                    } else {
                        Text("\(idx + 1)")
                            .font(.system(size: 10, weight: .bold, design: .rounded))
                            .foregroundStyle(idx == currentStep ? Color.ftDark : Color.ftTextDimmer)
                    }
                }
                // Connector line
                if idx < steps.count - 1 {
                    Rectangle()
                        .fill(idx < currentStep ? accent : Color.ftBorder)
                        .frame(height: 2)
                        .frame(maxWidth: .infinity)
                }
            }
        }
    }
}

// MARK: - Amount Input Field

struct AmountField: View {
    @Binding var text: String
    var placeholder: String = "0.00"

    var body: some View {
        HStack(spacing: 8) {
            Text("৳")
                .font(.system(size: 20, weight: .bold, design: .rounded))
                .foregroundStyle(Color.ftAccent)
            TextField(placeholder, text: $text)
                .font(.system(size: 22, weight: .bold, design: .rounded))
                .foregroundStyle(Color.ftText)
                .keyboardType(.decimalPad)
                .tint(.ftAccent)
        }
        .padding(14)
        .background(Color.ftSurface2)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.ftAccent.opacity(0.3), lineWidth: 1)
        )
    }
}

// MARK: - Info Callout

struct InfoCallout: View {
    let text: String
    var icon: String = "info.circle"
    var accent: Color = .ftAmber

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 14))
                .foregroundStyle(accent)
                .padding(.top, 1)
            Text(text)
                .font(.system(size: 12))
                .foregroundStyle(Color.ftText.opacity(0.8))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .background(accent.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(accent.opacity(0.2), lineWidth: 1)
        )
    }
}

// MARK: - Flow Arrow

struct FlowArrow: View {
    var label: String = ""
    var accent: Color = .ftTextDimmer

    var body: some View {
        VStack(spacing: 2) {
            if !label.isEmpty {
                Text(label)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(Color.ftTextDimmer)
                    .textCase(.uppercase)
                    .tracking(1)
            }
            Image(systemName: "arrow.down")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(accent)
        }
        .frame(maxWidth: .infinity)
    }
}
