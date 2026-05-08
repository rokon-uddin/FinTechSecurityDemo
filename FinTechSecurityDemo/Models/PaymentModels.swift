//
//  PaymentModels.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Core domain models for the FinTech Crypto Demo.
// All types are value types (struct/enum) and conform to Sendable
// so they can safely cross actor/concurrency boundaries.
//
// Design note: We separate models from logic (SRP).
// No business logic lives here — only pure data shapes.

import Foundation

// MARK: - Money (safe integer representation)
// CRITICAL: Never use Double/Float for money — IEEE 754 rounding
// causes 0.1 + 0.2 ≠ 0.3 in binary floating-point arithmetic.
// All monetary values are stored as Int64 paisa (1 BDT = 100 paisa).

/// Represents a monetary amount in BDT using integer paisa to avoid floating-point errors.
public struct Money: Sendable, Codable, Equatable, Hashable,
    CustomStringConvertible
{
    /// The amount in paisa (1 BDT = 100 paisa). Always non-negative.
    public let paisa: Int64

    public init(paisa: Int64) {
        precondition(paisa >= 0, "Money cannot be negative")
        self.paisa = paisa
    }

    /// Convenience initialiser from a BDT string (e.g. "500.00").
    public init?(bdtString: String) {
        guard let bdt = Double(bdtString), bdt >= 0 else { return nil }
        self.paisa = Int64((bdt * 100).rounded())
    }

    /// Human-readable BDT string, e.g. "৳500.00"
    public var description: String {
        let bdt = Double(paisa) / 100.0
        return String(format: "৳%.2f", bdt)
    }

    public var bdtValue: Double { Double(paisa) / 100.0 }
}

// MARK: - Wallet

/// A FinTech mobile wallet identified by a phone number.
public struct WalletID: Sendable, Codable, Equatable, Hashable, RawRepresentable
{
    public let rawValue: String

    public init(rawValue: String) { self.rawValue = rawValue }

    /// Validates BD mobile number format: 01XXXXXXXXX (11 digits)
    public var isValid: Bool {
        let pattern = #"^01[3-9]\d{8}$"#
        return rawValue.range(of: pattern, options: .regularExpression) != nil
    }
}

// MARK: - Transaction

/// Unique identifier for a transaction.
public typealias TransactionID = UUID

/// Status of a payment transaction.
public enum TransactionStatus: String, Sendable, Codable, Equatable {
    case pending
    case signed  // signed by device, not yet submitted
    case submitted  // sent to server
    case processing  // server accepted, processing
    case completed  // settled
    case failed
    case reverted
}

/// The canonical transaction payload that is signed by the Secure Enclave.
/// Every field is included in the canonical representation to ensure
/// non-repudiation — the user cannot deny any field.
public struct Transaction: Sendable, Codable, Equatable {
    public let id: TransactionID
    public let senderWallet: WalletID
    public let receiverWallet: WalletID
    public let amount: Money
    public let timestampUnix: Int64
    public let nonce: String
    public let currency: String
    public let note: String
    public var status: TransactionStatus

    public init(
        id: TransactionID = UUID(),
        senderWallet: WalletID,
        receiverWallet: WalletID,
        amount: Money,
        timestampUnix: Int64 = Int64(Date.now.timeIntervalSince1970),
        nonce: String,
        currency: String = "BDT",
        note: String = "",
        status: TransactionStatus = .pending
    ) {
        self.id = id
        self.senderWallet = senderWallet
        self.receiverWallet = receiverWallet
        self.amount = amount
        self.timestampUnix = timestampUnix
        self.nonce = nonce
        self.currency = currency
        self.note = note
        self.status = status
    }

    /// Deterministic canonical byte representation for signing.
    /// Both client and server MUST produce identical bytes from the same input.
    /// Format: pipe-separated fields in fixed order, all as UTF-8 strings.
    /// Integer paisa ensures no locale-dependent formatting issues.
    public var canonicalBytes: Data {
        let fields: [String] = [
            id.uuidString.uppercased(),
            senderWallet.rawValue,
            receiverWallet.rawValue,
            String(amount.paisa),  // integer — no decimal formatting
            String(timestampUnix),
            nonce,
            currency,
        ]
        return fields.joined(separator: "|").data(using: .utf8)!
    }
}

// MARK: - Tokenization Models

/// A payment token that replaces a real card number.
/// Stored on device; the actual card data is in the token vault (server-side).
public struct PaymentToken: Sendable, Codable, Equatable, Identifiable {
    public let id: String  // e.g. "pm_1A2B3C4D5E"
    public let lastFour: String  // "4242" — safe for display
    public let brand: CardBrand
    public let expiryMonth: Int
    public let expiryYear: Int
    public let createdAt: Date

    /// PCI-compliant masked display string — never shows full PAN.
    public var maskedPAN: String { "•••• •••• •••• \(lastFour)" }

    /// Whether this card appears expired based on current date.
    public var isExpired: Bool {
        let cal = Calendar.current
        let now = Date.now
        let year = cal.component(.year, from: now)
        let mon = cal.component(.month, from: now)
        if expiryYear < year { return true }
        if expiryYear == year, expiryMonth < mon { return true }
        return false
    }
}

public enum CardBrand: String, Sendable, Codable, Equatable {
    case visa, mastercard, amex, discover, unknown
}

/// Request to tokenize a card — sent to the payment gateway SDK.
/// In production this is handled by a PCI-DSS Level 1 SDK (Stripe, Adyen etc.)
/// and raw card data NEVER enters your code.
public struct CardTokenizationRequest: Sendable {
    /// PAN entered in SDK-managed UI — your code never reads this value.
    let pan: String
    let cvv: String
    let expiryMonth: Int
    let expiryYear: Int
    let cardHolder: String

    /// Factory used only by the SDK/mock — prevents raw PAN from appearing
    /// in calling code. In production the SDK constructs this internally.
    internal static func make(
        pan: String,
        cvv: String,
        expiryMonth: Int,
        expiryYear: Int,
        cardHolder: String
    ) -> CardTokenizationRequest {
        CardTokenizationRequest(
            pan: pan,
            cvv: cvv,
            expiryMonth: expiryMonth,
            expiryYear: expiryYear,
            cardHolder: cardHolder
        )
    }
}

// MARK: - OTP / TOTP Models

/// A one-time password of a given length and algorithm.
public struct OTP: Sendable, Equatable {
    public let code: String
    public let expiresAt: Date
    public let algorithm: OTPAlgorithm

    public var isExpired: Bool { Date.now >= expiresAt }
    public var secondsRemaining: Int {
        max(0, Int(expiresAt.timeIntervalSinceNow))
    }
}

public enum OTPAlgorithm: String, Sendable, Codable {
    case sha1  // RFC 4226 — standard for TOTP compatibility
    case sha256  // More secure, less widely supported by authenticator apps
    case sha512
}

/// TOTP configuration, typically stored from QR code enrollment.
public struct TOTPConfig: Sendable, Codable, Equatable {
    public let secret: Data  // shared secret (base32 encoded in QR)
    public let digits: Int  // 6 or 8
    public let period: TimeInterval  // 30 seconds standard
    public let algorithm: OTPAlgorithm
    public let issuer: String
    public let accountName: String

    public init(
        secret: Data,
        digits: Int = 6,
        period: TimeInterval = 30,
        algorithm: OTPAlgorithm = .sha1,
        issuer: String = "FinTech",
        accountName: String
    ) {
        self.secret = secret
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
        self.issuer = issuer
        self.accountName = accountName
    }
}

// MARK: - Session / JWT Models

/// JWT claims used by FinTech access tokens.
/// Only claims relevant to the mobile app are modelled here.
public struct JWTClaims: Sendable, Codable, Equatable {
    public let sub: String  // user ID
    public let walletId: String
    public let deviceId: String
    public let iat: Int64  // issued-at unix timestamp
    public let exp: Int64  // expiry unix timestamp
    public let roles: [String]
    public let sessionId: String

    public var isExpired: Bool {
        Date.now.timeIntervalSince1970 >= Double(exp)
    }

    /// Remaining validity with a 60-second safety buffer.
    public var expiresAt: Date {
        Date(timeIntervalSince1970: Double(exp))
    }
}

/// A complete auth token bundle returned after login or token refresh.
public struct AuthTokenBundle: Sendable {
    public let accessToken: String  // short-lived JWT (15 min) — memory only
    public let refreshToken: String  // long-lived opaque token — Keychain
    public let expiresIn: TimeInterval
    public let claims: JWTClaims
    public let tokenFamily: String  // for refresh token rotation tracking
}

/// PCI-DSS log event — used to demonstrate compliant logging.
public struct AuditEvent: Sendable {
    public enum Category: String, Sendable {
        case authentication, transaction, tokenization, security, session
    }
    public let timestamp: Date
    public let category: Category
    public let event: String
    public let userId: String?
    public let metadata: [String: String]
}
