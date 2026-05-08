//
//  TOTPService.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Implements RFC 6238 (TOTP) built on RFC 4226 (HOTP).
//
// TOTP = HMAC-Based OTP + Time-based counter
// Counter = floor(unix_time / time_step)
// Both client and server independently compute the same counter
// from wall-clock time → no synchronisation messages needed.
//
// Allowed clock skew: ±1 window (±30 seconds by default).
// Server MUST also track used codes within the window to prevent
// replay within the same 30-second period.

import Foundation
import CryptoKit

// MARK: - TOTP Service Implementation

/// Concrete TOTP service.
/// Stateless — all operations derive from the config and current time.
/// Thread-safe: no mutable state.
public final class TOTPService: TOTPServiceProtocol, Sendable {

    // Singleton for convenience; can also be injected via init.
    public static let shared = TOTPService()

    public init() {}

    // MARK: - TOTPServiceProtocol

    /// Generate the TOTP code for the current (or given) time window.
    public func generate(config: TOTPConfig, at date: Date = .now) -> String {
        let counter = timeCounter(for: date, period: config.period)
        return hotp(
            secret:    config.secret,
            counter:   counter,
            digits:    config.digits,
            algorithm: config.algorithm
        )
    }

    /// Validate a code against the current window and ±1 adjacent windows.
    /// This tolerates up to 30 seconds of clock skew between device and server.
    public func validate(code: String, config: TOTPConfig, at date: Date = .now) -> Bool {
        let counter = timeCounter(for: date, period: config.period)

        // Check: previous window, current window, next window
        // Server should also check that code hasn't been used this window (anti-replay).
        let windowsToCheck: [UInt64] = [counter &- 1, counter, counter &+ 1]
        return windowsToCheck.contains { window in
            hotp(
                secret:    config.secret,
                counter:   window,
                digits:    config.digits,
                algorithm: config.algorithm
            ) == code
        }
    }

    /// Returns seconds remaining in the current time window (0–29 for 30s period).
    public func secondsRemaining(config: TOTPConfig, at date: Date = .now) -> Int {
        let elapsed = date.timeIntervalSince1970.truncatingRemainder(dividingBy: config.period)
        return Int(config.period - elapsed)
    }

    /// Builds the standard `otpauth://totp/` URI for QR code generation.
    /// Format defined by Google Authenticator and used by all TOTP apps.
    public func enrollmentURI(config: TOTPConfig) -> URL? {
        let base32Secret = config.secret.base32Encoded()
        let label = "\(config.issuer):\(config.accountName)"
            .addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""

        var components = URLComponents()
        components.scheme = "otpauth"
        components.host   = "totp"
        components.path   = "/\(label)"
        components.queryItems = [
            URLQueryItem(name: "secret",    value: base32Secret),
            URLQueryItem(name: "issuer",    value: config.issuer),
            URLQueryItem(name: "algorithm", value: config.algorithm.rawValue.uppercased()),
            URLQueryItem(name: "digits",    value: String(config.digits)),
            URLQueryItem(name: "period",    value: String(Int(config.period)))
        ]
        return components.url
    }

    // MARK: - HOTP Core (RFC 4226)

    /// HOTP = HMAC-OTP — the building block for TOTP.
    /// counter: for HOTP this is an incrementing counter; for TOTP it's time-derived.
    internal func hotp(
        secret: Data,
        counter: UInt64,
        digits: Int,
        algorithm: OTPAlgorithm
    ) -> String {
        // Step 1: Encode counter as 8-byte big-endian
        var bigEndianCounter = counter.bigEndian
        let counterData = withUnsafeBytes(of: &bigEndianCounter) { Data($0) }

        // Step 2: HMAC with the chosen algorithm
        let key = SymmetricKey(data: secret)
        let hmacData: Data

        switch algorithm {
        case .sha1:
            // SHA-1 is used per RFC 4226 — acceptable for HOTP/TOTP contexts
            // (not for general cryptographic use).
            hmacData = Data(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))
        case .sha256:
            hmacData = Data(HMAC<SHA256>.authenticationCode(for: counterData, using: key))
        case .sha512:
            hmacData = Data(HMAC<SHA512>.authenticationCode(for: counterData, using: key))
        }

        // Step 3: Dynamic truncation (RFC 4226 §5.4)
        // Use the last nibble of the HMAC as the offset into the byte array.
        let offset = Int(hmacData[hmacData.count - 1] & 0x0F)

        // Extract 4 bytes at the offset, masking the high bit (sign bit).
        let binCode: UInt32 =
            (UInt32(hmacData[offset])     & 0x7F) << 24 |
            (UInt32(hmacData[offset + 1]) & 0xFF) << 16 |
            (UInt32(hmacData[offset + 2]) & 0xFF) << 8  |
            (UInt32(hmacData[offset + 3]) & 0xFF)

        // Step 4: Modulo and zero-pad to `digits` characters
        let divisor = UInt32(pow(10.0, Double(digits)))
        let otp     = binCode % divisor
        return String(format: "%0\(digits)d", otp)
    }

    // MARK: - Private helpers

    /// Converts a Date to the TOTP time-step counter.
    private func timeCounter(for date: Date, period: TimeInterval) -> UInt64 {
        UInt64(floor(date.timeIntervalSince1970 / period))
    }
}

// MARK: - OTP Service Implementation (SMS-style)

/// Simulates SMS/voice OTP delivery.
/// In production: calls your SMS gateway (Infobip, Twilio, etc.).
public actor OTPService: OTPServiceProtocol {

    // MARK: Dependencies (injected — DIP)
    private let nonceService: any NonceServiceProtocol
    private let auditLog:     any AuditLogServiceProtocol

    /// In-memory OTP store keyed by wallet. In production: Redis with TTL.
    private var store: [String: StoredOTP] = [:]

    /// Maximum allowed validation attempts before lockout.
    private let maxAttempts: Int

    public init(
        nonceService: any NonceServiceProtocol,
        auditLog:     any AuditLogServiceProtocol,
        maxAttempts:  Int = 3
    ) {
        self.nonceService = nonceService
        self.auditLog     = auditLog
        self.maxAttempts  = maxAttempts
    }

    // MARK: - OTPServiceProtocol

    public func generateOTP(for wallet: WalletID) async throws -> OTP {
        guard await wallet.isValid else {
            throw OTPError.walletNotFound
        }

        // Generate a cryptographically random 6-digit code.
        // Using SecRandomCopyBytes ensures uniform distribution
        // (modulo bias is negligible for 6 digits from 32-bit random).
        var randomBytes: UInt32 = 0
        _ = SecRandomCopyBytes(kSecRandomDefault, 4, &randomBytes)
        let code = String(format: "%06d", randomBytes % 1_000_000)

        let otp = OTP(
            code:      code,
            expiresAt: Date.now.addingTimeInterval(300),  // 5-minute validity
            algorithm: .sha256
        )

        // Store for validation (in production: also send via SMS gateway)
        store[wallet.rawValue] = StoredOTP(
            otp:      otp,
            attempts: 0,
            used:     false
        )

        await auditLog.log(
            category: .authentication,
            event:    "OTP generated",
            userId:   wallet.rawValue,
            metadata: ["expiresAt": otp.expiresAt.description]
            // NOTE: Never log the code itself — that would be a PCI violation
        )

        return otp
    }

    public func validateOTP(code: String, for wallet: WalletID) async throws -> Bool {
        guard var stored = store[wallet.rawValue] else {
            throw OTPError.walletNotFound
        }

        // Enforce attempt limit before checking code (prevents brute force)
        guard stored.attempts < maxAttempts else {
            await auditLog.log(
                category: .security,
                event:    "OTP lockout — too many attempts",
                userId:   wallet.rawValue,
                metadata: ["attempts": String(stored.attempts)]
            )
            throw OTPError.tooManyAttempts
        }

        // Reject already-used OTPs (prevents replay within validity window)
        guard !stored.used else { throw OTPError.alreadyUsed }

        // Reject expired OTPs
        guard await !stored.otp.isExpired else { throw OTPError.expired }

        // Constant-time comparison would be ideal here; Swift's == on String
        // is not guaranteed constant-time, but for 6-digit codes the timing
        // variance is negligible compared to network latency.
        // For production: use a dedicated constant-time compare function.
        stored.attempts += 1
        let isValid = stored.otp.code == code

        if isValid {
            stored.used = true
            await auditLog.log(
                category: .authentication,
                event:    "OTP validated successfully",
                userId:   wallet.rawValue,
                metadata: [:]
            )
        } else {
            await auditLog.log(
                category: .security,
                event:    "OTP validation failed",
                userId:   wallet.rawValue,
                metadata: ["attemptsUsed": String(stored.attempts)]
            )
        }

        store[wallet.rawValue] = stored
        return isValid
    }

    // MARK: - Private

    private struct StoredOTP {
        var otp:      OTP
        var attempts: Int
        var used:     Bool
    }
}

// MARK: - Base32 Encoding (RFC 4648 — required for otpauth:// URIs)

private extension Data {
    /// Encodes data as Base32 per RFC 4648 §6 (used in TOTP QR codes).
    func base32Encoded() -> String {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var result = ""
        var buffer: Int = 0
        var bitsLeft: Int = 0

        for byte in self {
            buffer = (buffer << 8) | Int(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                bitsLeft -= 5
                let index = (buffer >> bitsLeft) & 0x1F
                result.append(alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)])
            }
        }
        // Padding
        if bitsLeft > 0 {
            buffer <<= (5 - bitsLeft)
            let index = buffer & 0x1F
            result.append(alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)])
        }
        while result.count % 8 != 0 { result.append("=") }
        return result
    }
}
