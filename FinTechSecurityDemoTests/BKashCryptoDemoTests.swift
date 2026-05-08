//
//  FinTechCryptoDemoTests.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Swift Testing framework (Swift 5.9+ / Xcode 16+) test suite.
// Uses @Test, @Suite, #expect, #require, and withKnownIssue.
//
// Coverage:
//   • Money model (edge cases)
//   • TOTPService (RFC 6238 algorithm)
//   • OTPService (lifecycle, lockout, replay prevention)
//   • TokenizationService (happy path, error paths, PCI audit)
//   • TransactionSigningService (key lifecycle, sign/verify, tamper detection)
//   • SessionService (login, refresh, rotation, step-up, concurrent access)
//   • JWTDecoder (decode, expiry)
//   • NonceService (issue, consume, replay prevention)
//
// Each test is independent — no shared mutable state between tests.

import Testing
import Foundation
import CryptoKit

@testable import FinTechSecurityDemo

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Money Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("Money — Integer Paisa Representation")
struct MoneyTests {

    @Test("Initialise from BDT string")
    func initFromBDTString() {
        let money = Money(bdtString: "500.00")
        #expect(money != nil)
        #expect(money?.paisa == 50_000)
    }

    @Test("BDT string with fractional paisa rounds correctly")
    func fractionalRounding() {
        // 100.005 BDT → should round to 10001 paisa (nearest)
        let money = Money(bdtString: "100.005")
        #expect(money != nil)
        #expect(money?.paisa == 10_001)
    }

    @Test("Display string formats correctly")
    func displayString() {
        let money = Money(paisa: 50_000)
        #expect(money.description == "৳500.00")
    }

    @Test("Zero amount is valid")
    func zeroAmount() {
        let money = Money(paisa: 0)
        #expect(money.paisa == 0)
    }

    @Test("Invalid BDT string returns nil")
    func invalidString() {
        #expect(Money(bdtString: "abc") == nil)
        #expect(Money(bdtString: "-100") == nil)
        #expect(Money(bdtString: "") == nil)
    }

    @Test("Large amounts handled correctly")
    func largeAmount() {
        // 1,000,000 BDT = 100,000,000 paisa — within Int64 range
        let money = Money(bdtString: "1000000.00")
        #expect(money?.paisa == 100_000_000)
    }

    @Test("Canonical bytes are deterministic for identical transactions")
    func canonicalBytesAreDeterministic() {
        let wallet1 = WalletID(rawValue: "01800000001")
        let wallet2 = WalletID(rawValue: "01555000001")
        let nonce   = "test-nonce-123"

        let tx1 = Transaction(
            senderWallet:   wallet1,
            receiverWallet: wallet2,
            amount:         Money(paisa: 50_000),
            timestampUnix:  1_700_000_000,
            nonce:          nonce
        )
        let tx2 = Transaction(
            id:             tx1.id,   // same ID
            senderWallet:   wallet1,
            receiverWallet: wallet2,
            amount:         Money(paisa: 50_000),
            timestampUnix:  1_700_000_000,
            nonce:          nonce
        )
        #expect(tx1.canonicalBytes == tx2.canonicalBytes)
    }

    @Test("Different amounts produce different canonical bytes")
    func differentAmountsDifferentBytes() {
        let w = WalletID(rawValue: "01800000001")
        let id = UUID()
        let tx1 = Transaction(id: id, senderWallet: w, receiverWallet: w,
                               amount: Money(paisa: 100_00), timestampUnix: 1_700_000_000, nonce: "n")
        let tx2 = Transaction(id: id, senderWallet: w, receiverWallet: w,
                               amount: Money(paisa: 999_00), timestampUnix: 1_700_000_000, nonce: "n")
        #expect(tx1.canonicalBytes != tx2.canonicalBytes)
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: TOTP Service Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("TOTPService — RFC 6238 Implementation")
struct TOTPServiceTests {

    private let service = TOTPService()

    /// RFC 6238 Appendix B test vectors (SHA-1, 8-digit TOTP)
    /// These are the official test cases from the RFC.
    @Test("RFC 6238 SHA-1 test vectors", arguments: [
        // (unix_time, expected_totp)
        (59,          "94287082"),
        (1111111109,  "07081804"),
        (1111111111,  "14050471"),
        (1234567890,  "89005924"),
        (2000000000,  "69279037"),
        (20000000000, "65353130")
    ])
    func rfc6238SHA1TestVectors(unixTime: Int, expectedCode: String) throws {
        // RFC 6238 uses a fixed 20-byte secret: "12345678901234567890"
        let secretString = "12345678901234567890"
        let secret = Data(secretString.utf8)

        let config = TOTPConfig(
            secret:      secret,
            digits:      8,
            period:      30,
            algorithm:   .sha1,
            accountName: "test"
        )

        let date = Date(timeIntervalSince1970: TimeInterval(unixTime))
        let code = service.generate(config: config, at: date)

        #expect(code == expectedCode,
                "Unix time \(unixTime): expected \(expectedCode), got \(code)")
    }

    @Test("TOTP generates 6-digit code by default")
    func generates6Digits() {
        let config = makeTOTPConfig(digits: 6)
        let code   = service.generate(config: config, at: Date())
        #expect(code.count == 6)
        #expect(code.allSatisfy(\.isNumber))
    }

    @Test("TOTP generates 8-digit code when configured")
    func generates8Digits() {
        let config = makeTOTPConfig(digits: 8)
        let code   = service.generate(config: config, at: Date())
        #expect(code.count == 8)
    }

    @Test("Same time window produces same code")
    func sameWindowSameCode() {
        let config = makeTOTPConfig()
        let t1     = Date(timeIntervalSinceNow: 5)   // 5 seconds from now (same window)
        let t2     = Date(timeIntervalSinceNow: 10)  // 10 seconds from now (same window)
        #expect(service.generate(config: config, at: t1) ==
                service.generate(config: config, at: t2))
    }

    @Test("Different windows produce different codes (probabilistically)")
    func differentWindowsDifferentCodes() {
        let config = makeTOTPConfig()
        let t1 = Date(timeIntervalSince1970: 0)    // window 0
        let t2 = Date(timeIntervalSince1970: 30)   // window 1
        // There's a ~1/1_000_000 chance these match by coincidence — acceptable for tests
        #expect(service.generate(config: config, at: t1) !=
                service.generate(config: config, at: t2))
    }

    @Test("Validation succeeds for current window")
    func validateCurrentWindow() {
        let config = makeTOTPConfig()
        let date   = Date()
        let code   = service.generate(config: config, at: date)
        #expect(service.validate(code: code, config: config, at: date) == true)
    }

    @Test("Validation succeeds for previous window (clock skew)")
    func validatePreviousWindow() {
        let config   = makeTOTPConfig()
        let previous = Date().addingTimeInterval(-29)   // 29s ago — previous window
        let code     = service.generate(config: config, at: previous)
        // Current time is in the next window; validation should still accept previous
        #expect(service.validate(code: code, config: config, at: Date()) == true)
    }

    @Test("Validation fails for code two windows ago")
    func rejectTwoWindowsOld() {
        let config  = makeTOTPConfig()
        let old     = Date().addingTimeInterval(-61)   // >60s ago — two windows back
        let oldCode = service.generate(config: config, at: old)
        #expect(service.validate(code: oldCode, config: config, at: Date()) == false)
    }

    @Test("Validation rejects wrong code")
    func rejectWrongCode() {
        let config = makeTOTPConfig()
        #expect(service.validate(code: "000000", config: config, at: Date()) == false)
    }

    @Test("Seconds remaining is in 1–30 range")
    func secondsRemainingRange() {
        let config = makeTOTPConfig()
        let secs   = service.secondsRemaining(config: config, at: Date())
        #expect(secs >= 1)
        #expect(secs <= 30)
    }

    @Test("Enrollment URI has correct scheme")
    func enrollmentURIScheme() throws {
        let config = makeTOTPConfig(accountName: "01800000001")
        let url    = try #require(service.enrollmentURI(config: config))
        #expect(url.scheme == "otpauth")
        #expect(url.host == "totp")
        #expect(url.absoluteString.contains("FinTech"))
        #expect(url.absoluteString.contains("period=30"))
        #expect(url.absoluteString.contains("digits=6"))
    }

    @Test("HOTP core produces consistent results", arguments: [
        // (counter, expected 6-digit HOTP with known secret)
        (UInt64(0), 6),  // just check length
        (UInt64(1), 6),
        (UInt64(999999), 6)
    ])
    func hotpCoreLength(counter: UInt64, expectedLen: Int) {
        let secret = Data("12345678901234567890".utf8)
        let result = service.hotp(secret: secret, counter: counter, digits: 6, algorithm: .sha1)
        #expect(result.count == expectedLen)
        #expect(result.allSatisfy(\.isNumber))
    }

    // MARK: - Helpers
    private func makeTOTPConfig(digits: Int = 6, accountName: String = "test") -> TOTPConfig {
        var bytes = [UInt8](repeating: 0, count: 20)
        SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return TOTPConfig(secret: Data(bytes), digits: digits, period: 30,
                          algorithm: .sha1, accountName: accountName)
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: OTP Service Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("OTPService — SMS OTP Lifecycle")
struct OTPServiceTests {

    private func makeService() -> OTPService {
        OTPService(
            nonceService: NonceService(),
            auditLog:     AuditLogService(),
            maxAttempts:  3
        )
    }

    @Test("Generate OTP for valid wallet")
    func generateOTPForValidWallet() async throws {
        let service = makeService()
        let wallet  = WalletID(rawValue: "01800000001")
        let otp     = try await service.generateOTP(for: wallet)

        #expect(otp.code.count == 6)
        #expect(otp.code.allSatisfy(\.isNumber))
        #expect(!otp.isExpired)
        #expect(otp.secondsRemaining > 0)
    }

    @Test("Generate OTP for invalid wallet throws walletNotFound")
    func generateOTPInvalidWallet() async throws {
        let service = makeService()
        let wallet  = WalletID(rawValue: "99999")   // invalid format
        await #expect(throws: OTPError.walletNotFound) {
            try await service.generateOTP(for: wallet)
        }
    }

    @Test("Valid OTP code passes validation")
    func validateCorrectOTP() async throws {
        let service = makeService()
        let wallet  = WalletID(rawValue: "01800000001")
        let otp     = try await service.generateOTP(for: wallet)
        let result  = try await service.validateOTP(code: otp.code, for: wallet)
        #expect(result == true)
    }

    @Test("Wrong OTP code fails validation")
    func validateWrongOTP() async throws {
        let service = makeService()
        let wallet  = WalletID(rawValue: "01800000001")
        _           = try await service.generateOTP(for: wallet)
        let result  = try await service.validateOTP(code: "000000", for: wallet)
        #expect(result == false)
    }

    @Test("OTP is single-use — reuse throws alreadyUsed")
    func otpIsSingleUse() async throws {
        let service = makeService()
        let wallet  = WalletID(rawValue: "01800000001")
        let otp     = try await service.generateOTP(for: wallet)

        // First use: succeeds
        let first = try await service.validateOTP(code: otp.code, for: wallet)
        #expect(first == true)

        // Second use with same code: throws alreadyUsed
        await #expect(throws: OTPError.alreadyUsed) {
            try await service.validateOTP(code: otp.code, for: wallet)
        }
    }

    @Test("Too many wrong attempts triggers lockout")
    func lockoutAfterMaxAttempts() async throws {
        let service = makeService()
        let wallet  = WalletID(rawValue: "01800000001")
        _           = try await service.generateOTP(for: wallet)

        // 3 wrong attempts
        for _ in 0..<3 {
            _ = try? await service.validateOTP(code: "000000", for: wallet)
        }

        // 4th attempt should throw tooManyAttempts
        await #expect(throws: OTPError.tooManyAttempts) {
            try await service.validateOTP(code: "000000", for: wallet)
        }
    }

    @Test("OTP codes are cryptographically random (statistically)")
    func otpCodesAreRandom() async throws {
        let service = makeService()
        let wallet  = WalletID(rawValue: "01800000001")

        // Generate many codes and check they're not all the same
        var codes = Set<String>()
        for _ in 0..<10 {
            let otp = try await service.generateOTP(for: wallet)
            codes.insert(otp.code)
        }
        // With 10 random 6-digit codes, all 10 unique is statistically expected
        // (collision probability ≈ 10/1_000_000 per pair)
        #expect(codes.count > 5,
                "Expected mostly unique codes from CSPRNG, got only \(codes.count)")
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Nonce Service Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("NonceService — Replay Attack Prevention")
struct NonceServiceTests {

    private let service = NonceService()

    @Test("Issued nonce is consumed successfully on first use")
    func issueAndConsume() {
        let nonce = service.issue(ttl: 60)
        #expect(service.consume(nonce) == true)
    }

    @Test("Nonce cannot be consumed twice (anti-replay)")
    func cannotConsumeTwice() {
        let nonce = service.issue(ttl: 60)
        #expect(service.consume(nonce) == true)
        #expect(service.consume(nonce) == false)   // replay attempt rejected
    }

    @Test("Unknown nonce returns false")
    func unknownNonce() {
        #expect(service.consume("not-a-valid-nonce") == false)
    }

    @Test("Each issued nonce is unique (statistically)")
    func noncesAreUnique() {
        let nonces = (0..<100).map { _ in service.issue(ttl: 60) }
        let unique = Set(nonces)
        #expect(unique.count == 100, "All 100 nonces should be unique")
    }

    @Test("Nonce format is URL-safe (no +, /, or =)")
    func nonceIsURLSafe() {
        let nonce = service.issue(ttl: 60)
        #expect(!nonce.contains("+"))
        #expect(!nonce.contains("/"))
        #expect(!nonce.contains("="))
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Tokenization Service Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("TokenizationService — PCI-DSS Card Tokenization")
struct TokenizationServiceTests {

    private func makeService() -> TokenizationService {
        TokenizationService(
            storage:  InMemorySecureStorage(),
            auditLog: AuditLogService(),
            gateway:  MockTokenizationGateway()
        )
    }

    @Test("Tokenize a Visa card returns a valid token")
    func tokenizeVisaCard() async throws {
        let service = makeService()
        let request = CardTokenizationRequest.make(
            pan: "4242424242424242", cvv: "123",
            expiryMonth: 12, expiryYear: 2027, cardHolder: "TEST USER"
        )
        let token = try await service.tokenize(request: request)

        #expect(token.id.hasPrefix("pm_"))
        #expect(token.lastFour == "4242")
        #expect(token.brand == .visa)
        #expect(token.expiryMonth == 12)
        #expect(token.expiryYear == 2027)
        #expect(!token.isExpired)
    }

    @Test("Token ID does not contain PAN")
    func tokenDoesNotContainPAN() async throws {
        let service = makeService()
        let pan     = "4111111111111111"
        let request = CardTokenizationRequest.make(
            pan: pan, cvv: "123",
            expiryMonth: 1, expiryYear: 2028, cardHolder: "TEST"
        )
        let token = try await service.tokenize(request: request)

        // The token itself must not contain the PAN
        #expect(!token.id.contains(pan))
        // Masked PAN should only show last 4 digits
        #expect(token.maskedPAN == "•••• •••• •••• 1111")
        #expect(!token.maskedPAN.contains("4111"))
    }

    @Test("Tokenize Mastercard identifies brand correctly")
    func tokenizeMastercard() async throws {
        let service = makeService()
        let request = CardTokenizationRequest.make(
            pan: "5500000000000004", cvv: "123",
            expiryMonth: 6, expiryYear: 2026, cardHolder: "TEST"
        )
        let token = try await service.tokenize(request: request)
        #expect(token.brand == .mastercard)
    }

    @Test("Invalid PAN throws invalidCard error")
    func invalidPANThrows() async throws {
        let service = makeService()
        let request = CardTokenizationRequest.make(
            pan: "not-a-number", cvv: "123",
            expiryMonth: 12, expiryYear: 2027, cardHolder: "TEST"
        )
        await #expect(throws: TokenizationError.self) {
            try await service.tokenize(request: request)
        }
    }

    @Test("Token persists across service instances (via shared storage)")
    func tokenPersists() async throws {
        let storage  = InMemorySecureStorage()
        let auditLog = AuditLogService()
        let service1 = TokenizationService(
            storage: storage, auditLog: auditLog, gateway: MockTokenizationGateway()
        )
        let service2 = TokenizationService(
            storage: storage, auditLog: auditLog, gateway: MockTokenizationGateway()
        )

        let request = CardTokenizationRequest.make(
            pan: "4242424242424242", cvv: "123",
            expiryMonth: 12, expiryYear: 2027, cardHolder: "TEST"
        )
        let token    = try await service1.tokenize(request: request)
        let fetched  = try await service2.fetchToken(id: token.id)

        #expect(fetched.id == token.id)
        #expect(fetched.lastFour == token.lastFour)
    }

    @Test("Deleted token cannot be fetched")
    func deletedTokenNotFetchable() async throws {
        let service = makeService()
        let request = CardTokenizationRequest.make(
            pan: "4242424242424242", cvv: "123",
            expiryMonth: 12, expiryYear: 2027, cardHolder: "TEST"
        )
        let token = try await service.tokenize(request: request)
        try await service.deleteToken(id: token.id)

        await #expect(throws: TokenizationError.self) {
            try await service.fetchToken(id: token.id)
        }
    }

    @Test("Audit log records tokenization event without PAN")
    func auditLogDoesNotContainPAN() async throws {
        let auditLog = AuditLogService()
        let service  = TokenizationService(
            storage:  InMemorySecureStorage(),
            auditLog: auditLog,
            gateway:  MockTokenizationGateway()
        )
        let pan     = "4242424242424242"
        let request = CardTokenizationRequest.make(
            pan: pan, cvv: "123", expiryMonth: 12, expiryYear: 2027, cardHolder: "TEST"
        )
        _ = try await service.tokenize(request: request)

        let events   = auditLog.recentEvents(limit: 10)
        let logText  = events.flatMap { [$0.event] + $0.metadata.values }.joined()

        // PAN must NEVER appear in audit log (PCI Req 10)
        #expect(!logText.contains(pan),
                "PAN found in audit log — PCI violation!")
        // But the event should be recorded
        #expect(events.contains(where: { $0.event.contains("tokenized") }))
    }

    @Test("List tokens returns all stored tokens")
    func listTokens() async throws {
        let service = makeService()
        let pans    = ["4242424242424242", "5500000000000004"]

        for pan in pans {
            let req = CardTokenizationRequest.make(
                pan: pan, cvv: "123", expiryMonth: 12, expiryYear: 2027, cardHolder: "TEST"
            )
            _ = try await service.tokenize(request: req)
        }

        let tokens = try await service.listTokens()
        #expect(tokens.count == 2)
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Transaction Signing / Verification Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("TransactionSigningService — ECDSA P-256")
struct TransactionSigningTests {

    private func makeServices() -> (
        signing:      TransactionSigningService,
        verification: TransactionVerificationService
    ) {
        let storage  = InMemorySecureStorage()
        let auditLog = AuditLogService()
        return (
            TransactionSigningService(storage: storage, auditLog: auditLog),
            TransactionVerificationService()
        )
    }

    private func makeTransaction() -> Transaction {
        Transaction(
            senderWallet:   WalletID(rawValue: "01800000001"),
            receiverWallet: WalletID(rawValue: "01555000001"),
            amount:         Money(paisa: 250_000),
            timestampUnix:  1_700_000_000,
            nonce:          "test-nonce-abc123"
        )
    }

    @Test("Register key returns non-empty public key data")
    func registerKeyReturnsPublicKey() async throws {
        let (signing, _) = makeServices()
        let pubKey = try await signing.registerKey()
        #expect(!pubKey.isEmpty)
        // P-256 uncompressed public key = 65 bytes (0x04 || 32-byte x || 32-byte y)
        #expect(pubKey.count == 64,   // rawRepresentation is 64 bytes (without 0x04 prefix)
                "Expected 64-byte raw P-256 public key, got \(pubKey.count) bytes")
    }

    @Test("Has registered key after registerKey()")
    func hasKeyAfterRegistration() async throws {
        let (signing, _) = makeServices()
        #expect(await signing.hasRegisteredKey == false)
        _ = try await signing.registerKey()
        #expect(await signing.hasRegisteredKey == true)
    }

    @Test("Sign returns non-empty DER signature")
    func signReturnsSignature() async throws {
        let (signing, _) = makeServices()
        _ = try await signing.registerKey()
        let tx  = makeTransaction()
        let sig = try await signing.sign(transaction: tx)
        #expect(!sig.isEmpty)
        // DER-encoded ECDSA P-256 signature is typically 70-72 bytes
        #expect(sig.count >= 64)
        #expect(sig.count <= 80)
    }

    @Test("Verification succeeds for valid signature")
    func verificationSucceeds() async throws {
        let (signing, verification) = makeServices()
        let pubKey = try await signing.registerKey()
        let tx     = makeTransaction()
        let sig    = try await signing.sign(transaction: tx)

        let isValid = try verification.verify(
            transaction:  tx,
            signatureDER: sig,
            publicKeyRaw: pubKey
        )
        #expect(isValid == true)
    }

    @Test("Verification fails if transaction is tampered")
    func verificationFailsForTamperedTransaction() async throws {
        let (signing, verification) = makeServices()
        let pubKey = try await signing.registerKey()
        let tx     = makeTransaction()
        let sig    = try await signing.sign(transaction: tx)

        // Tamper: create a transaction with a different amount (same ID/nonce)
        let tampered = Transaction(
            id:             tx.id,
            senderWallet:   tx.senderWallet,
            receiverWallet: tx.receiverWallet,
            amount:         Money(paisa: 999_999_99),  // attacker changed amount!
            timestampUnix:  tx.timestampUnix,
            nonce:          tx.nonce
        )

        let isValid = try verification.verify(
            transaction:  tampered,
            signatureDER: sig,
            publicKeyRaw: pubKey
        )
        #expect(isValid == false)
    }

    @Test("Verification fails with wrong public key")
    func verificationFailsWithWrongKey() async throws {
        let (signing, verification) = makeServices()
        _ = try await signing.registerKey()
        let tx  = makeTransaction()
        let sig = try await signing.sign(transaction: tx)

        // Generate a completely different P-256 key pair
        let wrongKey = P256.Signing.PrivateKey().publicKey.rawRepresentation

        let isValid = try verification.verify(
            transaction:  tx,
            signatureDER: sig,
            publicKeyRaw: wrongKey
        )
        #expect(isValid == false)
    }

    @Test("Signing without registered key throws noKeyRegistered")
    func signWithoutKeyThrows() async throws {
        let (signing, _) = makeServices()
        let tx = makeTransaction()
        await #expect(throws: SigningError.noKeyRegistered) {
            try await signing.sign(transaction: tx)
        }
    }

    @Test("Delete key removes registration")
    func deleteKeyRemovesRegistration() async throws {
        let (signing, _) = makeServices()
        _ = try await signing.registerKey()
        #expect(await signing.hasRegisteredKey == true)
        try await signing.deleteKey()
        #expect(await signing.hasRegisteredKey == false)
    }

    @Test("Verification rejects malformed DER signature")
    func verificationRejectsMalformedSignature() async throws {
        let (signing, verification) = makeServices()
        let pubKey = try await signing.registerKey()
        let tx     = makeTransaction()

        // Feed random bytes as a "signature"
        let garbage = Data(repeating: 0xAA, count: 72)

        await #expect(throws: SigningError.self) {
            try verification.verify(
                transaction:  tx,
                signatureDER: garbage,
                publicKeyRaw: pubKey
            )
        }
    }

    @Test("Canonical bytes include all transaction fields")
    func canonicalBytesIncludeAllFields() {
        let tx = makeTransaction()
        let canonical = String(data: tx.canonicalBytes, encoding: .utf8)!

        #expect(canonical.contains(tx.id.uuidString.uppercased()))
        #expect(canonical.contains(tx.senderWallet.rawValue))
        #expect(canonical.contains(tx.receiverWallet.rawValue))
        #expect(canonical.contains(String(tx.amount.paisa)))
        #expect(canonical.contains(tx.nonce))
        // Fields separated by pipes
        #expect(canonical.contains("|"))
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Session Service Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("SessionService — JWT Lifecycle & Token Rotation")
struct SessionServiceTests {

    private func makeService() -> SessionService {
        SessionService(
            storage:     InMemorySecureStorage(),
            auditLog:    AuditLogService(),
            authBackend: MockAuthBackend()
        )
    }

    @Test("Login with valid credentials returns token bundle")
    func loginSucceeds() async throws {
        let service = makeService()
        let bundle  = try await service.login(
            wallet: WalletID(rawValue: "01800000001"),
            pin:    "1234"
        )
        #expect(!bundle.accessToken.isEmpty)
        #expect(!bundle.refreshToken.isEmpty)
        #expect(bundle.expiresIn > 0)
        #expect(bundle.claims.sub == "01800000001")
    }

    @Test("Login with invalid credentials throws invalidCredentials")
    func loginFailsWithWrongPin() async throws {
        let service = makeService()
        await #expect(throws: SessionError.invalidCredentials) {
            try await service.login(
                wallet: WalletID(rawValue: "01800000001"),
                pin:    "9999"   // wrong PIN
            )
        }
    }

    @Test("Login with invalid wallet throws invalidCredentials")
    func loginFailsWithInvalidWallet() async throws {
        let service = makeService()
        await #expect(throws: SessionError.invalidCredentials) {
            try await service.login(
                wallet: WalletID(rawValue: "12345"),  // invalid format
                pin:    "1234"
            )
        }
    }

    @Test("isAuthenticated is true after login")
    func isAuthenticatedAfterLogin() async throws {
        let service = makeService()
        #expect(await service.isAuthenticated == false)
        _ = try await service.login(
            wallet: WalletID(rawValue: "01800000001"),
            pin:    "1234"
        )
        #expect(await service.isAuthenticated == true)
    }

    @Test("validAccessToken returns non-empty token after login")
    func validAccessTokenAfterLogin() async throws {
        let service = makeService()
        _ = try await service.login(
            wallet: WalletID(rawValue: "01800000001"),
            pin:    "1234"
        )
        let token = try await service.validAccessToken()
        #expect(!token.isEmpty)
        // JWT format: three dot-separated parts
        #expect(token.split(separator: ".").count == 3)
    }

    @Test("Logout clears session state")
    func logoutClearsSession() async throws {
        let service = makeService()
        _ = try await service.login(
            wallet: WalletID(rawValue: "01800000001"),
            pin:    "1234"
        )
        #expect(await service.isAuthenticated == true)
        await service.logout()
        #expect(await service.isAuthenticated == false)
        #expect(await service.currentClaims == nil)
    }

    @Test("currentClaims contains correct wallet after login")
    func currentClaimsContainWallet() async throws {
        let service = makeService()
        let wallet  = "01800000001"
        _ = try await service.login(
            wallet: WalletID(rawValue: wallet),
            pin:    "1234"
        )
        let claims = await service.currentClaims
        #expect(claims != nil)
        #expect(claims?.walletId == wallet)
    }

    @Test("Concurrent validAccessToken calls do not double-refresh")
    func concurrentTokenRequestsAreSerialised() async throws {
        let service = makeService()
        _ = try await service.login(
            wallet: WalletID(rawValue: "01800000001"),
            pin:    "1234"
        )

        // Fire 10 concurrent requests — all should succeed and return the same token
        let tokens = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<10 {
                group.addTask { try await service.validAccessToken() }
            }
            var results: [String] = []
            for try await token in group { results.append(token) }
            return results
        }

        #expect(tokens.count == 10)
        // All tokens should be identical (same in-memory token)
        let uniqueTokens = Set(tokens)
        #expect(uniqueTokens.count == 1,
                "All concurrent calls should return the same access token")
    }

    @Test("Step-up token is returned for transaction")
    func stepUpTokenReturned() async throws {
        let service = makeService()
        _ = try await service.login(
            wallet: WalletID(rawValue: "01800000001"),
            pin:    "1234"
        )
        let tx = Transaction(
            senderWallet:   WalletID(rawValue: "01800000001"),
            receiverWallet: WalletID(rawValue: "01555000001"),
            amount:         Money(paisa: 100_000),
            nonce:          "test-nonce"
        )
        let authToken = try await service.requestTransactionAuthToken(for: tx)
        #expect(!authToken.isEmpty)
        #expect(authToken.contains("txauth_"))
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: JWT Decoder Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("JWTDecoder — Claims Decoding")
struct JWTDecoderTests {

    @Test("Decode valid mock JWT returns expected claims")
    func decodeMockJWT() throws {
        let now = Int64(Date().timeIntervalSince1970)
        let claims = JWTClaims(
            sub:       "user-123",
            walletId:  "01800000001",
            deviceId:  "device-abc",
            iat:       now,
            exp:       now + 900,
            roles:     ["user"],
            sessionId: "session-xyz"
        )
        let jwt     = JWTDecoder.mockJWT(claims: claims)
        let decoded = try #require(JWTDecoder.decode(jwt))

        #expect(decoded.sub == "user-123")
        #expect(decoded.walletId == "01800000001")
        #expect(decoded.roles == ["user"])
        #expect(!decoded.isExpired)
    }

    @Test("Decode malformed JWT returns nil")
    func decodeMalformedJWT() {
        #expect(JWTDecoder.decode("not.a.jwt.at.all.extra") == nil)
        #expect(JWTDecoder.decode("only-one-part") == nil)
        #expect(JWTDecoder.decode("") == nil)
    }

    @Test("isExpired is true for past expiry")
    func isExpiredForPastExpiry() throws {
        let pastTime = Int64(Date().timeIntervalSince1970) - 3600  // 1 hour ago
        let claims   = JWTClaims(
            sub: "u", walletId: "w", deviceId: "d",
            iat: pastTime - 900,
            exp: pastTime,               // expired 1 hour ago
            roles: [], sessionId: "s"
        )
        #expect(claims.isExpired == true)
    }

    @Test("isExpired is false for future expiry")
    func isExpiredForFutureExpiry() throws {
        let now    = Int64(Date().timeIntervalSince1970)
        let claims = JWTClaims(
            sub: "u", walletId: "w", deviceId: "d",
            iat: now,
            exp: now + 900,              // expires in 15 minutes
            roles: [], sessionId: "s"
        )
        #expect(claims.isExpired == false)
    }

    @Test("JWT has three parts separated by dots")
    func jwtHasThreeParts() {
        let claims = JWTClaims(
            sub: "u", walletId: "w", deviceId: "d",
            iat: 0, exp: 999999999999, roles: [], sessionId: "s"
        )
        let jwt   = JWTDecoder.mockJWT(claims: claims)
        let parts = jwt.split(separator: ".")
        #expect(parts.count == 3)
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: WalletID Validation Tests
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("WalletID — Bangladeshi Mobile Number Validation")
struct WalletIDTests {

    @Test("Valid BD mobile numbers", arguments: [
        "01300000000", "01400000000", "01500000000",
        "01600000000", "01700000000", "01800000000",
        "01900000000", "01912345678"
    ])
    func validNumbers(number: String) {
        #expect(WalletID(rawValue: number).isValid == true,
                "\(number) should be valid")
    }

    @Test("Invalid BD mobile numbers", arguments: [
        "12345",              // too short
        "01200000000",        // 012 prefix — not a valid BD operator
        "99999999999",        // wrong country
        "0180000000a",        // contains letter
        "018000000001",       // too long
        ""                    // empty
    ])
    func invalidNumbers(number: String) {
        #expect(WalletID(rawValue: number).isValid == false,
                "\(number) should be invalid")
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Audit Log Service Tests (PCI-DSS Req 10)
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("AuditLogService — PCI-DSS Req 10 Compliance")
struct AuditLogServiceTests {

    @Test("Logged event is retrievable")
    func logAndRetrieve() {
        let service = AuditLogService()
        service.log(
            category: .transaction,
            event:    "test event",
            userId:   "user-1",
            metadata: ["key": "value"]
        )
        let events = service.recentEvents(limit: 10)
        #expect(events.count == 1)
        #expect(events[0].event == "test event")
        #expect(events[0].userId == "user-1")
    }

    @Test("PAN-like patterns are scrubbed from metadata")
    func panIsScrubbedFromMetadata() {
        let service = AuditLogService()
        service.log(
            category: .tokenization,
            event:    "card processed",
            userId:   nil,
            metadata: ["fullCard": "4242424242424242"]   // should be scrubbed!
        )
        let events  = service.recentEvents(limit: 1)
        let logText = events.flatMap { $0.metadata.values }.joined()

        #expect(!logText.contains("4242424242424242"),
                "PAN should be scrubbed from audit log")
        #expect(logText.contains("PAN_REDACTED"),
                "Scrubbed placeholder should be present")
    }

    @Test("Events are returned most-recent first")
    func eventsReturnedNewestFirst() {
        let service = AuditLogService()
        for i in 1...5 {
            service.log(category: .session, event: "event \(i)", userId: nil, metadata: [:])
        }
        let events = service.recentEvents(limit: 5)
        #expect(events[0].event == "event 5")   // most recent first
        #expect(events[4].event == "event 1")
    }

    @Test("Respects the limit parameter")
    func respectsLimit() {
        let service = AuditLogService()
        for i in 1...20 {
            service.log(category: .session, event: "event \(i)", userId: nil, metadata: [:])
        }
        let limited = service.recentEvents(limit: 5)
        #expect(limited.count == 5)
    }
}
