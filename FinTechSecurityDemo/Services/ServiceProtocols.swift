//
//  ServiceProtocols.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Service layer protocols following the Interface Segregation Principle (ISP).
// Each protocol models exactly ONE responsibility.
// Concrete implementations can conform to one or many protocols.
// Test doubles only need to implement the protocol they replace.

import Foundation

// MARK: - Tokenization Service

/// Handles card tokenization — replacing raw card data with a safe token.
/// Conforms to ISP: only card-token operations, no payment processing.
public protocol CardTokenizationServiceProtocol: Sendable {

    /// Tokenize a card via the payment gateway SDK.
    /// - Returns: A `PaymentToken` that replaces the PAN in all future operations.
    /// - Throws: `TokenizationError` if the gateway rejects the card.
    /// - Note: Raw card data (PAN, CVV) must NEVER appear in calling code.
    func tokenize(request: CardTokenizationRequest) async throws -> PaymentToken

    /// Retrieve a stored token by its ID.
    func fetchToken(id: String) async throws -> PaymentToken

    /// Delete a stored token (e.g. on card removal).
    func deleteToken(id: String) async throws

    /// List all stored tokens for the current user.
    func listTokens() async throws -> [PaymentToken]
}

public enum TokenizationError: Error, Equatable {
    case invalidCard(String)
    case gatewayUnavailable
    case tokenNotFound(String)
    case networkError(String)
    case pciViolation(String)   // caller attempted to access raw PAN
}

// MARK: - OTP Service

/// Generates and validates one-time passwords.
/// Separate protocol from TOTP so each can be tested independently (ISP).
public protocol OTPServiceProtocol: Sendable {

    /// Generate an SMS-style OTP for the given wallet.
    func generateOTP(for wallet: WalletID) async throws -> OTP

    /// Validate an OTP code for the given wallet.
    /// - Returns: `true` if the code is valid and not yet expired/used.
    func validateOTP(code: String, for wallet: WalletID) async throws -> Bool
}

public protocol TOTPServiceProtocol: Sendable {

    /// Generate the current TOTP code from the given configuration.
    func generate(config: TOTPConfig, at date: Date) -> String

    /// Validate a TOTP code allowing ±1 window for clock skew.
    /// - Returns: `true` if the code matches any adjacent window.
    func validate(code: String, config: TOTPConfig, at date: Date) -> Bool

    /// Seconds remaining in the current time window.
    func secondsRemaining(config: TOTPConfig, at date: Date) -> Int

    /// Generate the `otpauth://` enrollment URI for QR code display.
    func enrollmentURI(config: TOTPConfig) -> URL?
}

public enum OTPError: Error, Equatable {
    case expired
    case alreadyUsed
    case invalidCode
    case tooManyAttempts
    case walletNotFound
}

// MARK: - Transaction Signing Service

/// Signs transactions using the device's hardware key (Secure Enclave on device,
/// software P-256 on Simulator). Separate from payment submission (ISP).
public protocol TransactionSigningServiceProtocol: Sendable {

    /// Returns `true` if a signing key is registered for this device.
    var hasRegisteredKey: Bool { get async }

    /// Register a new signing key pair. Uploads public key to server.
    /// On real device: generates key in Secure Enclave, gated by biometrics.
    func registerKey() async throws -> Data     // returns public key bytes

    /// Sign the canonical bytes of a transaction.
    /// On real device: triggers Face ID / Touch ID.
    /// - Returns: DER-encoded ECDSA P-256 signature.
    func sign(transaction: Transaction) async throws -> Data

    /// Delete the signing key (on logout or account deletion).
    func deleteKey() async throws
    func keyInfo() async -> SigningKeyInfo?
}

/// Verifies transaction signatures — used by both client (audit) and server.
public protocol TransactionVerificationServiceProtocol: Sendable {

    /// Verify a DER-encoded ECDSA P-256 signature against the transaction.
    func verify(
        transaction: Transaction,
        signatureDER: Data,
        publicKeyRaw: Data
    ) throws -> Bool
}

public enum SigningError: Error, Equatable {
    case noKeyRegistered
    case biometricFailed(String)
    case keyGenerationFailed(String)
    case signatureFailed(String)
    case verificationFailed(String)
}

// MARK: - Session Management Service

/// Manages authentication sessions, JWT tokens, and token refresh.
/// Isolated actor — all state mutations are serialised.
public protocol SessionServiceProtocol: Actor {

    /// Login with wallet credentials, returns a full token bundle.
    func login(wallet: WalletID, pin: String) async throws -> AuthTokenBundle

    /// Returns a valid access token, transparently refreshing if expired.
    func validAccessToken() async throws -> String

    /// Returns the decoded claims of the current access token, or nil if not logged in.
    var currentClaims: JWTClaims? { get async }

    /// Whether a valid session exists.
    var isAuthenticated: Bool { get async }

    /// Clear all session state and tokens (logout).
    func logout() async

    /// Step-up authentication for high-value transactions.
    /// Returns a short-lived (2-minute) transaction authorization token.
    func requestTransactionAuthToken(for transaction: Transaction) async throws -> String
}

public enum SessionError: Error, Equatable {
    case invalidCredentials
    case sessionExpired
    case refreshFailed(String)
    case biometricRequired
    case deviceNotRegistered
    case stepUpRequired       // transaction requires additional auth
}

// MARK: - Secure Storage Service

/// Abstracts Keychain storage. Separate from business logic (SRP / ISP).
public protocol SecureStorageProtocol: Sendable {

    func save(_ value: Data, forKey key: String) throws
    func load(forKey key: String) throws -> Data
    func delete(forKey key: String) throws
    func exists(forKey key: String) -> Bool
}

public enum SecureStorageError: Error, Equatable {
    case itemNotFound(String)
    case saveFailed(String)
    case deleteFailed(String)
}

// MARK: - Audit Logging Service

/// PCI-DSS Req 10: all access to CHD must be logged.
/// Never logs raw CHD — only events and metadata.
public protocol AuditLogServiceProtocol: Sendable {

    /// Log a security or compliance event.
    /// - Important: NEVER pass PAN, CVV, PIN, or OTP as metadata values.
    func log(
        category: AuditEvent.Category,
        event: String,
        userId: String?,
        metadata: [String: String]
    )

    /// Retrieve recent audit events (for in-app audit display).
    func recentEvents(limit: Int) -> [AuditEvent]
}

// MARK: - Nonce Service

/// Issues and validates single-use nonces to prevent replay attacks.
public protocol NonceServiceProtocol: Sendable {

    /// Issue a fresh nonce. Valid for `ttl` seconds.
    func issue(ttl: TimeInterval) -> String

    /// Consume a nonce — returns false if already used or expired.
    /// Consuming marks the nonce as used; subsequent calls return false.
    func consume(_ nonce: String) -> Bool
}
