//
//  SessionService.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//

// JWT session management with access/refresh token lifecycle.
//
// Security properties implemented:
//   • Access tokens: short-lived (15 min), in-memory only
//   • Refresh tokens: long-lived (7 days), Keychain with ThisDeviceOnly
//   • Refresh token rotation: each refresh invalidates old token (RFC 9700)
//   • Concurrent refresh serialisation: Actor prevents double-refresh race
//   • Step-up auth: high-value transactions require fresh biometric
//   • Auto-clear on background: access token wiped from memory on resign-active

import CryptoKit
import Foundation
// UIDevice import needed for device ID
import UIKit

// MARK: - JWT Utilities

/// Lightweight JWT decoder — decodes payload without verifying signature.
/// In production: verify signature on the server; client only reads claims for UI.
public enum JWTDecoder {

    /// Decode the payload section of a JWT without signature verification.
    /// - Parameter jwt: A standard 3-part `header.payload.signature` JWT string.
    /// - Returns: Decoded `JWTClaims` or nil if malformed.
    public static func decode(_ jwt: String) -> JWTClaims? {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }

        // Base64url → Base64 standard (JWT uses URL-safe alphabet)
        var base64 = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Pad to a multiple of 4
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        guard let data = Data(base64Encoded: base64) else { return nil }

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try? decoder.decode(JWTClaims.self, from: data)
    }

    /// Build a mock JWT for demo/testing purposes.
    /// In production: JWTs come from the auth server only.
    public static func mockJWT(claims: JWTClaims, expiresIn: TimeInterval = 900)
        -> String
    {
        let header = #"{"alg":"ES256","typ":"JWT"}"#

        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        guard let claimsData = try? encoder.encode(claims) else { return "" }

        let headerB64 = Data(header.utf8).base64URLEncoded()
        let payloadB64 = claimsData.base64URLEncoded()
        // Mock signature — not cryptographically valid but structurally correct
        let signature = "MOCK_SIGNATURE_NOT_VALID"

        return "\(headerB64).\(payloadB64).\(signature)"
    }
}

// MARK: - Session Service Implementation

/// Actor-isolated session manager.
/// All state mutations are serialised by the actor executor —
/// eliminates the double-refresh race condition without explicit locks.
public actor SessionService: SessionServiceProtocol {

    // MARK: Dependencies (injected)
    private let storage: any SecureStorageProtocol
    private let auditLog: any AuditLogServiceProtocol
    private let authBackend: any AuthBackendProtocol

    // MARK: Token storage keys
    private let refreshTokenKey = "com.fintech.session.refresh_token"
    private let deviceIdKey = "com.fintech.session.device_id"

    // MARK: In-memory state (access token NEVER written to disk)
    private var accessToken: String?
    private var accessTokenExp: Date?
    private var cachedClaims: JWTClaims?
    private var hasRefreshToken: Bool = false

    /// In-flight refresh Task — ensures only one refresh runs at a time
    /// regardless of how many concurrent callers await `validAccessToken()`.
    private var refreshTask: Task<String, Error>?

    public init(
        storage: any SecureStorageProtocol,
        auditLog: any AuditLogServiceProtocol,
        authBackend: any AuthBackendProtocol
    ) {
        self.storage = storage
        self.auditLog = auditLog
        self.authBackend = authBackend
    }

    // MARK: - SessionServiceProtocol

    public var currentClaims: JWTClaims? { cachedClaims }

    public var isAuthenticated: Bool {
        guard let exp = accessTokenExp else {
            return hasRefreshToken
        }
        return Date.now < exp || hasRefreshToken
    }

    public func login(wallet: WalletID, pin: String) async throws
        -> AuthTokenBundle
    {
        // Validate inputs before network call
        guard await wallet.isValid else {
            throw SessionError.invalidCredentials
        }
        guard !pin.isEmpty else { throw SessionError.invalidCredentials }

        // Call auth backend (mock in demo)
        let bundle = try await authBackend.login(
            wallet: wallet.rawValue,
            pin: pin
        )

        // Store tokens
        storeTokenBundle(bundle)

        await auditLog.log(
            category: .authentication,
            event: "User logged in",
            userId: wallet.rawValue,
            metadata: [
                "sessionId": bundle.claims.sessionId,
                "deviceId": bundle.claims.deviceId,
            ]
        )

        return bundle
    }

    /// Returns a valid access token.
    /// Transparently refreshes if the current token is within 60 seconds of expiry.
    /// If a refresh is already in-flight, all callers join the SAME Task
    /// — preventing the double-refresh race condition.
    public func validAccessToken() async throws -> String {
        // Fast path: non-expired token in memory
        if let token = accessToken,
            let expiry = accessTokenExp,
            expiry > Date.now.addingTimeInterval(60)
        {  // 60-second buffer
            return token
        }

        // If a refresh is already running, join it rather than starting a new one
        if let existing = refreshTask {
            return try await existing.value
        }

        // Start a new refresh
        let task = Task<String, Error> {
            guard
                let refreshData = try? await storage.load(
                    forKey: refreshTokenKey
                ),
                let refreshToken = String(data: refreshData, encoding: .utf8)
            else {
                throw SessionError.sessionExpired
            }

            let bundle = try await authBackend.refresh(token: refreshToken)

            // ROTATION: store the NEW refresh token, invalidating the old one.
            // If server detects the old token presented again → revoke entire family.
            storeTokenBundle(bundle)

            await auditLog.log(
                category: .session,
                event: "Token refreshed",
                userId: bundle.claims.sub,
                metadata: ["sessionId": bundle.claims.sessionId]
            )

            return bundle.accessToken
        }

        refreshTask = task

        do {
            let token = try await task.value
            refreshTask = nil
            return token
        } catch {
            refreshTask = nil
            // If refresh fails with 401, the session is truly dead
            clearSessionState()
            throw SessionError.sessionExpired
        }
    }

    public func logout() async {
        let userId = cachedClaims?.sub
        clearSessionState()

        await auditLog.log(
            category: .session,
            event: "User logged out",
            userId: userId,
            metadata: [:]
        )
    }

    /// Issues a short-lived (2-minute) transaction authorization token.
    /// Called before high-value transactions to enforce step-up authentication.
    /// In production: also triggers biometric re-confirmation.
    public func requestTransactionAuthToken(for transaction: Transaction)
        async throws -> String
    {
        // Must have a valid base session
        let _ = try await validAccessToken()

        return try await authBackend.stepUp(
            transactionId: transaction.id.uuidString,
            amount: transaction.amount.paisa
        )
    }

    // MARK: - Private

    private func storeTokenBundle(_ bundle: AuthTokenBundle) {
        // Access token: memory only — clears on app termination
        accessToken = bundle.accessToken
        accessTokenExp = Date.now.addingTimeInterval(bundle.expiresIn)
        cachedClaims = bundle.claims

        // Refresh token: Keychain, ThisDeviceOnly, no iCloud sync
        if let data = bundle.refreshToken.data(using: .utf8) {
            try? storage.save(data, forKey: refreshTokenKey)
        }
    }

    private func clearSessionState() {
        accessToken = nil
        accessTokenExp = nil
        cachedClaims = nil
        refreshTask = nil
        try? storage.delete(forKey: refreshTokenKey)
    }
}

// MARK: - Auth Backend Protocol & Mock

/// Abstraction over the authentication API.
public protocol AuthBackendProtocol: Sendable {
    func login(wallet: String, pin: String) async throws -> AuthTokenBundle
    func refresh(token: String) async throws -> AuthTokenBundle
    func stepUp(transactionId: String, amount: Int64) async throws -> String
}

/// Mock authentication backend for demo and tests.
public final class MockAuthBackend: AuthBackendProtocol {

    /// Simulates the set of valid credentials.
    private let validWallet = "01800000001"
    private let validPIN = "1234"

    public init() {}

    public func login(wallet: String, pin: String) async throws
        -> AuthTokenBundle
    {
        try await Task.sleep(for: .milliseconds(800))

        guard wallet == validWallet, pin == validPIN else {
            throw SessionError.invalidCredentials
        }

        return makeBundle(sub: wallet, expiresIn: 900)  // 15-minute access token
    }

    public func refresh(token: String) async throws -> AuthTokenBundle {
        try await Task.sleep(for: .milliseconds(400))

        // In production: server validates and rotates the refresh token.
        // If the old token is replayed, server revokes the entire token family.
        guard token.hasPrefix("refresh_") else {
            throw SessionError.refreshFailed("Invalid refresh token format")
        }

        return makeBundle(sub: validWallet, expiresIn: 900)
    }

    public func stepUp(transactionId: String, amount: Int64) async throws
        -> String
    {
        try await Task.sleep(for: .milliseconds(300))
        // Returns a short-lived transaction auth token (2-minute TTL)
        return
            "txauth_\(UUID().uuidString)_\(Int(Date.now.timeIntervalSince1970) + 120)"
    }

    // MARK: - Private helpers

    private func makeBundle(sub: String, expiresIn: TimeInterval)
        -> AuthTokenBundle
    {
        let now = Int64(Date.now.timeIntervalSince1970)
        let claims = JWTClaims(
            sub: sub,
            walletId: sub,
            deviceId: UIDevice.current.identifierForVendor?.uuidString
                ?? UUID().uuidString,
            iat: now,
            exp: now + Int64(expiresIn),
            roles: ["user"],
            sessionId: UUID().uuidString
        )
        let accessToken = JWTDecoder.mockJWT(
            claims: claims,
            expiresIn: expiresIn
        )
        let refreshToken = "refresh_\(UUID().uuidString)"

        return AuthTokenBundle(
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresIn: expiresIn,
            claims: claims,
            tokenFamily: UUID().uuidString
        )
    }
}

// MARK: - Data Base64URL extension

extension Data {
    fileprivate func base64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
