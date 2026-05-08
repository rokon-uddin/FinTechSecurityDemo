//
//  SessionViewModel.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//




import Foundation
import Observation

@Observable
@MainActor
public final class SessionViewModel {

    // MARK: State
    public var walletInput    = "01800000001"
    public var pinInput       = "1234"
    public var isLoggedIn     = false
    public var currentClaims: JWTClaims?
    public var accessTokenPreview = ""
    public var tokenExpiry:   Date?
    public var isLoading      = false
    public var statusMessage  = ""
    public var isSuccess      = true
    public var stepUpToken    = ""
    public var auditEvents:   [AuditEvent] = []

    // MARK: Dependencies
    private let sessionService: any SessionServiceProtocol
    private let auditLog:       any AuditLogServiceProtocol
    private let nonceService:   any NonceServiceProtocol

    public init(
        sessionService: any SessionServiceProtocol,
        auditLog:       any AuditLogServiceProtocol,
        nonceService:   any NonceServiceProtocol
    ) {
        self.sessionService = sessionService
        self.auditLog       = auditLog
        self.nonceService   = nonceService
    }

    // MARK: - Intents

    public func login() async {
        isLoading = true
        let wallet = WalletID(rawValue: walletInput)
        do {
            let bundle = try await sessionService.login(wallet: wallet, pin: pinInput)
            await syncSessionState(bundle: bundle)
            statusMessage = "✓ Logged in. Session: \(bundle.claims.sessionId.prefix(8))..."
            isSuccess     = true
        } catch let err as SessionError {
            statusMessage = describeError(err)
            isSuccess = false
        } catch {
            statusMessage = error.localizedDescription
            isSuccess = false
        }
        isLoading = false
        refreshAuditLog()
    }

    public func fetchWithAutoRefresh() async {
        isLoading = true
        do {
            let token = try await sessionService.validAccessToken()
            accessTokenPreview = "Bearer \(token.prefix(24))..."
            statusMessage = "✓ Access token obtained (refreshed if needed)"
            isSuccess = true
        } catch let err as SessionError {
            statusMessage = describeError(err)
            isSuccess = false
        } catch {
            statusMessage = error.localizedDescription
            isSuccess = false
        }
        isLoading = false
        refreshAuditLog()
    }

    public func stepUpAuth() async {
        guard let claims = currentClaims else { return }
        isLoading = true

        let tx = Transaction(
            senderWallet:   WalletID(rawValue: claims.walletId),
            receiverWallet: WalletID(rawValue: "01500000001"),
            amount:         Money(paisa: 500_00),
            nonce:          nonceService.issue(ttl: 120)
        )

        do {
            let authToken = try await sessionService.requestTransactionAuthToken(for: tx)
            stepUpToken   = "txauth_\(authToken.suffix(8))"
            statusMessage = "✓ Step-up auth token issued (2-minute TTL)"
            isSuccess     = true
        } catch {
            statusMessage = error.localizedDescription
            isSuccess = false
        }
        isLoading = false
        refreshAuditLog()
    }

    public func logout() async {
        await sessionService.logout()
        isLoggedIn         = false
        currentClaims      = nil
        accessTokenPreview = ""
        tokenExpiry        = nil
        stepUpToken        = ""
        statusMessage      = "Logged out. Session cleared."
        isSuccess          = true
        refreshAuditLog()
    }

    // MARK: - Private

    private func syncSessionState(bundle: AuthTokenBundle) async {
        isLoggedIn         = await sessionService.isAuthenticated
        currentClaims      = bundle.claims
        accessTokenPreview = "Bearer \(bundle.accessToken.prefix(24))..."
        tokenExpiry        = bundle.claims.expiresAt
    }

    private func refreshAuditLog() {
        auditEvents = auditLog.recentEvents(limit: 20)
    }

    private func describeError(_ err: SessionError) -> String {
        switch err {
        case .invalidCredentials:    return "✗ Invalid wallet or PIN"
        case .sessionExpired:        return "✗ Session expired — please login again"
        case .refreshFailed(let m):  return "✗ Token refresh failed: \(m)"
        case .biometricRequired:     return "✗ Biometric authentication required"
        case .deviceNotRegistered:   return "✗ Device not registered"
        case .stepUpRequired:        return "✗ Step-up authentication required"
        }
    }
}
