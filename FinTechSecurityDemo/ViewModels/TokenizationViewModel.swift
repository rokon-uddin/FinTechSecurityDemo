//
//  TokenizationViewModel.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//




import Foundation
import Observation

@Observable
@MainActor
public final class TokenizationViewModel {

    // MARK: Input
    public var pan         = "4242424242424242"
    public var cvv         = "123"
    public var expiryMonth = 12
    public var expiryYear  = 2027
    public var cardHolder  = "RAHMAN AHMED"

    // MARK: State
    public var isLoading      = false
    public var storedTokens:  [PaymentToken] = []
    public var errorMessage:  String?
    public var successMessage: String?
    public var pciAuditLog:   [AuditEvent]  = []

    // MARK: Dependencies (injected)
    private let tokenService: any CardTokenizationServiceProtocol
    private let auditLog:     any AuditLogServiceProtocol

    public init(
        tokenService: any CardTokenizationServiceProtocol,
        auditLog:     any AuditLogServiceProtocol
    ) {
        self.tokenService = tokenService
        self.auditLog     = auditLog
    }

    // MARK: - Intent methods

    public func tokenizeCard() async {
        isLoading     = true
        errorMessage  = nil
        successMessage = nil

        let request = CardTokenizationRequest.make(
            pan:         pan,
            cvv:         cvv,
            expiryMonth: expiryMonth,
            expiryYear:  expiryYear,
            cardHolder:  cardHolder
        )

        do {
            let token = try await tokenService.tokenize(request: request)
            successMessage = "Card tokenized: \(token.maskedPAN) (\(token.brand.rawValue.capitalized))"
            await loadTokens()
        } catch let error as TokenizationError {
            errorMessage = describeError(error)
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
        refreshAuditLog()
    }

    public func loadTokens() async {
        storedTokens = (try? await tokenService.listTokens()) ?? []
        refreshAuditLog()
    }

    public func deleteToken(_ token: PaymentToken) async {
        isLoading = true
        do {
            try await tokenService.deleteToken(id: token.id)
            await loadTokens()
            successMessage = "Token \(token.id.prefix(12))... deleted"
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
        refreshAuditLog()
    }

    public func clearMessages() {
        errorMessage = nil; successMessage = nil
    }

    // MARK: - Private

    private func refreshAuditLog() {
        pciAuditLog = auditLog.recentEvents(limit: 20)
    }

    private func describeError(_ error: TokenizationError) -> String {
        switch error {
        case .invalidCard(let msg):   return "Invalid card: \(msg)"
        case .gatewayUnavailable:     return "Payment gateway unavailable"
        case .tokenNotFound(let id):  return "Token not found: \(id)"
        case .networkError(let msg):  return "Network error: \(msg)"
        case .pciViolation(let msg):  return "PCI violation: \(msg)"
        }
    }
}
