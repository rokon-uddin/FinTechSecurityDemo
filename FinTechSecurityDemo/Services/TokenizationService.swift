//
//  TokenizationService.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// PCI-DSS compliant card tokenization service.
//
// PCI-DSS Requirements this addresses:
//   Req 3.4: Never store full PAN — store token instead.
//   Req 3.5: Protect stored data — tokens are stored in Keychain.
//   Req 6.5: Secure development — raw PAN never appears in app code.
//   Req 10:  Audit all access to cardholder data.
//
// Architecture:
//   1. Raw card data is entered in a gateway-managed UI (PCI scope reduction).
//   2. Gateway returns a token. App stores ONLY the token.
//   3. Payments are made by sending the token; gateway resolves it to the PAN.
//   4. If app is compromised, attacker gets useless tokens (not PANs).

import Foundation
import CryptoKit

// MARK: - Tokenization Service Implementation

/// PCI-DSS compliant tokenization service.
/// Implements SRP — only handles tokenization, not payment processing.
public final class TokenizationService: CardTokenizationServiceProtocol, Sendable {

    // MARK: Dependencies (injected — DIP)
    private let storage:  any SecureStorageProtocol
    private let auditLog: any AuditLogServiceProtocol
    private let gateway:  any TokenizationGatewayProtocol

    // Keychain namespace for token storage
    private let storageNamespace = "com.fintech.tokens."

    public init(
        storage:  any SecureStorageProtocol,
        auditLog: any AuditLogServiceProtocol,
        gateway:  any TokenizationGatewayProtocol
    ) {
        self.storage  = storage
        self.auditLog = auditLog
        self.gateway  = gateway
    }

    // MARK: - CardTokenizationServiceProtocol

    /// Tokenize a card via the payment gateway.
    /// Raw card data is handled entirely within the `request` object's
    /// private fields — calling code never has direct access to PAN/CVV.
    public func tokenize(request: CardTokenizationRequest) async throws -> PaymentToken {
        // PCI Req 3: never log, store, or expose raw card data
        auditLog.log(
            category: .tokenization,
            event:    "Card tokenization requested",
            userId:   nil,
            metadata: [
                "lastFour":     String(request.pan.suffix(4)),   // safe: only last 4
                "brand":        detectBrand(pan: request.pan).rawValue,
                "expiryMonth":  String(request.expiryMonth),
                "expiryYear":   String(request.expiryYear)
                // NEVER log: full PAN, CVV, cardholder name
            ]
        )

        // Delegate to gateway (Stripe, Adyen, etc. in production)
        let token = try await gateway.tokenize(request: request)

        // Store token securely in Keychain
        let tokenData = try JSONEncoder().encode(token)
        let storageKey = storageNamespace + token.id
        try storage.save(tokenData, forKey: storageKey)

        // Also maintain an index of all token IDs
        try updateTokenIndex(adding: token.id)

        auditLog.log(
            category: .tokenization,
            event:    "Card tokenized successfully",
            userId:   nil,
            metadata: [
                "tokenId":  token.id,
                "lastFour": token.lastFour,
                "brand":    token.brand.rawValue
            ]
        )

        return token
    }

    public func fetchToken(id: String) async throws -> PaymentToken {
        let key = storageNamespace + id
        guard storage.exists(forKey: key) else {
            throw TokenizationError.tokenNotFound(id)
        }
        let data  = try storage.load(forKey: key)
        let token = try JSONDecoder().decode(PaymentToken.self, from: data)

        auditLog.log(
            category: .tokenization,
            event:    "Token accessed",
            userId:   nil,
            metadata: ["tokenId": id]
        )

        return token
    }

    public func deleteToken(id: String) async throws {
        let key = storageNamespace + id
        guard storage.exists(forKey: key) else {
            throw TokenizationError.tokenNotFound(id)
        }
        try storage.delete(forKey: key)
        try updateTokenIndex(removing: id)

        auditLog.log(
            category: .tokenization,
            event:    "Token deleted",
            userId:   nil,
            metadata: ["tokenId": id]
        )
    }

    public func listTokens() async throws -> [PaymentToken] {
        let ids   = loadTokenIndex()
        var tokens: [PaymentToken] = []
        for id in ids {
            if let token = try? await fetchToken(id: id) {
                tokens.append(token)
            }
        }
        return tokens.sorted { $0.createdAt > $1.createdAt }
    }

    // MARK: - Private helpers

    private func detectBrand(pan: String) -> CardBrand {
        guard let first = pan.first else { return .unknown }
        switch first {
        case "4":              return .visa
        case "5":              return .mastercard
        case "3":              return .amex
        case "6":              return .discover
        default:               return .unknown
        }
    }

    private let indexKey = "com.fintech.tokens.index"

    private func loadTokenIndex() -> [String] {
        guard let data = try? storage.load(forKey: indexKey),
              let ids  = try? JSONDecoder().decode([String].self, from: data)
        else { return [] }
        return ids
    }

    private func updateTokenIndex(adding id: String) throws {
        var ids = loadTokenIndex()
        if !ids.contains(id) { ids.append(id) }
        let data = try JSONEncoder().encode(ids)
        try storage.save(data, forKey: indexKey)
    }

    private func updateTokenIndex(removing id: String) throws {
        var ids = loadTokenIndex()
        ids.removeAll { $0 == id }
        let data = try JSONEncoder().encode(ids)
        try storage.save(data, forKey: indexKey)
    }
}

// MARK: - Gateway Protocol (DIP — depend on abstraction)

/// Abstraction over the payment gateway SDK (Stripe, Adyen, etc.).
/// Allows the tokenization service to be tested without a real gateway.
public protocol TokenizationGatewayProtocol: Sendable {
    func tokenize(request: CardTokenizationRequest) async throws -> PaymentToken
}

// MARK: - Mock Gateway (used in demo and tests)

/// Simulates a PCI Level-1 payment gateway.
/// Generates realistic-looking tokens without touching real payment systems.
public final class MockTokenizationGateway: TokenizationGatewayProtocol {

    public init() {}

    public func tokenize(request: CardTokenizationRequest) async throws -> PaymentToken {
        // Simulate network latency
        try await Task.sleep(for: .milliseconds(600))

        // Validate the card (basic Luhn check in production; simplified here)
        guard request.pan.count >= 13,
              request.pan.allSatisfy(\.isNumber) else {
            throw TokenizationError.invalidCard("Invalid PAN format")
        }

        guard request.cvv.count >= 3 else {
            throw TokenizationError.invalidCard("Invalid CVV")
        }

        // Generate a realistic token ID
        let tokenId = "pm_" + randomAlphanumeric(length: 16)

        let brand: CardBrand
        switch request.pan.prefix(1) {
        case "4": brand = .visa
        case "5": brand = .mastercard
        case "3": brand = .amex
        default:  brand = .unknown
        }

        return PaymentToken(
            id:          tokenId,
            lastFour:    String(request.pan.suffix(4)),
            brand:       brand,
            expiryMonth: request.expiryMonth,
            expiryYear:  request.expiryYear,
            createdAt:   Date.now
        )
    }

    private func randomAlphanumeric(length: Int) -> String {
        let chars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return String((0..<length).compactMap { _ in chars.randomElement() })
    }
}

// MARK: - In-Memory Secure Storage (for demo and tests)
// In production: replace with Keychain implementation.

/// Thread-safe in-memory storage for demo/testing.
/// Implements SecureStorageProtocol so the real Keychain implementation
/// is a drop-in replacement (OCP — open for extension).
public final class InMemorySecureStorage: SecureStorageProtocol, @unchecked Sendable {

    private var store: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func save(_ value: Data, forKey key: String) throws {
        lock.withLock { store[key] = value }
    }

    public func load(forKey key: String) throws -> Data {
        guard let value = lock.withLock({ store[key] }) else {
            throw SecureStorageError.itemNotFound(key)
        }
        return value
    }

    public func delete(forKey key: String) throws {
        let removed = lock.withLock { store.removeValue(forKey: key) }
        if removed == nil {
            throw SecureStorageError.deleteFailed("Key not found: \(key)")
        }
    }

    public func exists(forKey key: String) -> Bool {
        lock.withLock { store[key] != nil }
    }
}

// MARK: - Audit Log Service Implementation

/// Compliant audit logger — scrubs all sensitive data before writing.
/// PCI-DSS Req 10: log access to CHD but NEVER log CHD itself.
public final class AuditLogService: AuditLogServiceProtocol, @unchecked Sendable {

    private var events: [AuditEvent] = []
    private let lock   = NSLock()
    private let maxEvents: Int

    public init(maxEvents: Int = 500) {
        self.maxEvents = maxEvents
    }

    public func log(
        category: AuditEvent.Category,
        event:    String,
        userId:   String?,
        metadata: [String: String]
    ) {
        // PCI Req 10.2: do not log sensitive values
        // Validate metadata does not contain obvious CHD patterns
        let safeMetadata = metadata.mapValues { sanitize($0) }

        let auditEvent = AuditEvent(
            timestamp: Date.now,
            category:  category,
            event:     event,
            userId:    userId,
            metadata:  safeMetadata
        )

        lock.withLock {
            events.insert(auditEvent, at: 0)
            if events.count > maxEvents {
                events.removeLast(events.count - maxEvents)
            }
        }

        // In production: also write to your centralised SIEM / log aggregation
        #if DEBUG
        let ts = ISO8601DateFormatter().string(from: auditEvent.timestamp)
        print("[\(ts)] [\(category.rawValue.uppercased())] \(event)")
        #endif
    }

    public func recentEvents(limit: Int) -> [AuditEvent] {
        lock.withLock { Array(events.prefix(limit)) }
    }

    /// Scrub patterns that look like PANs or other CHD.
    private func sanitize(_ value: String) -> String {
        var result = value
        // Mask anything that looks like a 13-19 digit card number
        let panPattern = #"\b\d{13,19}\b"#
        if let regex = try? NSRegularExpression(pattern: panPattern) {
            let range = NSRange(result.startIndex..., in: result)
            result = regex.stringByReplacingMatches(
                in: result, range: range, withTemplate: "[PAN_REDACTED]"
            )
        }
        return result
    }
}

// MARK: - Nonce Service Implementation

/// In-memory nonce store. In production: use Redis with TTL.
public final class NonceService: NonceServiceProtocol, @unchecked Sendable {

    private struct StoredNonce {
        let value:     String
        let expiresAt: Date
        var consumed:  Bool
    }

    private var store: [String: StoredNonce] = [:]
    private let lock  = NSLock()

    public init() {}

    public func issue(ttl: TimeInterval = 300) -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let nonce = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        lock.withLock {
            // Prune expired nonces (prevents unbounded memory growth)
            let now = Date.now
            store = store.filter { $0.value.expiresAt > now }

            store[nonce] = StoredNonce(
                value:     nonce,
                expiresAt: Date.now.addingTimeInterval(ttl),
                consumed:  false
            )
        }
        return nonce
    }

    public func consume(_ nonce: String) -> Bool {
        lock.withLock {
            guard var stored = store[nonce] else { return false }
            guard !stored.consumed, stored.expiresAt > Date.now else { return false }
            stored.consumed = true
            store[nonce] = stored
            return true
        }
    }
}
