//
//  TransactionSigningViewModel.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//




import Foundation
import Observation

@Observable
@MainActor
public final class TransactionSigningViewModel {

    // MARK: State
    public var keyInfo:         SigningKeyInfo?
    public var currentTx:       Transaction?
    public var signature:       Data?
    public var verificationResult: Bool?

    public var receiverWallet  = "01555000999"
    public var amountBDT       = "2500.00"
    public var note            = "High-value transfer"

    public var stepIndex       = 0
    public var isLoading       = false
    public var statusMessage   = ""
    public var isSuccess:      Bool = true
    public var tamperMode      = false
    public var auditEvents:    [AuditEvent] = []

    // MARK: Dependencies
    private let signingService:      any TransactionSigningServiceProtocol
    private let verificationService: TransactionVerificationServiceProtocol
    private let nonceService:        any NonceServiceProtocol
    private let auditLog:            any AuditLogServiceProtocol

    public init(
        signingService:      any TransactionSigningServiceProtocol,
        verificationService: TransactionVerificationServiceProtocol,
        nonceService:        any NonceServiceProtocol,
        auditLog:            any AuditLogServiceProtocol
    ) {
        self.signingService      = signingService
        self.verificationService = verificationService
        self.nonceService        = nonceService
        self.auditLog            = auditLog
    }

    // MARK: - Intents

    public func registerKey() async {
        isLoading = true
        do {
            let pubKeyData = try await signingService.registerKey()
            keyInfo = await signingService.keyInfo()
            statusMessage = "Key registered. Public key: \(pubKeyData.prefix(8).hexString)... (\(pubKeyData.count) bytes)"
            isSuccess = true
            stepIndex = 1
        } catch let err as SigningError {
            statusMessage = describeError(err)
            isSuccess = false
        } catch {
            statusMessage = error.localizedDescription
            isSuccess = false
        }
        isLoading = false
        refreshAuditLog()
    }

    public func buildTransaction() {
        let paise = Money(bdtString: amountBDT) ?? Money(paisa: 0)
        let nonce = nonceService.issue(ttl: 300)

        currentTx = Transaction(
            senderWallet:   WalletID(rawValue: "01800000001"),
            receiverWallet: WalletID(rawValue: receiverWallet),
            amount:         paise,
            nonce:          nonce,
            note:           note
        )
        signature        = nil
        verificationResult = nil
        statusMessage    = "Transaction built with server-issued nonce"
        isSuccess        = true
        stepIndex        = 2
    }

    public func signTransaction() async {
        guard let tx = currentTx else { return }
        isLoading = true
        do {
            let sig = try await signingService.sign(transaction: tx)
            signature     = sig
            statusMessage = "Transaction signed. Signature: \(sig.prefix(8).hexString)... (\(sig.count) bytes DER)"
            isSuccess     = true
            stepIndex     = 3
        } catch let err as SigningError {
            statusMessage = describeError(err)
            isSuccess     = false
        } catch {
            statusMessage = error.localizedDescription
            isSuccess     = false
        }
        isLoading = false
        refreshAuditLog()
    }

    public func verifySignature() async {
        guard var tx      = currentTx,
              let sig     = signature,
              let pubKey  = keyInfo?.publicKeyData else { return }

        isLoading = true

        var bytesToVerify = tx.canonicalBytes
        if tamperMode {
            var mutable = Array(bytesToVerify)
            if let idx = mutable.firstIndex(of: UInt8(ascii: "|")) {
                mutable[min(idx + 3, mutable.count - 1)] ^= 0x01
            }
            bytesToVerify = Data(mutable)
            tx = Transaction(
                id:             tx.id,
                senderWallet:   tx.senderWallet,
                receiverWallet: WalletID(rawValue: "01999999999"),
                amount:         tx.amount,
                timestampUnix:  tx.timestampUnix,
                nonce:          tx.nonce
            )
        }

        do {
            let valid = try verificationService.verify(
                transaction:  tx,
                signatureDER: sig,
                publicKeyRaw: pubKey
            )
            verificationResult = valid
            statusMessage = valid
                ? "✓ ECDSA P-256 signature verified. Non-repudiation confirmed."
                : "✗ Signature invalid — tampered transaction rejected."
            isSuccess = valid
            stepIndex = 4
        } catch let err as SigningError {
            statusMessage = describeError(err)
            isSuccess = false
        } catch {
            statusMessage = error.localizedDescription
            isSuccess = false
        }
        isLoading = false
        refreshAuditLog()
    }

    public func reset() {
        stepIndex = 0; currentTx = nil; signature = nil
        verificationResult = nil; statusMessage = ""; tamperMode = false
    }

    // MARK: - Private

    private func refreshAuditLog() {
        auditEvents = auditLog.recentEvents(limit: 15)
    }

    private func describeError(_ err: SigningError) -> String {
        switch err {
        case .noKeyRegistered:          return "No signing key. Register key first."
        case .biometricFailed(let m):   return "Biometric failed: \(m)"
        case .keyGenerationFailed(let m): return "Key generation failed: \(m)"
        case .signatureFailed(let m):   return "Signing failed: \(m)"
        case .verificationFailed(let m): return "Verification failed: \(m)"
        }
    }
}
