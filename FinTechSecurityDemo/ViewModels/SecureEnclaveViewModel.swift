//
//  SecureEnclaveViewModel.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//




import Foundation
import Observation
import CryptoKit

@Observable
@MainActor
final class SecureEnclaveViewModel {
    var currentStep       = 0
    var isProcessing      = false

    // Key info
    var keySource         = ""
    var publicKeyHex      = ""
    var keyProperties     = ""

    // Transaction
    var receiverWallet    = "01555000999"
    var amountBDT         = "2500.00"
    var canonicalBytes    = ""
    var canonicalHex      = ""

    // Signing
    var signatureHex      = ""
    var biometricPrompted = false
    var signingMessage    = ""
    var signingSuccess    = false

    // Verification
    var verifyMessage     = ""
    var verifySuccess     = false
    var tamperMode        = false

    // Internal
    private var managedKey: SEKeyManager.ManagedKey?
    private var lastSignedBytes: Data?
    private var lastSignatureDER: Data?

    // MARK: - Step 1: Load / generate key

    func loadKey() {
        isProcessing = true
        do {
            let key = try SEKeyManager.loadOrCreate()
            managedKey = key

            keySource   = key.source == .secureEnclave
                ? "✓ Secure Enclave (hardware-backed, biometric-protected)"
                : "⚠ Software P-256 (Simulator — no hardware protection)"
            publicKeyHex = key.publicKeyRaw.hexString

            keyProperties = """
            Algorithm:     P-256 (secp256r1) ECDSA
            Key size:      256 bits (32-byte private scalar)
            Location:      \(key.source == .secureEnclave ? "Secure Enclave coprocessor" : "Software keychain (Simulator)")
            Exportable:    NO — private key never leaves \(key.source == .secureEnclave ? "the Secure Enclave chip" : "memory")
            Access ctrl:   \(key.source == .secureEnclave ? "Face ID / Touch ID required per signing operation" : "No biometric (Simulator)")
            Public key:    \(key.publicKeyRaw.count) bytes (uncompressed P-256 point: 0x04 || x || y)
            Usage:         Transaction signing (ECDSA-SHA256)
            """

        } catch {
            keySource    = "Key generation failed: \(error.localizedDescription)"
            isProcessing = false
            return
        }
        currentStep  = 1
        isProcessing = false
    }

    // MARK: - Step 2: Build transaction

    func buildTransaction() {
        let paise   = Int64((Double(amountBDT) ?? 0) * 100)
        let nonce   = MockBackend.issueTransactionNonce()
        let tx = TransactionPayload(
            transactionId:  UUID().uuidString,
            senderWallet:   "01800000001",
            receiverWallet: receiverWallet,
            amountPaisa:    paise,
            timestampUnix:  Int64(Date.now.timeIntervalSince1970),
            nonce:          nonce,
            currency:       "BDT",
            note:           "High-value transfer"
        )
        let canonical = tx.canonicalBytes
        lastSignedBytes = canonical

        canonicalBytes = """
        txId:      \(tx.transactionId)
        from:      \(tx.senderWallet)
        to:        \(tx.receiverWallet)
        amount:    \(tx.displayAmount) (\(tx.amountPaisa) paisa)
        timestamp: \(tx.timestampUnix)
        nonce:     \(tx.nonce)
        currency:  \(tx.currency)

        Canonical bytes format:
        txId|from|to|amountPaisa|timestamp|nonce|currency
        """
        canonicalHex = canonical.hexString
        currentStep  = 2
    }

    // MARK: - Step 3: Sign with SE (triggers biometrics on device)

    func signTransaction() {
        guard let key = managedKey, let bytesToSign = lastSignedBytes else { return }
        isProcessing = true

        do {
            let sigDER = try SEKeyManager.sign(data: bytesToSign, using: key)
            lastSignatureDER = sigDER
            signatureHex     = sigDER.hexString
            biometricPrompted = true
            signingMessage   = key.source == .secureEnclave
                ? "✓ Signed inside Secure Enclave. Face ID confirmed user presence."
                : "✓ Signed with software key (Simulator — no biometric required)."
            signingSuccess   = true
        } catch {
            signingMessage   = "✗ Signing failed: \(error.localizedDescription)"
            signingSuccess   = false
        }
        currentStep  = 3
        isProcessing = false
    }

    // MARK: - Step 4: Server verifies

    func verifySignature() {
        guard let sig = lastSignatureDER,
              let key = managedKey,
              var bytesToVerify = lastSignedBytes else { return }
        isProcessing = true

        if tamperMode {
            var bytes = Array(bytesToVerify)
            if let pipeIdx = bytesToVerify.firstIndex(of: UInt8(ascii: "|")) {
                let modIdx = min(Int(pipeIdx) + 5, bytes.count - 1)
                bytes[modIdx] ^= 0x01
            }
            bytesToVerify = Data(bytes)
        }

        let result = MockBackend.verifyTransactionSignature(
            canonicalBytes: bytesToVerify,
            signatureDER:   sig,
            publicKeyRaw:   key.publicKeyRaw
        )

        verifyMessage = result.message
        verifySuccess = result.valid
        currentStep   = 4
        isProcessing  = false
    }

    func reset() {
        currentStep = 0
        keySource = ""; publicKeyHex = ""; keyProperties = ""
        canonicalBytes = ""; canonicalHex = ""
        signatureHex = ""; signingMessage = ""; signingSuccess = false
        biometricPrompted = false
        verifyMessage = ""; verifySuccess = false; tamperMode = false
        lastSignedBytes = nil; lastSignatureDER = nil
    }

    func deleteAndReset() {
        SEKeyManager.deleteKey()
        managedKey = nil
        reset()
    }
}
