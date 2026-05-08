//
//  AESGCMViewModel.swift
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
final class AESGCMViewModel {
    // MARK: Inputs
    var receiverWallet = "01712345678"
    var amountBDT      = "500.00"
    var note           = "Rent payment"

    // MARK: State
    var currentStep  = 0
    var isProcessing = false
    var tamperMode   = false

    // MARK: Outputs
    var plaintextJSON   = ""
    var nonce           = ""
    var ciphertext      = ""
    var authTag         = ""
    var keyPreview      = ""
    var serverResult    = ""
    var serverSuccess   = false
    var envelope: EncryptedEnvelope?

    // MARK: - Step 1: Encrypt

    func encrypt() {
        isProcessing = true

        let paise = Int64((Double(amountBDT) ?? 0) * 100)
        let tx = TransactionPayload(
            transactionId:  UUID().uuidString,
            senderWallet:   "01800000001",
            receiverWallet: receiverWallet,
            amountPaisa:    paise,
            timestampUnix:  Int64(Date.now.timeIntervalSince1970),
            nonce:          MockBackend.issueTransactionNonce(),
            currency:       "BDT",
            note:           note
        )

        if let data = try? JSONEncoder().encode(tx),
           let pretty = prettyJSON(data) {
            plaintextJSON = pretty
        }

        let keyBytes = MockBackend.serverAESKey.withUnsafeBytes { Data($0) }
        keyPreview = "Key[0..7]: \(keyBytes.prefix(8).hexString)... (256-bit, stored in server HSM)"

        let key = MockBackend.serverAESKey

        do {
            let aesNonce = AES.GCM.Nonce()
            let plainData = try JSONEncoder().encode(tx)
            let sealedBox = try AES.GCM.seal(plainData, using: key, nonce: aesNonce)

            let env = EncryptedEnvelope(
                nonce:      Data(aesNonce),
                ciphertext: sealedBox.ciphertext,
                tag:        sealedBox.tag,
                keyId:      MockBackend.serverAESKeyId
            )
            envelope = env

            nonce      = Data(aesNonce).base64EncodedString()
            ciphertext = sealedBox.ciphertext.base64EncodedString()
            authTag    = sealedBox.tag.base64EncodedString()

        } catch {
            serverResult  = "Encryption failed: \(error)"
            serverSuccess = false
        }

        currentStep   = 1
        isProcessing  = false
    }

    // MARK: - Step 2: Send to server (decrypt + verify)

    func sendToServer() {
        guard var env = envelope else { return }
        isProcessing = true

        if tamperMode {
            var tampered = env.ciphertext
            if !tampered.isEmpty {
                tampered[0] ^= 0xFF
            }
            env = EncryptedEnvelope(
                nonce: env.nonce,
                ciphertext: tampered,
                tag: env.tag,
                keyId: env.keyId
            )
        }

        let result = MockBackend.decryptTransaction(envelope: env)

        serverResult  = result.message
        serverSuccess = result.success
        currentStep   = 2
        isProcessing  = false
    }

    // MARK: - Reset

    func reset() {
        currentStep  = 0
        plaintextJSON = ""
        nonce = ""; ciphertext = ""; authTag = ""; keyPreview = ""
        serverResult = ""; serverSuccess = false
        envelope = nil; tamperMode = false
    }

    private func prettyJSON(_ data: Data) -> String? {
        guard let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(withJSONObject: obj,
                                                        options: .prettyPrinted)
        else { return nil }
        return String(data: pretty, encoding: .utf8)
    }
}
