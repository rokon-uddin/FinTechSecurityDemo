//
//  ECDHViewModel.swift
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
final class ECDHViewModel {
    var currentStep     = 0
    var isProcessing    = false

    // Client side
    var clientPrivKeyPreview  = ""
    var clientPubKeyHex       = ""

    // Server response
    var serverPubKeyHex       = ""
    var sessionId             = ""

    // Derived keys
    var clientDerivedKeyHex   = ""
    var serverDerivedKeyHex   = ""
    var keysMatch             = false

    // Encryption demo
    var pinPayload            = "NewPIN:4829"
    var encryptedPIN          = ""
    var decryptedPIN          = ""
    var encryptionSuccess     = false

    // Internal
    private var clientPrivateKey: P256.KeyAgreement.PrivateKey?
    private var sessionKey: SymmetricKey?

    // MARK: - Step 1: Client generates key pair

    func generateClientKeys() {
        isProcessing = true

        let privKey = P256.KeyAgreement.PrivateKey()
        clientPrivateKey = privKey

        let privRaw = privKey.rawRepresentation
        clientPrivKeyPreview = "sk[0..7]: \(privRaw.prefix(8).hexString)... (EPHEMERAL — discarded after session)"

        clientPubKeyHex = privKey.publicKey.rawRepresentation.hexString

        currentStep  = 1
        isProcessing = false
    }

    // MARK: - Step 2: Exchange with server

    func performKeyExchange() {
        guard let clientPrivKey = clientPrivateKey else { return }
        isProcessing = true

        let clientPubKeyData = clientPrivKey.publicKey.rawRepresentation

        let result = MockBackend.performECDHKeyAgreement(
            clientPublicKeyData: clientPubKeyData
        )

        serverPubKeyHex      = result.serverResponse.serverPublicKeyData.hexString
        sessionId            = result.serverResponse.sessionId
        serverDerivedKeyHex  = result.sharedSessionKey.hexString

        do {
            let serverPubKey = try P256.KeyAgreement.PublicKey(
                rawRepresentation: result.serverResponse.serverPublicKeyData
            )

            let sharedSecret = try clientPrivKey.sharedSecretFromKeyAgreement(
                with: serverPubKey
            )

            let derivedKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: "fintech-session-v1".data(using: .utf8)!,
                sharedInfo: sessionId.data(using: .utf8)!,
                outputByteCount: 32
            )

            sessionKey = derivedKey
            clientDerivedKeyHex = derivedKey.withUnsafeBytes { Data($0) }.hexString

            keysMatch = clientDerivedKeyHex == serverDerivedKeyHex

        } catch {
            clientDerivedKeyHex = "Error: \(error.localizedDescription)"
        }

        currentStep  = 2
        isProcessing = false
    }

    // MARK: - Step 3: Use session key to encrypt PIN change

    func encryptWithSessionKey() {
        guard let key = sessionKey else { return }
        isProcessing = true

        do {
            let plainData = pinPayload.data(using: .utf8)!

            let nonce     = AES.GCM.Nonce()
            let sealedBox = try AES.GCM.seal(plainData, using: key, nonce: nonce)

            let combined = nonce.withUnsafeBytes { Data($0) }
                         + sealedBox.ciphertext
                         + sealedBox.tag
            encryptedPIN = combined.base64EncodedString()

            let serverKey  = SymmetricKey(data: Data(hexString: serverDerivedKeyHex)!)
            let nonceBytes = Data(combined.prefix(12))
            let ctBytes    = Data(combined.dropFirst(12).dropLast(16))
            let tagBytes   = Data(combined.suffix(16))

            let serverNonce = try AES.GCM.Nonce(data: nonceBytes)
            let serverBox   = try AES.GCM.SealedBox(
                nonce:      serverNonce,
                ciphertext: ctBytes,
                tag:        tagBytes
            )
            let recovered = try AES.GCM.open(serverBox, using: serverKey)
            decryptedPIN  = String(data: recovered, encoding: .utf8) ?? "decode error"
            encryptionSuccess = true

        } catch {
            encryptedPIN  = "Encryption failed: \(error)"
            decryptedPIN  = "N/A"
            encryptionSuccess = false
        }

        currentStep  = 3
        isProcessing = false
    }

    func reset() {
        currentStep = 0
        clientPrivKeyPreview = ""; clientPubKeyHex = ""; serverPubKeyHex = ""
        sessionId = ""; clientDerivedKeyHex = ""; serverDerivedKeyHex = ""
        encryptedPIN = ""; decryptedPIN = ""; keysMatch = false
        encryptionSuccess = false; clientPrivateKey = nil; sessionKey = nil
    }
}
