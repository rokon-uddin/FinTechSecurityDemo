//
//  RSAViewModel.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//




import Foundation
import Observation
import CryptoKit
import Security

@Observable
@MainActor
final class RSAViewModel {
    var currentStep      = 0
    var isProcessing     = false

    // RSA server key info
    var serverPubKeyInfo = ""

    // Client AES key
    var clientAESKeyHex      = ""
    var clientAESKeyPurpose  = ""

    // RSA wrap
    var wrappedKeyBase64     = ""
    var wrappedKeySizeBytes  = 0

    // Server unwrap
    var serverRecoveredHex   = ""
    var keysMatch            = false
    var serverMessage        = ""
    var serverSuccess        = false

    // Encryption demo with wrapped key
    var demoPlaintext        = "CardToken:4242424242424242:12/26:FinTech-User-001"
    var demoEncrypted        = ""
    var demoDecrypted        = ""

    // Internal
    private var clientAESKey: SymmetricKey?
    private var wrappedKeyData: Data?

    // MARK: - Step 1: Inspect server public key

    func inspectServerKey() {
        isProcessing = true
        let pubKeyData = MockBackend.serverRSAPublicKeyData
        let pubKey = MockBackend.serverRSAPublicKey
        let keyBlockBytes = SecKeyGetBlockSize(pubKey)

        serverPubKeyInfo = """
        Algorithm: RSA-2048
        Key size:  \(keyBlockBytes * 8) bits (\(keyBlockBytes) bytes)
        Padding:   OAEP-SHA256 (secure — NOT PKCS#1 v1.5)
        Key data:  \(pubKeyData.prefix(16).hexString)... (\(pubKeyData.count) bytes)
        Source:    Server TLS certificate / pinned key
        Purpose:   Key wrapping only (NOT for data encryption)
        """

        currentStep  = 1
        isProcessing = false
    }

    // MARK: - Step 2: Generate AES key and wrap with RSA

    func generateAndWrapKey() {
        isProcessing = true

        let aesKey = SymmetricKey(size: .bits256)
        clientAESKey = aesKey

        let keyBytes = aesKey.withUnsafeBytes { Data($0) }
        clientAESKeyHex    = keyBytes.hexString
        clientAESKeyPurpose = "AES-256 session key — will encrypt card tokenization data"

        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        guard SecKeyIsAlgorithmSupported(MockBackend.serverRSAPublicKey, .encrypt, algorithm) else {
            serverMessage = "RSA-OAEP-SHA256 not supported on this device"
            serverSuccess = false
            currentStep = 2
            isProcessing = false
            return
        }

        var error: Unmanaged<CFError>?
        guard let wrapped = SecKeyCreateEncryptedData(
            MockBackend.serverRSAPublicKey,
            algorithm,
            keyBytes as CFData,
            &error
        ) as Data? else {
            serverMessage = "RSA wrap failed: \((error!.takeRetainedValue() as Error).localizedDescription)"
            serverSuccess = false
            currentStep = 2
            isProcessing = false
            return
        }

        wrappedKeyData    = wrapped
        wrappedKeyBase64  = wrapped.base64EncodedString()
        wrappedKeySizeBytes = wrapped.count

        currentStep  = 2
        isProcessing = false
    }

    // MARK: - Step 3: Server unwraps the AES key

    func serverUnwrap() {
        guard let wrapped = wrappedKeyData else { return }
        isProcessing = true

        let result = MockBackend.rsaUnwrapKey(wrappedKeyData: wrapped)

        serverMessage   = result.message
        serverSuccess   = result.success

        if let recovered = result.unwrappedKeyData {
            serverRecoveredHex = recovered.hexString
            keysMatch          = serverRecoveredHex == clientAESKeyHex
        }

        currentStep  = 3
        isProcessing = false
    }

    // MARK: - Step 4: Demo — encrypt card token with the wrapped AES key

    func encryptWithWrappedKey() {
        guard let key = clientAESKey else { return }
        isProcessing = true

        do {
            let plainData = demoPlaintext.data(using: .utf8)!
            let nonce     = AES.GCM.Nonce()
            let sealed    = try AES.GCM.seal(plainData, using: key, nonce: nonce)

            demoEncrypted = (Data(nonce) + sealed.ciphertext + sealed.tag).base64EncodedString()

            if let recoveredKeyData = Data(hexString: serverRecoveredHex) {
                let serverKey   = SymmetricKey(data: recoveredKeyData)
                let combined    = Data(base64Encoded: demoEncrypted)!
                let sNonce      = try AES.GCM.Nonce(data: Data(combined.prefix(12)))
                let sCt         = Data(combined.dropFirst(12).dropLast(16))
                let sTag        = Data(combined.suffix(16))
                let sBox        = try AES.GCM.SealedBox(nonce: sNonce, ciphertext: sCt, tag: sTag)
                let recovered   = try AES.GCM.open(sBox, using: serverKey)
                demoDecrypted   = String(data: recovered, encoding: .utf8) ?? "decode error"
            }

        } catch {
            demoEncrypted = "Error: \(error)"
        }

        currentStep  = 4
        isProcessing = false
    }

    func reset() {
        currentStep = 0
        serverPubKeyInfo = ""; clientAESKeyHex = ""; clientAESKeyPurpose = ""
        wrappedKeyBase64 = ""; wrappedKeySizeBytes = 0
        serverRecoveredHex = ""; keysMatch = false
        serverMessage = ""; serverSuccess = false
        demoEncrypted = ""; demoDecrypted = ""
        clientAESKey = nil; wrappedKeyData = nil
    }
}
