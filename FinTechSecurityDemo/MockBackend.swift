//
//  MockBackend.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Simulates FinTech's server-side cryptographic operations.
// In a real app these would be HTTP calls to your actual backend.
// Everything here runs in-process to make the demo self-contained.

import Foundation
import CryptoKit
import Security

// MARK: - Shared Data Models

struct TransactionPayload: Codable {
    let transactionId: String
    let senderWallet: String
    let receiverWallet: String
    let amountPaisa: Int64        // ALWAYS integer — never Double for money
    let timestampUnix: Int64
    let nonce: String
    let currency: String
    let note: String

    /// Deterministic canonical bytes used for signing.
    /// Both client and server must produce identical bytes from the same input.
    var canonicalBytes: Data {
        let fields = [
            transactionId,
            senderWallet,
            receiverWallet,
            String(amountPaisa),
            String(timestampUnix),
            nonce,
            currency
        ].joined(separator: "|")
        return fields.data(using: .utf8)!
    }

    /// Human-readable amount in BDT
    var displayAmount: String {
        let bdt = Double(amountPaisa) / 100.0
        return String(format: "৳%.2f", bdt)
    }
}

struct EncryptedEnvelope: Codable {
    let nonce: Data
    let ciphertext: Data
    let tag: Data
    let keyId: String
}

struct SignedRequest: Codable {
    let payload: TransactionPayload
    let signatureBase64: String
    let publicKeyBase64: String
}

// MARK: - Mock Backend Server

/// Simulates the FinTech server. All methods are `static` and run in-process.
/// In production each of these would be a separate backend microservice.
enum MockBackend {

    // MARK: - Server's AES-GCM Key (simulates key stored in server's HSM)
    // In production: stored in a Hardware Security Module, never in code.
    static let serverAESKey = SymmetricKey(size: .bits256)
    static let serverAESKeyId = "fintech-aes-v1"

    // MARK: - Server's RSA Key Pair (simulates server's certificate)
    // Generated once at server startup; public key distributed to clients.
    static let serverRSAPrivateKey: SecKey = {
        let attrs: [CFString: Any] = [
            kSecAttrKeyType:       kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048 as CFNumber
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            fatalError("MockBackend: Failed to generate RSA key: \(error!.takeRetainedValue())")
        }
        return key
    }()

    static var serverRSAPublicKey: SecKey {
        SecKeyCopyPublicKey(serverRSAPrivateKey)!
    }

    static var serverRSAPublicKeyData: Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(serverRSAPublicKey, &error) as Data? else {
            fatalError("MockBackend: Cannot export RSA public key")
        }
        return data
    }

    // MARK: - HMAC Secret (shared between client and server)
    // In production: derived during secure device registration.
    static let hmacSecret = SymmetricKey(data: {
        var bytes = [UInt8](repeating: 0, count: 32)
        return Data(bytes)
    }())

    // MARK: - Nonce Store (prevents replay attacks)
    // In production: stored in Redis/database with TTL.
    private static var usedNonces = Set<String>()
    private static var nonceLock = NSLock()

    // MARK: - API: Issue a single-use transaction nonce

    static func issueTransactionNonce() -> String {
        let nonce = UUID().uuidString + "-" + String(Int64(Date.now.timeIntervalSince1970))
        nonceLock.withLock {
            usedNonces.insert(nonce)
        }
        return nonce
    }

    static func consumeNonce(_ nonce: String) -> Bool {
        nonceLock.withLock {
            usedNonces.remove(nonce) != nil
        }
    }

    // MARK: - API: AES-GCM — Decrypt and verify transaction

    struct DecryptResult {
        let success: Bool
        let transaction: TransactionPayload?
        let message: String
    }

    static func decryptTransaction(envelope: EncryptedEnvelope) -> DecryptResult {
        guard envelope.keyId == serverAESKeyId else {
            return .init(success: false, transaction: nil,
                         message: "Unknown key ID: \(envelope.keyId)")
        }
        do {
            let nonce = try AES.GCM.Nonce(data: envelope.nonce)
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: envelope.ciphertext,
                tag: envelope.tag
            )
            let plainData = try AES.GCM.open(box, using: serverAESKey)
            let tx = try JSONDecoder().decode(TransactionPayload.self, from: plainData)
            return .init(success: true, transaction: tx,
                         message: "✓ Decrypted successfully. Amount: \(tx.displayAmount) → \(tx.receiverWallet)")
        } catch {
            return .init(success: false, transaction: nil,
                         message: "✗ Decryption/auth failed: \(error.localizedDescription)")
        }
    }

    // MARK: - API: HMAC — Verify request signature

    struct HMACVerifyResult {
        let valid: Bool
        let message: String
    }

    static func verifyHMACSignature(body: Data, signatureHex: String) -> HMACVerifyResult {
        let expectedMAC = HMAC<SHA256>.authenticationCode(for: body, using: hmacSecret)
        let expectedHex = Data(expectedMAC).hexString

        // Constant-time comparison (prevents timing attacks)
        let valid = HMAC<SHA256>.isValidAuthenticationCode(
            Data(hexString: signatureHex) ?? Data(),
            authenticating: body,
            using: hmacSecret
        )
        return .init(
            valid: valid,
            message: valid
                ? "✓ HMAC verified. Request is authentic."
                : "✗ HMAC mismatch. Request may be tampered.\n  Expected: \(expectedHex.prefix(32))...\n  Received: \(signatureHex.prefix(32))..."
        )
    }

    // MARK: - API: ECDH — Server-side key agreement step

    struct ECDHServerResponse {
        let serverPublicKeyData: Data
        let sessionId: String
    }

    static func performECDHKeyAgreement(
        clientPublicKeyData: Data
    ) -> (serverResponse: ECDHServerResponse, sharedSecret: Data) {
        // Server generates its own ephemeral key pair
        let serverPrivKey = P256.KeyAgreement.PrivateKey()
        let serverPubKey  = serverPrivKey.publicKey

        // Reconstruct client public key
        let clientPubKey = try! P256.KeyAgreement.PublicKey(rawRepresentation: clientPublicKeyData)

        // ECDH: compute shared secret
        let sharedSecret = try! serverPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)

        // Derive session key using HKDF (same as client will do)
        let sessionId = UUID().uuidString
        let sessionKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "fintech-session-v1".data(using: .utf8)!,
            sharedInfo: sessionId.data(using: .utf8)!,
            outputByteCount: 32
        )

        // Return server's public key so client can derive the same secret
        return (
            serverResponse: ECDHServerResponse(
                serverPublicKeyData: serverPubKey.rawRepresentation,
                sessionId: sessionId
            ),
            sharedSecret: sessionKey.withUnsafeBytes { Data($0) }  // Server stores this; returned here for demo visibility
        )
    }

    // MARK: - API: RSA — Decrypt RSA-wrapped AES key

    struct RSAUnwrapResult {
        let success: Bool
        let unwrappedKeyData: Data?
        let message: String
    }

    static func rsaUnwrapKey(wrappedKeyData: Data) -> RSAUnwrapResult {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        guard SecKeyIsAlgorithmSupported(serverRSAPrivateKey, .decrypt, algorithm) else {
            return .init(success: false, unwrappedKeyData: nil,
                         message: "RSA-OAEP-SHA256 not supported on this device")
        }
        var error: Unmanaged<CFError>?
        guard let plainData = SecKeyCreateDecryptedData(
            serverRSAPrivateKey, algorithm, wrappedKeyData as CFData, &error
        ) as Data? else {
            return .init(success: false, unwrappedKeyData: nil,
                         message: "✗ RSA unwrap failed: \((error!.takeRetainedValue() as Error).localizedDescription)")
        }
        return .init(success: true, unwrappedKeyData: plainData,
                     message: "✓ RSA unwrapped. Key recovered: \(plainData.hexString.prefix(32))...")
    }

    // MARK: - API: Secure Enclave — Verify transaction signature

    struct SEVerifyResult {
        let valid: Bool
        let message: String
    }

    static func verifyTransactionSignature(
        canonicalBytes: Data,
        signatureDER: Data,
        publicKeyRaw: Data
    ) -> SEVerifyResult {
        do {
            let pubKey = try P256.Signing.PublicKey(rawRepresentation: publicKeyRaw)
            let sig    = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
            let valid  = pubKey.isValidSignature(sig, for: canonicalBytes)
            return .init(
                valid: valid,
                message: valid
                    ? "✓ ECDSA P-256 signature verified.\n  Transaction is cryptographically authenticated."
                    : "✗ Signature invalid. Transaction may be tampered."
            )
        } catch {
            return .init(valid: false,
                         message: "✗ Signature parse error: \(error.localizedDescription)")
        }
    }
}

// MARK: - Data Helpers

extension Data {
    
    init?(hexString: String) {
        let hex = hexString
        guard hex.count % 2 == 0 else { return nil }
        var data = Data()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        self = data
    }
    
    var hexString: String { map { String(format: "%02hhx", $0) }.joined() }
}
