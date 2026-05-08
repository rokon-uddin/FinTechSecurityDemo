//
//  TransactionSigningService.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//

// Hardware-backed transaction signing using Secure Enclave (P-256 ECDSA).
//
// Security guarantees:
//   • Private key never leaves the Secure Enclave hardware
//   • Signing requires biometric confirmation (Face ID / Touch ID)
//   • .biometryCurrentSet: key invalidated if biometry enrollment changes
//     (prevents thief from enrolling their fingerprint to gain access)
//   • Opaque data representation: stored handle ≠ raw key bytes
//
// Fallback on Simulator:
//   • Secure Enclave is not available on iOS Simulator
//   • Falls back to software P-256 key, clearly labelled
//   • All APIs identical — only the hardware guarantee is absent

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// MARK: - Key Metadata

/// Describes the source and properties of the signing key.
public struct SigningKeyInfo: Sendable {
    public let source: KeySourceType
    public let publicKeyData: Data
    public let keyAlgorithm: String
    public let isProtected: Bool  // true if biometric-protected

    public enum KeySourceType: Sendable, Equatable {
        case secureEnclave  // hardware — private key never leaves chip
        case softwareKeychain  // software — used on Simulator
    }

    public var sourceDescription: String {
        switch source {
        case .secureEnclave:
            return
                "Secure Enclave (A-series/M-series coprocessor, hardware-isolated)"
        case .softwareKeychain:
            return "Software Keychain (Simulator — no hardware protection)"
        }
    }
}

// MARK: - Transaction Signing Service

/// Signs transactions with a device-bound P-256 key.
/// On real devices: Secure Enclave + Face ID.
/// On Simulator: software P-256 key with no biometric.
public actor TransactionSigningService: TransactionSigningServiceProtocol {

    // MARK: Constants
    private static let keyStorageKey = "com.fintech.signing.private_key_handle"

    // MARK: Dependencies (injected — DIP)
    private let storage: any SecureStorageProtocol
    private let auditLog: any AuditLogServiceProtocol

    /// Cached key info — loaded once, reused across signing calls.
    private var cachedKeyInfo: SigningKeyInfo?

    /// Abstracted signing closure — decouples SE-specific API from the service.
    private var signingClosure: ((Data) throws -> Data)?

    public init(
        storage: any SecureStorageProtocol,
        auditLog: any AuditLogServiceProtocol
    ) {
        self.storage = storage
        self.auditLog = auditLog
    }

    // MARK: - TransactionSigningServiceProtocol

    public var hasRegisteredKey: Bool {
        get async {
            await storage.exists(forKey: Self.keyStorageKey)
        }
    }

    /// Register (generate) a new signing key.
    /// On device: creates P-256 key in Secure Enclave, gated by biometrics.
    /// Uploads the public key to the server (caller's responsibility).
    public func registerKey() async throws -> Data {
        // Delete any existing key first
        try? await deleteKey()

        let keyInfo: SigningKeyInfo

        if SecureEnclave.isAvailable {
            keyInfo = try await generateSecureEnclaveKey()
        } else {
            keyInfo = generateSoftwareKey()
        }

        cachedKeyInfo = keyInfo

        await auditLog.log(
            category: .security,
            event: "Signing key registered",
            userId: nil,
            metadata: [
                "keySource": keyInfo.source == .secureEnclave
                    ? "SecureEnclave" : "Software",
                "algorithm": keyInfo.keyAlgorithm,
                "publicKeyLen": String(keyInfo.publicKeyData.count),
            ]
        )

        return keyInfo.publicKeyData
    }

    /// Sign a transaction's canonical bytes.
    /// On real device: blocks until Face ID completes.
    public func sign(transaction: Transaction) async throws -> Data {
        guard let signer = signingClosure else {
            throw SigningError.noKeyRegistered
        }

        await auditLog.log(
            category: .transaction,
            event: "Transaction signing initiated",
            userId: transaction.senderWallet.rawValue,
            metadata: [
                "txId": transaction.id.uuidString,
                "amount": String(transaction.amount.paisa),
                "to": transaction.receiverWallet.rawValue,
                    // NOTE: amount is safe to log; it's in the audit trail
            ]
        )

        do {
            let signatureDER = try signer(transaction.canonicalBytes)

            await auditLog.log(
                category: .transaction,
                event: "Transaction signed successfully",
                userId: transaction.senderWallet.rawValue,
                metadata: ["txId": transaction.id.uuidString]
            )

            return signatureDER
        } catch {
            await auditLog.log(
                category: .security,
                event: "Transaction signing failed",
                userId: transaction.senderWallet.rawValue,
                metadata: [
                    "txId": transaction.id.uuidString,
                    "error": error.localizedDescription,
                ]
            )
            throw SigningError.signatureFailed(error.localizedDescription)
        }
    }

    public func deleteKey() async throws {
        signingClosure = nil
        cachedKeyInfo = nil
        try? storage.delete(forKey: Self.keyStorageKey)

        // Also delete from Keychain (for SE key handle)
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: Self.keyStorageKey.data(using: .utf8)!,
        ]
        SecItemDelete(query as CFDictionary)

        auditLog.log(
            category: .security,
            event: "Signing key deleted",
            userId: nil,
            metadata: [:]
        )
    }

    /// Returns key metadata if a key is registered.
    public func keyInfo() async -> SigningKeyInfo? { cachedKeyInfo }

    // MARK: - Secure Enclave Key Generation

    private func generateSecureEnclaveKey() async throws -> SigningKeyInfo {
        // Access control requirements:
        // .privateKeyUsage: key can be used for signing
        // .biometryCurrentSet: requires biometric; invalidated if enrollment changes
        //   → prevents attacker from adding their fingerprint to gain access
        guard
            let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet],
                nil
            )
        else {
            throw SigningError.keyGenerationFailed(
                "SecAccessControlCreateWithFlags failed"
            )
        }

        do {
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
                accessControl: access
            )

            // Store the OPAQUE data representation in Keychain.
            // This is NOT the raw key bytes — it's a handle to the SE key.
            // Without this handle, the SE key cannot be referenced again.
            let handleData = privateKey.dataRepresentation
            try await storage.save(handleData, forKey: Self.keyStorageKey)

            // Capture the signing closure — this is the only way to sign;
            // the private key reference cannot be exported.
            signingClosure = { data in
                // Calling .signature() here triggers the Face ID prompt.
                // The prompt is shown by the Secure Enclave hardware;
                // no UI code needed from the app.
                let sig = try privateKey.signature(for: data)
                return sig.derRepresentation
            }

            return SigningKeyInfo(
                source: .secureEnclave,
                publicKeyData: privateKey.publicKey.rawRepresentation,
                keyAlgorithm: "P-256 ECDSA (Secure Enclave)",
                isProtected: true
            )
        } catch {
            throw SigningError.keyGenerationFailed(error.localizedDescription)
        }
    }

    // MARK: - Software Key Generation (Simulator fallback)

    private func generateSoftwareKey() -> SigningKeyInfo {
        let privateKey = P256.Signing.PrivateKey()

        // For software key: store raw private key representation.
        // In a production Simulator build you'd use Keychain; here in-memory storage.
        let rawPriv = privateKey.rawRepresentation
        try? storage.save(rawPriv, forKey: Self.keyStorageKey)

        signingClosure = { data in
            let sig = try privateKey.signature(for: data)
            return sig.derRepresentation
        }

        return SigningKeyInfo(
            source: .softwareKeychain,
            publicKeyData: privateKey.publicKey.rawRepresentation,
            keyAlgorithm: "P-256 ECDSA (Software — Simulator)",
            isProtected: false
        )
    }
}

// MARK: - Transaction Verification Service

/// Verifies ECDSA P-256 signatures.
/// Stateless — depends only on the public key and the transaction.
/// Can run on both client and server.
public final class TransactionVerificationService:
    TransactionVerificationServiceProtocol, Sendable
{

    public init() {}

    /// Verify that `signatureDER` was produced by the holder of `publicKeyRaw`
    /// over `transaction.canonicalBytes`.
    public func verify(
        transaction: Transaction,
        signatureDER: Data,
        publicKeyRaw: Data
    ) throws -> Bool {
        do {
            let pubKey = try P256.Signing.PublicKey(
                rawRepresentation: publicKeyRaw
            )
            let sig = try P256.Signing.ECDSASignature(
                derRepresentation: signatureDER
            )
            // P256.Signing.PublicKey.isValidSignature is the single authoritative check.
            // It returns Bool rather than throwing — false means invalid, not an error.
            return pubKey.isValidSignature(sig, for: transaction.canonicalBytes)
        } catch {
            // Parsing failures (malformed DER, invalid key) are thrown as errors,
            // not returned as false. Callers should distinguish these cases.
            throw SigningError.verificationFailed(error.localizedDescription)
        }
    }
}
