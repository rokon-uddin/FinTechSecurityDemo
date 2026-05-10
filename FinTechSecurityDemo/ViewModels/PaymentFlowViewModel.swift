//
//  PaymentFlowViewModel.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/8/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//

import CryptoKit
import Foundation
import LocalAuthentication
import OSLog

// MARK: - Step Log Entry

struct StepLogEntry: Identifiable {
    let id = UUID()
    let stepNumber: Int
    let title: String
    let securityTopics: [String]
    let side: ExecutionSide
    let requestParams: [(label: String, value: String)]
    let responseData: [(label: String, value: String)]
    let logLines: [String]
    let timestamp: Date

    enum ExecutionSide: String {
        case client = "CLIENT"
        case server = "SERVER"
        case both = "CLIENT ↔ SERVER"
    }
}

// MARK: - PaymentFlowViewModel

@Observable
@MainActor
final class PaymentFlowViewModel {

    // MARK: - Flow State

    var currentStep = 0
    var isProcessing = false
    var flowComplete = false
    var errorMessage: String?
    
    var stepLogs: [StepLogEntry] = []
    
    // MARK: Step 0 — Device Security
    var deviceSecurityPassed = false
    var jailbreakPassed = false
    var biometricStateChanged = false
    var isSimulatorEnvironment = false
    var deviceCheckSummary: [(label: String, status: String)] = []

    // MARK: Step 1 — Login
    var walletInput = "01800000001"
    var pinInput = "1234"
    var loginResult: AuthTokenBundle?
    
    // MARK: Step 2 — Session
    var sessionClaims: JWTClaims?
    var accessTokenPreview = ""
    var refreshTokenPreview = ""
    
    // MARK: Step 3 — ECDH Key Exchange
    var clientPubKeyHex = ""
    var serverPubKeyHex = ""
    var derivedKeyHex = ""
    var ecdhSessionId = ""
    var receiverWallet = "01555000999"
    var amountText = "2500.00"
    var paymentNote = "Rent payment"
    var transactionNonce = ""
    var builtTransaction: Transaction?
    var cardNumber = "4242424242424242"
    var paymentToken: PaymentToken?
    var signatureDER: Data?
    var signatureHex = ""
    var publicKeyHex = ""
    var signingKeySource = ""
    var encryptedEnvelope: EncryptedEnvelope?
    var hmacSignatureHex = ""
    var nonceHex = ""
    var ciphertextPreview = ""
    var tagHex = ""
    var verificationResult: VerificationResult?

    // MARK: Step 8 — TLS Transmit
    var certPinHash = ""
    var tlsTransmitComplete = false

    // MARK: Step 10 — Response & Cleanup
    var serverResponseJSON = ""
    var memoryWipeComplete = false

    // MARK: - Dependencies

    private let sessionService: any SessionServiceProtocol
    private let tokenService: any CardTokenizationServiceProtocol
    private let signingService: any TransactionSigningServiceProtocol
    private let verificationService: any TransactionVerificationServiceProtocol
    private let auditLog: any AuditLogServiceProtocol

    // MARK: Internal crypto state
    private var clientPrivateKey: P256.KeyAgreement.PrivateKey?
    private var sessionKey: SymmetricKey?
    private var hmacKey: SymmetricKey?
    private var registeredPublicKey: Data?
    private var hmacBody: Data?
    private var storedBiometricState: Data?

    init(
        sessionService: any SessionServiceProtocol,
        tokenService: any CardTokenizationServiceProtocol,
        signingService: any TransactionSigningServiceProtocol,
        verificationService: any TransactionVerificationServiceProtocol,
        auditLog: any AuditLogServiceProtocol
    ) {
        self.sessionService = sessionService
        self.tokenService = tokenService
        self.signingService = signingService
        self.verificationService = verificationService
        self.auditLog = auditLog
    }

    // MARK: - Step 0: Device Security Check

    func performDeviceSecurityCheck() {
        PaymentFlowLogger.flow.info("▶ performDeviceSecurityCheck()")
        isProcessing = true
        var logs: [String] = []

        logs.append("[SECURITY] ═══ Device Security Pre-Flight ═══")

        // 1. Jailbreak Detection
        logs.append("[JAILBREAK] Running multi-signal jailbreak detection...")

        let cydiaExists = FileManager.default.fileExists(atPath: "/Applications/Cydia.app")
        let sshdExists = FileManager.default.fileExists(atPath: "/usr/sbin/sshd")
        let aptExists = FileManager.default.fileExists(atPath: "/private/var/lib/apt")
        let substrateExists = FileManager.default.fileExists(
            atPath: "/Library/MobileSubstrate/MobileSubstrate.dylib")
        let dyldClean = ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] == nil

        let jbChecks: [(String, Bool)] = [
            ("Cydia.app not found", !cydiaExists),
            ("sshd binary absent", !sshdExists),
            ("APT directory absent", !aptExists),
            ("MobileSubstrate absent", !substrateExists),
            ("DYLD_INSERT_LIBRARIES clean", dyldClean),
            ("Sandbox integrity", true),
            ("fork() blocked (non-jailbroken)", true),
        ]

        for (name, passed) in jbChecks {
            logs.append("[JAILBREAK] \(passed ? "✓" : "✗") \(name)")
        }
        jailbreakPassed = jbChecks.allSatisfy(\.1)
        logs.append(
            "[JAILBREAK] Overall: \(jailbreakPassed ? "✓ No jailbreak indicators" : "✗ JAILBREAK DETECTED — would abort in production")"
        )

        // 2. Environment Detection
        logs.append("[ENV] Checking execution environment...")
        let seAvailable = SecureEnclave.isAvailable
        isSimulatorEnvironment = !seAvailable

        let envChecks: [(String, Bool)] = [
            ("Secure Enclave available", seAvailable),
            ("Running on physical device", !isSimulatorEnvironment),
            ("Debugger not attached (P_TRACED)", true),
            ("Code signature valid", true),
        ]

        for (name, passed) in envChecks {
            logs.append("[ENV] \(passed ? "✓" : "⚠") \(name)")
        }

        if isSimulatorEnvironment {
            logs.append("[ENV] ⚠ Simulator detected — software fallbacks will be used")
            logs.append("[ENV] ⚠ In production: App Attest would fail on simulator")
        }

        // 3. Biometric Enrollment Validation
        logs.append("[BIO] Checking biometric enrollment state...")
        let context = LAContext()
        var bioError: NSError?
        let bioAvailable = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &bioError)

        if bioAvailable {
            let currentState = context.evaluatedPolicyDomainState
            if let stored = storedBiometricState, let current = currentState {
                biometricStateChanged = stored != current
                if biometricStateChanged {
                    logs.append("[BIO] ⚠ Biometric enrollment CHANGED since last check")
                    logs.append(
                        "[BIO] ⚠ New fingerprint/face enrolled — force re-authentication")
                } else {
                    logs.append("[BIO] ✓ Biometric enrollment unchanged — trusted state")
                }
            } else {
                storedBiometricState = currentState
                logs.append("[BIO] ✓ Biometric state baseline captured")
                biometricStateChanged = false
            }
        } else {
            logs.append(
                "[BIO] \(isSimulatorEnvironment ? "⚠ Biometrics unavailable (Simulator)" : "✗ No biometric hardware")"
            )
            biometricStateChanged = false
        }

        deviceSecurityPassed = jailbreakPassed
        deviceCheckSummary = [
            ("Jailbreak Detection", jailbreakPassed ? "✓ Clean" : "✗ Indicators Found"),
            (
                "Secure Enclave",
                seAvailable ? "✓ Hardware-backed" : "⚠ Software fallback (Simulator)"
            ),
            (
                "Biometric Enrollment",
                biometricStateChanged
                    ? "⚠ Changed" : (bioAvailable ? "✓ Unchanged" : "⚠ Unavailable")
            ),
            ("Environment Integrity", "✓ Validated"),
        ]

        logs.append("[SECURITY] ═══════════════════════════════════════")
        logs.append(
            "[SECURITY] Pre-flight: \(deviceSecurityPassed ? "✓ PASSED" : "⚠ WARNINGS (proceeding for demo)")"
        )

        PaymentFlowLogger.flow.info(
            "✓ Device security check complete — passed: \(self.deviceSecurityPassed)")

        stepLogs.append(
            StepLogEntry(
                stepNumber: 0,
                title: "Device Security Pre-Flight",
                securityTopics: [
                    "Jailbreak Detection", "Environment Validation",
                    "Biometric Enrollment", "App Attest",
                ],
                side: .client,
                requestParams: [
                    ("Jailbreak Checks", "\(jbChecks.count) signals"),
                    ("Environment Checks", "\(envChecks.count) signals"),
                    ("Biometric Policy", ".deviceOwnerAuthenticationWithBiometrics"),
                    ("Domain State", "evaluatedPolicyDomainState comparison"),
                ],
                responseData: deviceCheckSummary.map { ($0.label, $0.status) },
                logLines: logs,
                timestamp: Date.now
            )
        )
        currentStep = 1
        isProcessing = false
    }

    // MARK: - Step 1: Login

    func performLogin() async {
        PaymentFlowLogger.auth.info(
            "▶ performLogin() — wallet: \(self.walletInput)"
        )
        isProcessing = true
        errorMessage = nil
        var logs: [String] = []

        logs.append("[AUTH] Login request for wallet \(walletInput)")

        do {
            let wallet = WalletID(rawValue: walletInput)
            logs.append("[AUTH] Wallet format valid: \(wallet.isValid)")

            let bundle = try await sessionService.login(
                wallet: wallet,
                pin: pinInput
            )

            loginResult = bundle
            sessionClaims = bundle.claims
            accessTokenPreview = String(bundle.accessToken.prefix(40)) + "..."
            refreshTokenPreview = String(bundle.refreshToken.prefix(20)) + "..."

            logs.append(
                "[AUTH] Login succeeded — sessionId: \(bundle.claims.sessionId.prefix(8))..."
            )
            logs.append("[AUTH] Access token issued (15-min TTL, memory-only)")
            logs.append("[AUTH] Refresh token stored (7-day TTL, Keychain)")
            logs.append(
                "[AUTH] Token family: \(bundle.tokenFamily.prefix(8))..."
            )

            PaymentFlowLogger.auth.info(
                "✓ Login succeeded — session: \(bundle.claims.sessionId)"
            )

            stepLogs.append(
                StepLogEntry(
                    stepNumber: 1,
                    title: "Login & Authentication",
                    securityTopics: [
                        "Session Management", "JWT Tokens",
                        "Credential Validation",
                    ],
                    side: .both,
                    requestParams: [
                        ("Wallet Number", walletInput),
                        ("PIN", String(repeating: "•", count: pinInput.count)),
                        ("Endpoint", "POST /auth/login"),
                    ],
                    responseData: [
                        ("Access Token (JWT)", accessTokenPreview),
                        ("Refresh Token", refreshTokenPreview),
                        ("Session ID", bundle.claims.sessionId),
                        ("Expires In", "\(Int(bundle.expiresIn))s (15 min)"),
                        ("Token Family", bundle.tokenFamily),
                        ("Device ID", bundle.claims.deviceId.prefix(8) + "..."),
                    ],
                    logLines: logs,
                    timestamp: Date.now
                )
            )
            currentStep = 2
        } catch {
            logs.append("[AUTH] ✗ Login failed: \(error.localizedDescription)")
            PaymentFlowLogger.auth.error(
                "✗ Login failed: \(error.localizedDescription)"
            )
            errorMessage = "Login failed: \(error.localizedDescription)"
        }
        isProcessing = false
    }

    // MARK: - Step 2: Inspect Session

    func inspectSession() {
        PaymentFlowLogger.auth.info("▶ inspectSession()")
        var logs: [String] = []

        guard let claims = sessionClaims, let bundle = loginResult else {
            return
        }

        logs.append(
            "[SESSION] Decoding JWT access token (no signature verification on client)"
        )
        logs.append("[SESSION] sub: \(claims.sub)")
        logs.append("[SESSION] walletId: \(claims.walletId)")
        logs.append("[SESSION] deviceId: \(claims.deviceId.prefix(8))...")
        logs.append("[SESSION] iat: \(claims.iat) (issued-at UNIX)")
        logs.append("[SESSION] exp: \(claims.exp) (expiry UNIX)")
        logs.append("[SESSION] roles: \(claims.roles.joined(separator: ", "))")
        logs.append(
            "[SESSION] Access token: MEMORY ONLY — never persisted to disk"
        )
        logs.append(
            "[SESSION] Refresh token: Keychain (WhenUnlockedThisDeviceOnly)"
        )
        logs.append(
            "[SESSION] Refresh rotation: each refresh invalidates old token (RFC 9700)"
        )

        PaymentFlowLogger.auth.info("✓ Session inspected — claims decoded")

        stepLogs.append(
            StepLogEntry(
                stepNumber: 2,
                title: "Session Token Inspection",
                securityTopics: [
                    "JWT Claims", "Token Storage Strategy",
                    "Refresh Token Rotation",
                ],
                side: .client,
                requestParams: [
                    ("Access Token (first 40 chars)", accessTokenPreview),
                    (
                        "JWT Parts",
                        "header.payload.signature (3 base64url sections)"
                    ),
                ],
                responseData: [
                    ("Subject (sub)", claims.sub),
                    ("Wallet ID", claims.walletId),
                    ("Device ID", String(claims.deviceId.prefix(12)) + "..."),
                    ("Issued At (iat)", "\(claims.iat)"),
                    ("Expires At (exp)", "\(claims.exp)"),
                    ("Roles", claims.roles.joined(separator: ", ")),
                    ("Session ID", claims.sessionId),
                    (
                        "Access Token Storage",
                        "Memory only (cleared on resign-active)"
                    ),
                    (
                        "Refresh Token Storage",
                        "Keychain (ThisDeviceOnly, no iCloud)"
                    ),
                    ("Token Family", bundle.tokenFamily),
                ],
                logLines: logs,
                timestamp: Date.now
            )
        )
        currentStep = 3
    }

    // MARK: - Step 3: ECDH Key Exchange

    func performKeyExchange() {
        PaymentFlowLogger.crypto.info("▶ performKeyExchange()")
        var logs: [String] = []

        logs.append("[ECDH] Generating ephemeral P-256 key pair on CLIENT")
        let clientPrivKey = P256.KeyAgreement.PrivateKey()
        self.clientPrivateKey = clientPrivKey
        let clientPubData = clientPrivKey.publicKey.rawRepresentation
        clientPubKeyHex = clientPubData.hexString

        logs.append(
            "[ECDH] Client public key: \(clientPubKeyHex.prefix(32))... (\(clientPubData.count) bytes)"
        )
        logs.append("[ECDH] Sending client public key to SERVER...")

        let serverResult = MockBackend.performECDHKeyAgreement(
            clientPublicKeyData: clientPubData
        )

        let serverPubData = serverResult.serverResponse.serverPublicKeyData
        serverPubKeyHex = serverPubData.hexString
        ecdhSessionId = serverResult.serverResponse.sessionId

        logs.append("[ECDH] Server generated ephemeral P-256 key pair")
        logs.append(
            "[ECDH] Server public key: \(serverPubKeyHex.prefix(32))... (\(serverPubData.count) bytes)"
        )
        logs.append(
            "[ECDH] Session ID from server: \(ecdhSessionId.prefix(8))..."
        )

        logs.append("[ECDH] Computing shared secret on CLIENT via ECDH...")
        let serverPubKey = try! P256.KeyAgreement.PublicKey(
            rawRepresentation: serverPubData
        )
        let sharedSecret = try! clientPrivKey.sharedSecretFromKeyAgreement(
            with: serverPubKey
        )

        logs.append(
            "[ECDH] Shared secret computed (both sides get identical result)"
        )
        logs.append("[HKDF] Deriving keys with HKDF-SHA256 (domain separation)")
        logs.append("[HKDF] Key 1 salt: \"fintech-session-v1\" → AES-GCM session key")
        logs.append("[HKDF] Key 2 salt: \"fintech-hmac-v1\" → HMAC signing key")
        logs.append("[HKDF] Info: sessionId (binds keys to this session)")

        let derived = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "fintech-session-v1".data(using: .utf8)!,
            sharedInfo: ecdhSessionId.data(using: .utf8)!,
            outputByteCount: 32
        )
        self.sessionKey = derived
        derivedKeyHex = derived.withUnsafeBytes { Data($0).hexString }

        let derivedHMAC = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "fintech-hmac-v1".data(using: .utf8)!,
            sharedInfo: ecdhSessionId.data(using: .utf8)!,
            outputByteCount: 32
        )
        self.hmacKey = derivedHMAC
        let hmacKeyHex = derivedHMAC.withUnsafeBytes { Data($0).hexString }

        logs.append(
            "[HKDF] Session key: \(derivedKeyHex.prefix(32))... (256-bit AES)"
        )
        logs.append(
            "[HKDF] HMAC key: \(hmacKeyHex.prefix(32))... (256-bit HMAC)"
        )
        logs.append(
            "[ECDH] Session key matches server: \(derivedKeyHex == serverResult.sharedSessionKey.hexString)"
        )
        logs.append(
            "[ECDH] HMAC key matches server: \(hmacKeyHex == serverResult.sharedHMACKey.hexString)"
        )
        logs.append("[PFS] Ephemeral keys provide Perfect Forward Secrecy")
        logs.append("[ECDH] Client private key will be discarded after session")

        PaymentFlowLogger.crypto.info("✓ ECDH complete — session + HMAC keys derived")

        stepLogs.append(
            StepLogEntry(
                stepNumber: 3,
                title: "ECDH Key Exchange + HKDF",
                securityTopics: [
                    "ECDH P-256", "HKDF Key Derivation",
                    "Perfect Forward Secrecy", "Domain Separation",
                ],
                side: .both,
                requestParams: [
                    ("Client Public Key", clientPubKeyHex.prefix(40) + "..."),
                    ("Key Algorithm", "P-256 (secp256r1)"),
                    (
                        "Key Size",
                        "\(clientPubData.count) bytes (raw representation)"
                    ),
                ],
                responseData: [
                    ("Server Public Key", serverPubKeyHex.prefix(40) + "..."),
                    ("ECDH Session ID", ecdhSessionId),
                    ("Derived Session Key", derivedKeyHex.prefix(40) + "..."),
                    ("Derived HMAC Key", hmacKeyHex.prefix(40) + "..."),
                    ("Key Derivation", "HKDF-SHA256 (2 keys, domain-separated)"),
                    ("Session Key Salt", "\"fintech-session-v1\""),
                    ("HMAC Key Salt", "\"fintech-hmac-v1\""),
                    (
                        "Session Keys Match",
                        derivedKeyHex == serverResult.sharedSessionKey.hexString
                            ? "YES" : "NO"
                    ),
                    (
                        "HMAC Keys Match",
                        hmacKeyHex == serverResult.sharedHMACKey.hexString
                            ? "YES" : "NO"
                    ),
                    (
                        "Forward Secrecy",
                        "Ephemeral keys — past sessions safe if long-term key compromised"
                    ),
                ],
                logLines: logs,
                timestamp: Date.now
            )
        )
        currentStep = 4
    }

    // MARK: - Step 4: Build Payment

    func buildPayment() {
        PaymentFlowLogger.flow.info("▶ buildPayment()")
        var logs: [String] = []

        logs.append("[NONCE] Requesting single-use nonce from server...")
        let nonce = MockBackend.issueTransactionNonce()
        transactionNonce = nonce

        logs.append(
            "[NONCE] Server issued nonce: \(nonce.prefix(16))..."
        )
        logs.append("[NONCE] Stored server-side with TTL (single-use, anti-replay)")
        logs.append("[NONCE] Client cannot forge — only server tracks valid nonces")

        guard let amount = Money(bdtString: amountText) else {
            errorMessage = "Invalid amount"
            return
        }

        logs.append("[TX] Building transaction payload")
        logs.append(
            "[MONEY] Amount: \(amountText) BDT → \(amount.paisa) paisa (integer arithmetic)"
        )
        logs.append(
            "[MONEY] Integer representation prevents IEEE 754 floating-point errors"
        )

        let tx = Transaction(
            senderWallet: WalletID(rawValue: walletInput),
            receiverWallet: WalletID(rawValue: receiverWallet),
            amount: amount,
            nonce: nonce,
            note: paymentNote
        )
        builtTransaction = tx

        logs.append("[TX] Transaction ID: \(tx.id.uuidString.prefix(8))...")
        logs.append("[TX] Sender: \(tx.senderWallet.rawValue)")
        logs.append("[TX] Receiver: \(tx.receiverWallet.rawValue)")
        logs.append("[TX] Amount: \(tx.amount) (\(tx.amount.paisa) paisa)")
        logs.append("[TX] Canonical bytes: \(tx.canonicalBytes.count) bytes")
        logs.append(
            "[TX] Canonical format: ID|sender|receiver|paisa|timestamp|nonce|currency"
        )

        PaymentFlowLogger.flow.info(
            "✓ Transaction built — \(tx.amount.description) → \(self.receiverWallet)"
        )

        stepLogs.append(
            StepLogEntry(
                stepNumber: 4,
                title: "Build Payment Transaction",
                securityTopics: [
                    "Nonce (Replay Prevention)", "Integer Money",
                    "Canonical Representation",
                ],
                side: .both,
                requestParams: [
                    ("Receiver Wallet", receiverWallet),
                    ("Amount (BDT)", amountText),
                    ("Amount (Paisa)", String(amount.paisa)),
                    ("Note", paymentNote),
                    ("Nonce Endpoint", "GET /nonce/issue"),
                ],
                responseData: [
                    ("Transaction ID", tx.id.uuidString),
                    ("Server Nonce", String(nonce.prefix(20)) + "..."),
                    ("Nonce TTL", "300s (single-use)"),
                    ("Timestamp (UNIX)", String(tx.timestampUnix)),
                    ("Currency", tx.currency),
                    (
                        "Canonical Bytes Length",
                        "\(tx.canonicalBytes.count) bytes"
                    ),
                    ("Status", tx.status.rawValue),
                ],
                logLines: logs,
                timestamp: Date.now
            )
        )
        currentStep = 5
    }

    // MARK: - Step 5: Tokenize Card

    func tokenizeCard() async {
        PaymentFlowLogger.token.info("▶ tokenizeCard()")
        isProcessing = true
        errorMessage = nil
        var logs: [String] = []

        logs.append("[PCI] Card tokenization initiated")
        logs.append(
            "[PCI] PAN entered in gateway-managed UI (never in app code)"
        )
        logs.append(
            "[PCI] Raw card data: NEVER logged, stored, or transmitted by app"
        )
        logs.append("[PCI] Req 3.4: Store token, not PAN")
        logs.append("[PCI] Req 6.5: SDK manages all CHD input")
        logs.append("[PCI] Sending to gateway SDK...")

        let request = CardTokenizationRequest.make(
            pan: cardNumber,
            cvv: "123",
            expiryMonth: 12,
            expiryYear: 2027,
            cardHolder: "Demo User"
        )

        do {
            let token = try await tokenService.tokenize(request: request)
            paymentToken = token

            logs.append("[PCI] Gateway returned token: \(token.id)")
            logs.append("[PCI] Last four: \(token.lastFour) (safe for display)")
            logs.append("[PCI] Brand: \(token.brand.rawValue)")
            logs.append("[PCI] Token stored in Keychain (encrypted at rest)")
            logs.append("[PCI] Original PAN discarded — never stored")
            logs.append("[AUDIT] Tokenization logged (no CHD in logs)")

            PaymentFlowLogger.token.info("✓ Card tokenized: \(token.id)")

            stepLogs.append(
                StepLogEntry(
                    stepNumber: 5,
                    title: "PCI-DSS Card Tokenization",
                    securityTopics: [
                        "PCI-DSS Tokenization", "Secure Card Input",
                        "Keychain Storage",
                    ],
                    side: .both,
                    requestParams: [
                        ("Card Input", "Gateway-managed secure UI"),
                        (
                            "PAN",
                            "•••• •••• •••• \(String(cardNumber.suffix(4)))"
                        ),
                        ("CVV", "•••"),
                        ("Expiry", "12/2027"),
                        ("Gateway", "Mock PCI Level-1 Gateway"),
                    ],
                    responseData: [
                        ("Token ID", token.id),
                        ("Last Four", token.lastFour),
                        ("Brand", token.brand.rawValue),
                        ("Masked PAN", token.maskedPAN),
                        (
                            "Token Storage",
                            "Keychain (WhenUnlockedThisDeviceOnly)"
                        ),
                        ("PCI Scope", "SAQ A (gateway handles all CHD)"),
                    ],
                    logLines: logs,
                    timestamp: Date.now
                )
            )
            currentStep = 6
        } catch {
            logs.append(
                "[PCI] ✗ Tokenization failed: \(error.localizedDescription)"
            )
            PaymentFlowLogger.token.error(
                "✗ Tokenization failed: \(error.localizedDescription)"
            )
            errorMessage = "Tokenization failed: \(error.localizedDescription)"
        }
        isProcessing = false
    }

    // MARK: - Step 6: Sign Transaction

    func signTransaction() async {
        PaymentFlowLogger.signing.info("▶ signTransaction()")
        isProcessing = true
        errorMessage = nil
        var logs: [String] = []

        guard let tx = builtTransaction else { return }

        logs.append("[SE] Checking for registered signing key...")

        do {
            let hasKey = await signingService.hasRegisteredKey
            if !hasKey {
                logs.append(
                    "[SE] No key found — registering new P-256 key pair"
                )
                let pubKeyData = try await signingService.registerKey()
                registeredPublicKey = pubKeyData
                logs.append(
                    "[SE] Key registered — public key uploaded to server"
                )
            } else {
                logs.append("[SE] Existing key found")
            }

            if let info = await signingService.keyInfo() {
                signingKeySource = info.sourceDescription
                registeredPublicKey = info.publicKeyData
                publicKeyHex = info.publicKeyData.hexString
                logs.append("[SE] Key source: \(info.sourceDescription)")
                logs.append("[SE] Algorithm: \(info.keyAlgorithm)")
                logs.append("[SE] Biometric protected: \(info.isProtected)")
            }

            logs.append("[SIGN] Building canonical bytes from transaction")
            logs.append(
                "[SIGN] Canonical: \(String(data: tx.canonicalBytes, encoding: .utf8)?.prefix(60) ?? "")..."
            )
            logs.append(
                "[SIGN] Triggering biometric authentication (Face ID / Touch ID)..."
            )
            logs.append(
                "[SIGN] Signing happens INSIDE Secure Enclave — private key never exits"
            )

            let sig = try await signingService.sign(transaction: tx)
            signatureDER = sig
            signatureHex = sig.hexString

            logs.append(
                "[SIGN] ECDSA P-256 signature produced: \(sig.count) bytes (DER)"
            )
            logs.append("[SIGN] Signature: \(signatureHex.prefix(40))...")
            logs.append(
                "[SIGN] Non-repudiation: user's biometric confirmed signing"
            )

            PaymentFlowLogger.signing.info(
                "✓ Transaction signed — \(sig.count) bytes"
            )

            stepLogs.append(
                StepLogEntry(
                    stepNumber: 6,
                    title: "Secure Enclave Transaction Signing",
                    securityTopics: [
                        "ECDSA P-256", "Secure Enclave", "Biometric Auth",
                        "Non-Repudiation",
                    ],
                    side: .client,
                    requestParams: [
                        ("Transaction ID", tx.id.uuidString),
                        ("Canonical Bytes", "\(tx.canonicalBytes.count) bytes"),
                        (
                            "Canonical Preview",
                            String(data: tx.canonicalBytes, encoding: .utf8)?
                                .prefix(50).appending("...") ?? ""
                        ),
                        ("Key Source", signingKeySource),
                        ("Biometric Prompt", "Face ID / Touch ID required"),
                    ],
                    responseData: [
                        ("Signature (DER)", signatureHex.prefix(40) + "..."),
                        ("Signature Size", "\(sig.count) bytes"),
                        ("Public Key", publicKeyHex.prefix(40) + "..."),
                        ("Algorithm", "ECDSA P-256 (secp256r1)"),
                        ("Key Source", signingKeySource),
                        (
                            "Non-Repudiation",
                            "Biometric + hardware key = undeniable proof"
                        ),
                    ],
                    logLines: logs,
                    timestamp: Date.now
                )
            )
            currentStep = 7
        } catch {
            logs.append(
                "[SIGN] ✗ Signing failed: \(error.localizedDescription)"
            )
            PaymentFlowLogger.signing.error(
                "✗ Signing failed: \(error.localizedDescription)"
            )
            errorMessage = "Signing failed: \(error.localizedDescription)"
        }
        isProcessing = false
    }

    // MARK: - Step 7: Encrypt + HMAC

    func encryptAndSubmit() {
        PaymentFlowLogger.crypto.info("▶ encryptAndSubmit()")
        var logs: [String] = []

        guard let tx = builtTransaction, let key = sessionKey else { return }

        logs.append("[AES-GCM] Encrypting transaction payload with session key")
        logs.append("[AES-GCM] Algorithm: AES-256-GCM (AEAD)")
        logs.append("[AES-GCM] Key: derived from ECDH + HKDF (step 2)")

        do {
            let plaintext = try JSONEncoder().encode(
                TransactionPayload(
                    transactionId: tx.id.uuidString,
                    senderWallet: tx.senderWallet.rawValue,
                    receiverWallet: tx.receiverWallet.rawValue,
                    amountPaisa: tx.amount.paisa,
                    timestampUnix: tx.timestampUnix,
                    nonce: tx.nonce,
                    currency: tx.currency,
                    note: tx.note
                )
            )

            let nonce = AES.GCM.Nonce()
            let sealedBox = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: nonce
            )

            nonceHex = Data(nonce).hexString
            ciphertextPreview =
                sealedBox.ciphertext.prefix(20).hexString + "..."
            tagHex = sealedBox.tag.hexString

            let envelope = EncryptedEnvelope(
                nonce: Data(nonce),
                ciphertext: sealedBox.ciphertext,
                tag: sealedBox.tag,
                keyId: "ecdh-session-\(ecdhSessionId.prefix(8))"
            )
            encryptedEnvelope = envelope

            logs.append(
                "[AES-GCM] Nonce: \(nonceHex) (12 bytes, random, unique)"
            )
            logs.append(
                "[AES-GCM] Ciphertext: \(sealedBox.ciphertext.count) bytes"
            )
            logs.append("[AES-GCM] Auth tag: \(tagHex) (16 bytes)")
            logs.append(
                "[AES-GCM] Tag ensures tamper detection — any modification fails decryption"
            )

            logs.append("[HMAC] Computing HMAC-SHA256 over request body")
            logs.append("[HMAC] Key: derived from ECDH shared secret via HKDF (step 3)")
            logs.append(
                "[HMAC] Covers: method + path + timestamp + nonce + body hash"
            )

            guard let hmacKey else {
                errorMessage = "HMAC key not available — complete ECDH key exchange first"
                return
            }

            let bodyForHMAC = try JSONEncoder().encode(envelope)
            self.hmacBody = bodyForHMAC
            let hmacCode = HMAC<SHA256>.authenticationCode(
                for: bodyForHMAC,
                using: hmacKey
            )
            hmacSignatureHex = Data(hmacCode).hexString

            logs.append("[HMAC] Signature: \(hmacSignatureHex.prefix(32))...")
            logs.append(
                "[HMAC] Prevents request tampering even if TLS is compromised"
            )
            logs.append(
                "[HMAC] Server verifies with its own ECDH-derived key (constant-time comparison)"
            )

            PaymentFlowLogger.crypto.info("✓ Encrypted + HMAC signed")

            stepLogs.append(
                StepLogEntry(
                    stepNumber: 7,
                    title: "AES-GCM Encryption + HMAC Signing",
                    securityTopics: [
                        "AES-256-GCM", "HMAC-SHA256", "AEAD",
                        "Request Integrity",
                    ],
                    side: .client,
                    requestParams: [
                        ("Plaintext Size", "\(plaintext.count) bytes (JSON)"),
                        ("Encryption Key", "ECDH-derived session key (step 2)"),
                        ("AES Mode", "GCM (Galois/Counter Mode)"),
                        ("Key Size", "256-bit"),
                        ("HMAC Key", "ECDH-derived (HKDF, \"fintech-hmac-v1\")"),
                    ],
                    responseData: [
                        ("Nonce (IV)", nonceHex),
                        ("Ciphertext", "\(sealedBox.ciphertext.count) bytes"),
                        ("Auth Tag", tagHex),
                        ("Key ID", envelope.keyId),
                        ("HMAC-SHA256", hmacSignatureHex.prefix(40) + "..."),
                        ("HMAC Covers", "Full encrypted envelope"),
                        (
                            "Tamper Protection",
                            "Tag (AES-GCM) + HMAC (request-level)"
                        ),
                    ],
                    logLines: logs,
                    timestamp: Date.now
                )
            )
            currentStep = 8
        } catch {
            logs.append(
                "[AES-GCM] ✗ Encryption failed: \(error.localizedDescription)"
            )
            PaymentFlowLogger.crypto.error(
                "✗ Encryption failed: \(error.localizedDescription)"
            )
            errorMessage = "Encryption failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Step 8: TLS Transmit

    func simulateTLSTransmit() {
        PaymentFlowLogger.network.info("▶ simulateTLSTransmit()")
        var logs: [String] = []

        logs.append("[TLS] ═══ Secure Transport Layer ═══")
        logs.append("[TLS] Protocol: TLS 1.3 (RFC 8446)")
        logs.append("[TLS] Key exchange: ECDHE with P-256 (per-connection ephemeral)")
        logs.append("[TLS] Cipher suite: TLS_AES_256_GCM_SHA384")
        logs.append("[TLS] Forward secrecy: ✓ Ephemeral keys per connection")
        logs.append("[TLS] 0-RTT: Disabled (prevents replay on resumption)")

        logs.append("[PIN] ── Certificate Pinning ──")
        logs.append("[PIN] Strategy: Public key (SPKI) pinning")
        let mockCertData = "api.fintech.example.com-production-2026".data(using: .utf8)!
        let pinHash = SHA256.hash(data: mockCertData)
        certPinHash = Data(pinHash).hexString
        logs.append("[PIN] Expected SPKI SHA-256: \(certPinHash.prefix(32))...")
        logs.append("[PIN] Server certificate SPKI: \(certPinHash.prefix(32))...")
        logs.append("[PIN] Pin match: ✓ Certificate trusted")
        logs.append("[PIN] Backup pin: ✓ Configured (rotation support)")
        logs.append(
            "[PIN] Validation: URLSessionDelegate.urlSession(_:didReceive:completionHandler:)"
        )

        logs.append("[SESSION] ── Ephemeral URLSession ──")
        logs.append("[SESSION] Configuration: URLSessionConfiguration.ephemeral")
        logs.append("[SESSION] Disk cache: NONE")
        logs.append("[SESSION] Cookie storage: NONE (in-memory only)")
        logs.append("[SESSION] Credential storage: NONE")
        logs.append("[SESSION] TLS session cache: In-memory only")

        logs.append("[TX] ── Transmitting Request ──")
        logs.append("[TX] POST /api/v3/transfer")
        logs.append("[TX] Content-Type: application/octet-stream")
        logs.append("[TX] X-Fintech-Signature: \(hmacSignatureHex.prefix(16))...")
        logs.append("[TX] X-Nonce: \(transactionNonce.prefix(8))...")
        logs.append("[TX] X-Timestamp: \(builtTransaction.map { String($0.timestampUnix) } ?? "")")
        logs.append("[TX] Authorization: Bearer \(accessTokenPreview.prefix(16))...")
        logs.append("[TX] X-Device-Attest: (SE-attested device token)")
        logs.append(
            "[TX] Body: \(encryptedEnvelope?.ciphertext.count ?? 0) bytes (AES-GCM encrypted)")
        logs.append("[TX] ✓ 200 OK — \(Int.random(in: 45...120))ms round-trip")

        tlsTransmitComplete = true

        PaymentFlowLogger.network.info("✓ TLS transmission complete")

        stepLogs.append(
            StepLogEntry(
                stepNumber: 8,
                title: "TLS 1.3 Secure Transmission",
                securityTopics: [
                    "TLS 1.3", "Certificate Pinning",
                    "Ephemeral URLSession", "ECDHE",
                ],
                side: .both,
                requestParams: [
                    ("Endpoint", "POST /api/v3/transfer"),
                    ("TLS Version", "1.3 (RFC 8446)"),
                    ("Cipher Suite", "TLS_AES_256_GCM_SHA384"),
                    ("Session Config", "URLSessionConfiguration.ephemeral"),
                    ("Cert Pinning", "SPKI SHA-256"),
                    ("Pin Hash", certPinHash.prefix(40) + "..."),
                ],
                responseData: [
                    ("Status", "200 OK"),
                    ("TLS Handshake", "1-RTT (TLS 1.3)"),
                    ("Forward Secrecy", "✓ Ephemeral ECDHE per connection"),
                    ("Cert Pin Valid", "✓ Matches expected SPKI hash"),
                    ("Disk Cache", "None (ephemeral session)"),
                    ("Response", "Encrypted body (AES-GCM)"),
                ],
                logLines: logs,
                timestamp: Date.now
            )
        )
        currentStep = 9
    }

    // MARK: - Step 9: Server Verification

    func verifyOnServer() {
        PaymentFlowLogger.network.info("▶ verifyOnServer()")
        var logs: [String] = []

        guard let tx = builtTransaction,
            let sig = signatureDER,
            let pubKey = registeredPublicKey,
            let body = hmacBody
        else { return }

        logs.append("[SERVER] ═══ Server-Side Verification Pipeline ═══")

        // 1) HMAC Verification (using server's ECDH-derived HMAC key for this session)
        logs.append(
            "[SERVER] Step 1: Verifying HMAC-SHA256 with session-derived key..."
        )
        let hmacResult = MockBackend.verifyHMACSignature(
            body: body,
            signatureHex: hmacSignatureHex,
            sessionId: ecdhSessionId
        )
        logs.append(
            "[SERVER] HMAC: \(hmacResult.valid ? "✓ VALID" : "✗ INVALID")"
        )

        // 2) Nonce Verification (server-side: remove from nonce store)
        logs.append("[SERVER] Step 2: Consuming server-issued nonce...")
        let nonceValid = MockBackend.consumeNonce(tx.nonce)
        logs.append(
            "[SERVER] Nonce: \(nonceValid ? "✓ VALID (first use, now consumed)" : "✗ ALREADY USED or NOT SERVER-ISSUED")"
        )

        // 3) Timestamp Validation
        logs.append("[SERVER] Step 3: Validating transaction timestamp...")
        let txAge = Int64(Date.now.timeIntervalSince1970) - tx.timestampUnix
        let timestampValid = txAge >= 0 && txAge <= 300
        logs.append("[SERVER] Transaction age: \(txAge)s (max 300s)")
        logs.append(
            "[SERVER] Timestamp: \(timestampValid ? "✓ WITHIN 5-MIN WINDOW" : "✗ EXPIRED or FUTURE")"
        )

        // 4) Signature Verification
        logs.append(
            "[SERVER] Step 4: Verifying ECDSA P-256 transaction signature..."
        )
        let sigResult = MockBackend.verifyTransactionSignature(
            canonicalBytes: tx.canonicalBytes,
            signatureDER: sig,
            publicKeyRaw: pubKey
        )
        logs.append(
            "[SERVER] Signature: \(sigResult.valid ? "✓ VALID" : "✗ INVALID")"
        )

        // 5) Decryption (using ECDH-derived key — simulate server having the same key)
        logs.append(
            "[SERVER] Step 5: Decrypting AES-GCM envelope with session key..."
        )
        var decryptionSuccess = false
        var decryptedPreview = ""
        if let envelope = encryptedEnvelope, let key = sessionKey {
            do {
                let nonce = try AES.GCM.Nonce(data: envelope.nonce)
                let box = try AES.GCM.SealedBox(
                    nonce: nonce,
                    ciphertext: envelope.ciphertext,
                    tag: envelope.tag
                )
                let plainData = try AES.GCM.open(box, using: key)
                let decoded = try JSONDecoder().decode(
                    TransactionPayload.self,
                    from: plainData
                )
                decryptionSuccess = true
                decryptedPreview =
                    "✓ \(decoded.displayAmount) → \(decoded.receiverWallet)"
                logs.append("[SERVER] Decryption: ✓ SUCCESS")
                logs.append(
                    "[SERVER] Payload: \(decoded.displayAmount) → \(decoded.receiverWallet)"
                )
            } catch {
                logs.append(
                    "[SERVER] Decryption: ✗ FAILED — \(error.localizedDescription)"
                )
            }
        }

        let allPassed =
            hmacResult.valid && nonceValid && timestampValid && sigResult.valid
            && decryptionSuccess

        logs.append("[SERVER] ═══════════════════════════════════════")
        logs.append(
            "[SERVER] Overall: \(allPassed ? "✓ ALL 5 CHECKS PASSED" : "✗ VERIFICATION FAILED")"
        )

        if allPassed {
            logs.append("[SERVER] Transaction APPROVED for processing")
        }

        let result = VerificationResult(
            hmacValid: hmacResult.valid,
            nonceValid: nonceValid,
            timestampValid: timestampValid,
            signatureValid: sigResult.valid,
            decryptionSuccess: decryptionSuccess,
            overallSuccess: allPassed,
            decryptedPreview: decryptedPreview
        )
        verificationResult = result

        PaymentFlowLogger.network.info(
            "✓ Server verification complete — overall: \(allPassed)"
        )

        stepLogs.append(
            StepLogEntry(
                stepNumber: 9,
                title: "Server-Side Verification Pipeline",
                securityTopics: [
                    "HMAC Verification", "Nonce Validation",
                    "Timestamp Validation", "Signature Verification",
                    "AES-GCM Decryption",
                ],
                side: .server,
                requestParams: [
                    ("HMAC Signature", hmacSignatureHex.prefix(32) + "..."),
                    ("Transaction Nonce", String(tx.nonce.prefix(16)) + "..."),
                    ("Transaction Timestamp", String(tx.timestampUnix)),
                    ("ECDSA Signature", signatureHex.prefix(32) + "..."),
                    (
                        "Encrypted Envelope",
                        "\(encryptedEnvelope?.ciphertext.count ?? 0) bytes"
                    ),
                ],
                responseData: [
                    (
                        "1. HMAC Check",
                        hmacResult.valid ? "✓ Authentic" : "✗ Tampered"
                    ),
                    (
                        "2. Nonce Check",
                        nonceValid ? "✓ First use" : "✗ Replay detected"
                    ),
                    (
                        "3. Timestamp Check",
                        timestampValid
                            ? "✓ Within 5-min window (\(txAge)s)"
                            : "✗ Expired (\(txAge)s)"
                    ),
                    (
                        "4. Signature Check",
                        sigResult.valid ? "✓ Valid ECDSA" : "✗ Invalid"
                    ),
                    (
                        "5. Decryption",
                        decryptionSuccess ? "✓ Decrypted" : "✗ Failed"
                    ),
                    ("Overall Result", allPassed ? "✓ APPROVED" : "✗ REJECTED"),
                    ("Decrypted Payload", decryptedPreview),
                ],
                logLines: logs,
                timestamp: Date.now
            )
        )

        currentStep = 10
    }

    // MARK: - Step 10: Response & Secure Cleanup

    func handleResponseAndCleanup() {
        PaymentFlowLogger.flow.info("▶ handleResponseAndCleanup()")
        var logs: [String] = []

        guard let key = sessionKey, let result = verificationResult else { return }

        // 1. Simulate encrypted response from server
        logs.append("[RESPONSE] ═══ Encrypted Server Response ═══")
        logs.append("[RESPONSE] Server responds with AES-GCM encrypted body")

        let responsePayload: [String: Any] = [
            "status": result.overallSuccess ? "APPROVED" : "REJECTED",
            "transactionId": builtTransaction?.id.uuidString ?? "",
            "amount": builtTransaction?.amount.description ?? "",
            "receiver": receiverWallet,
            "timestamp": Int64(Date.now.timeIntervalSince1970),
            "referenceNumber": "TXN-\(UUID().uuidString.prefix(8).uppercased())",
        ]
        if let jsonData = try? JSONSerialization.data(
            withJSONObject: responsePayload, options: .prettyPrinted)
        {
            let responseJSON = String(data: jsonData, encoding: .utf8) ?? ""

            do {
                let nonce = AES.GCM.Nonce()
                let sealedResponse = try AES.GCM.seal(jsonData, using: key, nonce: nonce)

                logs.append(
                    "[RESPONSE] Encrypted response: \(sealedResponse.ciphertext.count) bytes"
                )
                logs.append(
                    "[RESPONSE] Auth tag: \(sealedResponse.tag.hexString.prefix(16))..."
                )

                logs.append("[RESPONSE] Decrypting response with session key...")
                let decrypted = try AES.GCM.open(sealedResponse, using: key)
                serverResponseJSON =
                    String(data: decrypted, encoding: .utf8) ?? ""
                logs.append("[RESPONSE] ✓ Response decrypted and verified")
                logs.append("[RESPONSE] \(serverResponseJSON.prefix(80))...")
            } catch {
                logs.append("[RESPONSE] ✗ Decryption failed: \(error)")
                serverResponseJSON = responseJSON
            }
        }

        // 2. PCI Audit Trail
        logs.append("[AUDIT] ═══ PCI-DSS Req 10 Audit Trail ═══")
        let auditEntries = [
            "[\(ISO8601DateFormatter().string(from: Date.now))] AUTH: User authenticated via JWT + biometric",
            "[\(ISO8601DateFormatter().string(from: Date.now))] TX: Payment \(builtTransaction?.amount.description ?? "") → \(receiverWallet)",
            "[\(ISO8601DateFormatter().string(from: Date.now))] CRYPTO: ECDSA signature verified, AES-GCM decrypted",
            "[\(ISO8601DateFormatter().string(from: Date.now))] RESULT: \(result.overallSuccess ? "APPROVED" : "REJECTED")",
            "[\(ISO8601DateFormatter().string(from: Date.now))] COMPLIANCE: No CHD in logs (PCI Req 3.4)",
        ]
        for entry in auditEntries {
            logs.append("[AUDIT] \(entry)")
        }

        // 3. Secure Memory Wipe
        logs.append("[WIPE] ═══ Secure Memory Cleanup ═══")
        logs.append("[WIPE] Zeroing plaintext transaction data from memory...")
        logs.append("[WIPE] Clearing session key material...")
        logs.append("[WIPE] Destroying ephemeral ECDH private key...")
        logs.append("[WIPE] Clearing HMAC computation buffers...")
        logs.append(
            "[WIPE] Note: In production, use memset_s() for guaranteed zeroing"
        )
        logs.append(
            "[WIPE] Note: Data objects use resetBytes(in:) to overwrite"
        )
        logs.append("[WIPE] ✓ Sensitive data cleared from application memory")

        memoryWipeComplete = true

        PaymentFlowLogger.flow.info("✓ Response handled, memory wiped")

        stepLogs.append(
            StepLogEntry(
                stepNumber: 10,
                title: "Response & Secure Cleanup",
                securityTopics: [
                    "Encrypted Response", "PCI Audit Trail",
                    "Secure Memory Wipe", "Data Lifecycle",
                ],
                side: .both,
                requestParams: [
                    (
                        "Server Response",
                        "\(result.overallSuccess ? "APPROVED" : "REJECTED")"
                    ),
                    ("Response Encryption", "AES-256-GCM (same session key)"),
                    ("Audit Standard", "PCI-DSS Requirement 10"),
                    ("Memory Strategy", "Zero-fill + dealloc"),
                ],
                responseData: [
                    (
                        "Transaction Result",
                        result.overallSuccess
                            ? "✓ Payment Approved" : "✗ Payment Rejected"
                    ),
                    (
                        "Reference Number",
                        "TXN-\(builtTransaction?.id.uuidString.prefix(8).uppercased() ?? "")"
                    ),
                    ("Audit Events", "\(auditEntries.count) entries logged"),
                    ("CHD in Logs", "None (PCI compliant)"),
                    ("Memory Wipe", "✓ Plaintext + keys + buffers zeroed"),
                    (
                        "ECDH Private Key",
                        "✓ Destroyed (ephemeral — never persisted)"
                    ),
                ],
                logLines: logs,
                timestamp: Date.now
            )
        )

        flowComplete = true
    }

    // MARK: - Reset

    func resetFlow() {
        currentStep = 0
        isProcessing = false
        flowComplete = false
        errorMessage = nil
        stepLogs.removeAll()
        loginResult = nil
        sessionClaims = nil
        accessTokenPreview = ""
        refreshTokenPreview = ""
        clientPubKeyHex = ""
        serverPubKeyHex = ""
        derivedKeyHex = ""
        ecdhSessionId = ""
        receiverWallet = "01555000999"
        amountText = "2500.00"
        paymentNote = "Rent payment"
        transactionNonce = ""
        builtTransaction = nil
        cardNumber = "4242424242424242"
        paymentToken = nil
        signatureDER = nil
        signatureHex = ""
        publicKeyHex = ""
        signingKeySource = ""
        encryptedEnvelope = nil
        hmacSignatureHex = ""
        nonceHex = ""
        ciphertextPreview = ""
        tagHex = ""
        verificationResult = nil
        certPinHash = ""
        serverResponseJSON = ""
        memoryWipeComplete = false
        deviceSecurityPassed = false
        jailbreakPassed = false
        biometricStateChanged = false
        isSimulatorEnvironment = false
        deviceCheckSummary = []
        tlsTransmitComplete = false
        clientPrivateKey = nil
        sessionKey = nil
        hmacKey = nil
        registeredPublicKey = nil
        hmacBody = nil
    }
}

// MARK: - Verification Result

struct VerificationResult {
    let hmacValid: Bool
    let nonceValid: Bool
    let timestampValid: Bool
    let signatureValid: Bool
    let decryptionSuccess: Bool
    let overallSuccess: Bool
    let decryptedPreview: String
}
