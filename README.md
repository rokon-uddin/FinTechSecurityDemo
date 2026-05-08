# FinTech iOS App Security: A Complete Engineering Guide from TLS to the Secure Enclave

## How to build a production-hardened iOS payment application — with real Swift code, cryptographic first principles, and the security mindset that separates senior engineers from everyone else

---

*When you're building a mobile payment product that handles real money, the cost of a security mistake isn't a failed test — it's a user's life savings. This guide is a complete walkthrough of every security layer a production FinTech iOS app demands: from how TLS 1.3 negotiates a handshake to how the Secure Enclave signs a transaction at the hardware level. We'll go deep, write real Swift, and explain the* why *behind every decision.*

---

## The Mental Model: Security Is a Stack

Before a single line of Swift, understand the layering. A FinTech iOS app has at least five distinct security layers, each providing a different guarantee. If any layer is missing, the layers above it are weakened:

```
┌────────────────────────────────────────┐
│  Layer 5: Payment & Business Logic     │  ← PCI-DSS, Tokenization, Non-Repudiation
├────────────────────────────────────────┤
│  Layer 4: Session & Identity           │  ← JWT, Token Rotation, Step-Up Auth
├────────────────────────────────────────┤
│  Layer 3: App Integrity                │  ← Jailbreak Detection, Code Signing
├────────────────────────────────────────┤
│  Layer 2: Data at Rest                 │  ← Keychain, Secure Enclave, Data Protection
├────────────────────────────────────────┤
│  Layer 1: Data in Transit              │  ← TLS 1.3, Certificate Pinning, ATS
└────────────────────────────────────────┘
```

We'll build upward from the network.

---

## Part 1: Securing the Wire — URLSession, TLS 1.3, and Certificate Pinning

### URLSession Is Not Just an HTTP Client

`URLSession` manages your entire security surface for network communication: connection pooling, credential storage, cookie persistence, and the TLS handshake lifecycle. The configuration you choose determines whether sensitive response data lands on disk or stays in memory. For a payment app, that distinction is critical.

```swift
// The three configurations — choose deliberately
let payConfig = URLSessionConfiguration.ephemeral
// ✓ No disk cache. No cookie persistence. No credential storage.
// Everything lives in memory and vanishes when the session is invalidated.

let defaultConfig = URLSessionConfiguration.default
// ✗ Writes response data to disk cache. Auth tokens can survive app restarts.
// Never use this for financial API endpoints.

let bgConfig = URLSessionConfiguration.background(withIdentifier: "com.app.kyc-upload")
// ✓ For large uploads (KYC documents) that must survive app termination.
// Understand: this writes to disk. Use it only for non-sensitive bulk transfers.
```

There is a subtler trap that catches most developers: **`URLSession.shared` cannot do certificate pinning.** The shared session is created with a `nil` delegate, and because the delegate is copied at initialization, you cannot assign one after the fact. If your app is doing anything security-sensitive on `URLSession.shared`, you have no pinning — any certificate from any CA will be silently accepted.

Production setup for a payment session looks like this:

```swift
final class NetworkSession {
    static let shared = NetworkSession()

    let paymentSession: URLSession

    private init() {
        let config = URLSessionConfiguration.ephemeral

        // Belt-and-suspenders: disable caching at both the request and session level
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil

        // Fail fast for payment UX — don't leave users hanging
        config.timeoutIntervalForRequest  = 30
        config.timeoutIntervalForResource = 60

        // We manage auth via Authorization header, not cookies
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies   = false
        config.httpCookieStorage      = nil

        // Security and idempotency headers on every request
        config.httpAdditionalHeaders = [
            "X-App-Version": Bundle.main.appVersion,
            "X-Platform":    "iOS",
            "X-Request-ID":  UUID().uuidString  // idempotency key
        ]

        // Custom delegate is mandatory for certificate pinning
        self.paymentSession = URLSession(
            configuration: config,
            delegate: PinningDelegate(),
            delegateQueue: nil
        )
    }
}
```

---

### TLS 1.3 — Understanding What Protects Your Data

TLS 1.3 (RFC 8446) is the protocol that encrypts every byte between your app and your server. Understanding it at the handshake level — not just "we use HTTPS" — separates engineers who can defend architectural decisions from those who can't.

**What TLS actually guarantees:**

- **Confidentiality** — Data is encrypted. Eavesdroppers see ciphertext.
- **Integrity** — Any modification in transit is detected. An attacker cannot flip a transaction amount without the server rejecting the message.
- **Authentication** — You're talking to the real server, not an impostor.

All three are required. Confidentiality without integrity is dangerous: an attacker who cannot *read* your data can still *corrupt* it.

**The TLS 1.3 handshake in one breath:**

The key innovation in TLS 1.3 is that the client sends its ECDH key share *in the first message*. The server can immediately derive shared keys and begin encrypting its response. The result is a **1-RTT** handshake — compared to 2-RTT in TLS 1.2 — and the certificate is now transmitted encrypted, not in plaintext.

```
Client                                     Server
  │──── ClientHello (+ ECDH key share) ────►│
  │◄═══ ServerHello + Certificate           │  ← Encrypted from here
  │◄═══ {CertificateVerify} ════════════════│  ← Server signs w/ private key
  │◄═══ {Finished} ═════════════════════════│
  │════ {Finished} ═════════════════════════►│
  │════ {Application Data} ═════════════════►│  ← 1 RTT total
```

**Perfect Forward Secrecy — why it matters for payment data:**

TLS 1.3 makes PFS mandatory by using ECDHE (Elliptic Curve Diffie-Hellman Ephemeral). Each session generates a new ephemeral key pair. The shared secret is derived and immediately discarded. No session key is ever stored.

The threat scenario without PFS: an attacker records all your encrypted traffic today. Six months from now, they compromise your server's private key (breach, court order, state actor). They can now decrypt every historical session — every transaction amount, every recipient account, every balance query — going back to the beginning. With PFS, recorded traffic is permanently safe because the session keys no longer exist.

**The one TLS 1.3 trap to memorize: 0-RTT resumption**

TLS 1.3 allows returning clients to send application data before the handshake completes using a pre-shared key. Zero round trips. It sounds attractive for latency, but **0-RTT data is vulnerable to replay attacks**: an intercepted request can be re-submitted verbatim. For a `POST /transfer` endpoint, this could mean a payment executes twice.

Never enable 0-RTT for any mutating endpoint. Only for idempotent GETs of static content.

To enforce TLS 1.3 programmatically via Apple's Network framework:

```swift
import Network

let tlsOptions = NWProtocolTLS.Options()
sec_protocol_options_set_min_tls_protocol_version(
    tlsOptions.securityProtocolOptions,
    .TLSv13
)
let params = NWParameters(tls: tlsOptions)
let connection = NWConnection(host: "api.fintech.com", port: 443, using: params)
```

---

### Certificate Pinning — Three Methods, One Goal

Standard TLS trusts any certificate signed by any of the hundreds of Certificate Authorities in the device trust store. A compromised or malicious CA can issue a valid certificate for your domain — and your app will accept it. Certificate pinning breaks this assumption by hardcoding expected cryptographic values and validating them on every handshake.

**Method 1: Full Certificate Pinning**
Pin the entire DER-encoded certificate. Maximum specificity. Breaks on every certificate renewal.

**Method 2: Public Key (SPKI) Pinning** ← *Recommended for production*
Pin the SHA-256 hash of the SubjectPublicKeyInfo — the public key and its algorithm metadata. Survives certificate renewals as long as the key pair is reused. Extract the pin with:

```bash
openssl s_client -connect api.fintech.com:443 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

**Method 3: CA/Intermediate Pinning**
Pin the issuing CA. More flexible but trusts the entire CA hierarchy. Only appropriate if you run your own internal CA.

Here is a production-grade SPKI pinning delegate:

```swift
import CryptoKit
import Security

final class SPKIPinner: NSObject, URLSessionDelegate {

    // Always pin at minimum 2 hashes: current + backup for rotation
    private static let pins: [String: Set<String>] = [
        "api.fintech.com": [
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",  // current
            "CXVN1p2FqLGh7asDFdxf5Mg7xqxz7VBrKJpb4R3qZtY="   // backup
        ]
    ]

    // ASN.1 header for EC keys — must be prepended before hashing
    private static let ecHeaderBytes: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    ]

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard
            challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let serverTrust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Step 1: Standard chain validation (expiry, revocation, CA chain)
        var cfError: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &cfError) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Step 2: Custom SPKI pin validation on top of standard TLS
        guard validateSPKIPin(serverTrust: serverTrust, host: challenge.protectionSpace.host) else {
            SecurityTelemetry.report(event: .pinFailure(host: challenge.protectionSpace.host))
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }

    private func validateSPKIPin(serverTrust: SecTrust, host: String) -> Bool {
        guard let expectedPins = SPKIPinner.pins[host],
              let cert       = SecTrustGetCertificateAtIndex(serverTrust, 0),
              let publicKey  = SecCertificateCopyKey(cert),
              let rawKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else { return false }

        var spki = Data(SPKIPinner.ecHeaderBytes)
        spki.append(rawKeyData)

        let hash       = SHA256.hash(data: spki)
        let hashBase64 = Data(hash).base64EncodedString()

        return expectedPins.contains(hashBase64)
    }
}
```

**The operational reality: pin rotation**

Pinning creates an operational hazard — a certificate change without a corresponding app update bricks your users. The strategy:

1. Always ship **N+1 pins**: the current key hash AND the hash of the next key pair, before you rotate.
2. Serve the upcoming pin in a signed API response *before* the rotation date. App versions can learn the next pin dynamically.
3. Enforce a minimum app version after rotation. Return `426 Upgrade Required` to old versions.
4. Have an emergency kill switch: a time-limited, server-signed flag that disables pinning enforcement. Fetched via an alternate channel. Only for catastrophic failure scenarios.

---

### App Transport Security — Harden the Policy Layer

ATS is Apple's network security policy, enforced at the OS level before your code runs. The defaults are reasonable, but a payment app should harden further:

```xml
<!-- Info.plist — Production ATS for a FinTech app -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Never. Not even for a "temporary" developer convenience. -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <key>NSExceptionDomains</key>
    <dict>
        <key>api.fintech.com</key>
        <dict>
            <!-- TLS 1.3 minimum — iOS 12.2+ -->
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.3</string>

            <!-- ECDHE cipher suites only — enforces PFS -->
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>

            <!-- Require cert to appear in Certificate Transparency logs -->
            <key>NSRequiresCertificateTransparency</key>
            <true/>

            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>
    </dict>
</dict>
```

`NSRequiresCertificateTransparency` is worth calling out: it forces iOS to verify that the server's certificate is logged in a public CT ledger. This prevents "private" certificate issuance by a CA — a rogue cert for your domain that was never publicly logged will be rejected by the OS before your URLSession delegate even fires.

---

### Concurrency: The Double Token Refresh Race Condition

There is a class of bug that exists in virtually every payment app using refresh tokens and callback-based networking. Two concurrent requests — say, a balance check and a transaction history load — both receive a `401 Unauthorized` at the same moment. Both detect an expired token. Both trigger a refresh simultaneously. The server processes both, invalidating the old refresh token twice. Depending on timing, one or both calls end up orphaned, and the user is silently logged out.

Swift actors solve this elegantly with compile-time enforcement:

```swift
actor TokenStore {
    private var accessToken: String?
    private var expiresAt:   Date?
    // This task reference is the key to serialization
    private var refreshTask: Task<String, Error>?

    func validToken(using refresher: TokenRefresher) async throws -> String {
        // Fast path: valid token in memory
        if let token = accessToken,
           let expiry = expiresAt,
           expiry > Date().addingTimeInterval(60) {
            return token
        }

        // Critical: if a refresh is already in-flight, JOIN it.
        // Don't start a second one. All callers await the same Task.
        if let existing = refreshTask {
            return try await existing.value
        }

        // Start exactly one refresh
        let task = Task<String, Error> {
            let refreshToken = try KeychainService.load(key: .refreshToken)
            let response     = try await refresher.refresh(token: refreshToken)
            try KeychainService.save(response.refreshToken, key: .refreshToken)
            await self.setToken(response.accessToken, expiresIn: response.expiresIn)
            return response.accessToken
        }
        refreshTask = task

        do {
            let result = try await task.value
            refreshTask = nil
            return result
        } catch {
            refreshTask = nil
            throw error
        }
    }
}
```

The actor's serial execution model makes the race condition structurally impossible. The compiler enforces it — you cannot access actor-isolated state without `await`, and the actor guarantees only one execution context enters at a time.

---

## Part 2: Data at Rest — Keychain, Cryptography, and the Secure Enclave

### Keychain: Not All Storage Is Equal

The Keychain is the correct place for all sensitive data in an iOS app. But the Keychain is not a simple database — it has a protection class system that determines when item keys are available, tied to the device hardware and the user's passcode.

The accessibility attribute is the most consequential choice you make:

| Attribute | When Accessible | Syncs to iCloud | Use For |
|---|---|---|---|
| `WhenUnlocked` | Device unlocked | Yes | — |
| **`WhenUnlockedThisDeviceOnly`** | Device unlocked | **No** | **Auth tokens, session data** |
| `AfterFirstUnlock` | After first unlock | Yes | — |
| `AfterFirstUnlockThisDeviceOnly` | After first unlock | No | Push notification processing |
| `WhenPasscodeSetThisDeviceOnly` | Unlocked + passcode set | No | Biometric-gated items |
| `Always` *(deprecated)* | Always | Yes | Never use |

The `ThisDeviceOnly` variants are critical: they exclude items from iCloud Keychain sync, iCloud backups, and device migration. A payment session token should never silently appear on a user's new iPhone. If it does, your device-binding and registration checks are worthless.

```swift
final class KeychainService {
    private static let service     = "com.fintech.ios"
    private static let accessGroup = "TEAMID.com.fintech.shared"

    static func save(_ data: Data, key: KeychainKey) throws {
        deleteIfExists(key: key)  // Prevent -25299 duplicate item error

        let query: [CFString: Any] = [
            kSecClass:              kSecClassGenericPassword,
            kSecAttrService:        service,
            kSecAttrAccount:        key.rawValue,
            kSecValueData:          data,
            kSecAttrAccessible:     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable: kCFBooleanFalse!,
            kSecAttrAccessGroup:    accessGroup
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
}
```

**The Keychain persistence gotcha:** Items persist after app deletion by default. A fresh install can read items written by a previous install. On first launch, check for a "clean install" marker in `UserDefaults` (which *is* cleared on delete). If `UserDefaults` is empty but the Keychain has data, you have stale credentials from a prior install — wipe the Keychain.

---

### Cryptography: AES-GCM, ECDH, HMAC, and RSA

Apple's CryptoKit makes safe cryptography remarkably ergonomic. Here are the patterns that matter in a payment app.

**AES-256-GCM: Authenticated Encryption**

GCM (Galois/Counter Mode) is an AEAD — Authenticated Encryption with Associated Data. One operation provides both confidentiality and integrity. The 16-byte authentication tag prevents any modification of the ciphertext from going undetected. Use this everywhere. Never use AES-CBC for new code — it provides confidentiality only and is vulnerable to padding oracle attacks.

```swift
import CryptoKit

// Encrypt a transaction payload before transmission
func encrypt(_ plaintext: Data, key: SymmetricKey) throws -> EncryptedEnvelope {
    // CryptoKit generates a cryptographically random 12-byte nonce automatically.
    // NEVER reuse a nonce with the same key — catastrophic in GCM.
    // Nonce reuse with the same key allows an attacker to XOR ciphertexts
    // and recover plaintext, plus forge authentication tags.
    let nonce = try AES.GCM.Nonce()

    let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)

    return EncryptedEnvelope(
        nonce:      Data(nonce),
        ciphertext: sealed.ciphertext,
        tag:        sealed.tag         // 16 bytes — detects any tampering
    )
}

// Decrypt — throws CryptoKitError.authenticationFailure if tampered
func decrypt(_ envelope: EncryptedEnvelope, key: SymmetricKey) throws -> Data {
    let nonce     = try AES.GCM.Nonce(data: envelope.nonce)
    let sealedBox = try AES.GCM.SealedBox(
        nonce:      nonce,
        ciphertext: envelope.ciphertext,
        tag:        envelope.tag
    )
    return try AES.GCM.open(sealedBox, using: key)
    // If the tag doesn't match, this throws. It does not silently return wrong data.
}
```

**ECDH + HKDF: Session Key Establishment**

When you need to establish a shared encryption key with the server — for something like end-to-end encrypting a PIN change — ECDH lets both parties compute the same secret without transmitting it. The security rests on the Elliptic Curve Discrete Logarithm Problem: an attacker observing both public keys cannot derive the shared secret.

```swift
import CryptoKit

// Client-side: generate ephemeral key pair for this session only
let clientPrivKey = P256.KeyAgreement.PrivateKey()  // ephemeral — discarded after

// Send clientPrivKey.publicKey.rawRepresentation to server
// Receive serverPublicKeyData from server

let serverPubKey  = try P256.KeyAgreement.PublicKey(
    rawRepresentation: serverPublicKeyData
)

// ECDH: compute shared secret
let sharedSecret = try clientPrivKey.sharedSecretFromKeyAgreement(with: serverPubKey)

// HKDF derivation — NEVER use the raw shared secret directly as an AES key.
// The ECDH output has mathematical structure. HKDF "randomizes" it into
// a uniform bit string suitable as a cryptographic key.
// The sharedInfo parameter binds the key to this specific session ID.
let sessionKey = sharedSecret.hkdfDerivedSymmetricKey(
    using: SHA256.self,
    salt:       "fintech-session-v1".data(using: .utf8)!,
    sharedInfo: sessionId.data(using: .utf8)!,
    outputByteCount: 32  // 256-bit AES key
)
// Both client and server derive identical keys. The secret was never transmitted.
```

**HMAC: API Request Signing**

Every API request should carry an HMAC-SHA256 signature over a canonical representation of the request. This proves the request came from a holder of the shared secret and was not modified after signing.

```swift
// Canonical request string — both client and server must produce identical bytes
// Format: METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body_hex)
let canonical = ["POST", "/api/v3/transfer",
                  String(timestamp), nonce,
                  SHA256.hash(data: bodyData).hexString]
    .joined(separator: "\n")

let key = MockBackend.hmacSecret  // shared secret from device registration
let mac = HMAC<SHA256>.authenticationCode(
    for: canonical.data(using: .utf8)!,
    using: key
)
// Send as: X-Fintech-Signature: <hex string>

// Server-side verification — constant-time comparison prevents timing attacks
let valid = HMAC<SHA256>.isValidAuthenticationCode(
    receivedMACBytes,        // received from client
    authenticating: canonical.data(using: .utf8)!,
    using: key
)
// isValidAuthenticationCode always takes the same time regardless of where
// a mismatch occurs — prevents attackers from guessing bytes via response time.
```

**RSA-OAEP: Key Wrapping**

RSA is not for encrypting data — it's slow and limited to roughly 190 bytes at 2048-bit. RSA is for *key wrapping*: encrypting a freshly generated AES key with the server's public key so only the server can recover it. The hybrid pattern is: **RSA wraps the AES key → AES encrypts the data**.

Always use `rsaEncryptionOAEPSHA256`. Never `rsaEncryptionPKCS1` — Bleichenbacher's 1998 padding oracle attack is still practical against PKCS#1 v1.5 implementations.

```swift
let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
var error: Unmanaged<CFError>?

// Wrap: encrypt AES key bytes with server's RSA public key
let wrappedKey = SecKeyCreateEncryptedData(
    serverPublicKey,
    algorithm,
    aesKeyBytes as CFData,
    &error
) as Data?

// OAEP output size = RSA key size = 256 bytes for RSA-2048, always
// OAEP is probabilistic: same input → different output every time
// This is a feature. PKCS#1 v1.5 is deterministic — a weakness.

// Unwrap: server uses private key
let unwrapped = SecKeyCreateDecryptedData(
    serverPrivateKey,
    algorithm,
    wrappedKey! as CFData,
    &error
) as Data?
```

---

### The Secure Enclave: Hardware-Level Security

The Secure Enclave is a dedicated coprocessor in every Apple device with an A7 chip or later. It has its own encrypted memory, its own boot ROM, and its own cryptographic engine. When you generate a P-256 key pair inside the Secure Enclave, the private key **never leaves the chip** — not even the main CPU, the OS, or your code can read it. Signing operations are performed inside the enclave; only the signature exits.

This changes the threat model fundamentally. Even a fully compromised iOS device cannot produce a valid transaction signature without the user's biometric.

```swift
import CryptoKit
import Security

// Device registration: generate hardware-bound key pair
// .biometryCurrentSet: Face ID required AND key invalidated if enrollment changes.
// If someone adds their fingerprint after theft, the key becomes inaccessible.
let access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet],
    nil
)!

let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)

// Store the opaque data representation in Keychain.
// This is NOT the raw private key — it's a hardware handle.
// Without this handle, you cannot reference the SE key again.
// With the handle but without the biometric, the SE won't sign.
let handleData = privateKey.dataRepresentation
try KeychainService.save(handleData, key: .deviceSigningKey)

// Upload the public key to your server during registration
let publicKeyForServer = privateKey.publicKey.rawRepresentation

// ── Transaction signing ──────────────────────────────────────────

// Load key from stored handle (no biometric required to load, only to use)
let restoredKey = try SecureEnclave.P256.Signing.PrivateKey(
    dataRepresentation: storedHandleData
)

// Construct canonical transaction bytes — what we're actually signing
// Both client and server must produce identical bytes from the same fields.
// Amount as integer paisa: never use Double for money.
// 0.1 + 0.2 = 0.30000000000000004 in IEEE 754. That's not a transaction amount.
let canonical = [
    transactionId,
    senderWallet,
    receiverWallet,
    String(amountPaisa),     // ← Int64 paisa, not Double BDT
    String(timestampUnix),
    serverIssuedNonce,       // prevents replay attacks
    currency
].joined(separator: "|").data(using: .utf8)!

// This call triggers Face ID on a real device.
// The biometric prompt is shown by Secure Enclave hardware — not your UI code.
// Even on a jailbroken device, this cannot be bypassed without the user's face/fingerprint.
let signature = try restoredKey.signature(for: canonical)
// Returns DER-encoded ECDSA P-256 signature (~70-72 bytes)

// Server-side verification — stateless, only needs the public key
let pubKey    = try P256.Signing.PublicKey(rawRepresentation: storedPublicKey)
let sig       = try P256.Signing.ECDSASignature(derRepresentation: signature.derRepresentation)
let isValid   = pubKey.isValidSignature(sig, for: canonical)
// isValid = true → non-repudiation established.
// The user cannot credibly deny this transaction.
```

---

## Part 3: Payment Layer Security

### PCI-DSS — What Actually Applies to Your iOS Code

PCI-DSS is the security standard for any system handling payment card data. The mobile app is in scope if it touches card numbers, expiry dates, or CVVs. The strategic goal is to **minimize what your code ever sees**.

The most important requirements that touch iOS code:

**Req 3 — Never store the PAN:** Not encrypted, not hashed — not at all. Store a token. Display only the last four digits. Never store CVV under any circumstance, even temporarily.

**Req 4 — Encrypt in transit:** TLS 1.2+ minimum (TLS 1.3 recommended). Your ATS configuration, certificate pinning, and ephemeral `URLSession` directly satisfy this.

**Req 6 — Secure development:** OWASP Mobile Top 10 coverage is explicitly required in PCI DSS v4.0. SAST scanning on every build. Security review checklist on every pull request touching payment flows.

**Req 10 — Log everything, but never log card data:** A log file containing a PAN is itself in PCI scope. Your logging layer must scrub sensitive patterns before writing:

```swift
final class SecureLogger {
    private static let scrubPatterns: [(pattern: String, replacement: String)] = [
        (#"\b\d{13,19}\b"#,                    "[CARD_REDACTED]"),   // PAN
        (#""pin"\s*:\s*"[^"]+""#,              #""pin":"[REDACTED]"#),
        (#""otp"\s*:\s*"[^"]+""#,              #""otp":"[REDACTED]"#),
        ("Bearer [A-Za-z0-9._-]+",             "Bearer [TOKEN]")
    ]

    static func log(_ message: String) {
        var safe = message
        for (pattern, replacement) in scrubPatterns {
            if let regex = try? NSRegularExpression(pattern: pattern) {
                safe = regex.stringByReplacingMatches(
                    in: safe,
                    range: NSRange(safe.startIndex..., in: safe),
                    withTemplate: replacement
                )
            }
        }
        // Now safe to write to OSLog
        os_log("%{public}@", safe)
    }
}
```

### Tokenization vs. Encryption — A Critical Distinction

These are not interchangeable. Understanding the difference is fundamental to designing a secure payment architecture.

**Encryption** is reversible with a key. If your key is compromised — through a breach, an extraction attack on a jailbroken device, or an insider — every encrypted record is exposed. Encryption protects data from eavesdroppers. It does not protect data from someone who compromises the system holding the key.

**Tokenization** replaces a card number with a random, meaningless token. The mapping lives in a separate, isolated token vault — a PCI Level 1 certified system your app never communicates with directly. Even if your app is fully compromised, an attacker retrieves tokens. A token like `pm_1A2B3C4D5E` without access to the vault is permanently useless.

The implementation principle: **never let raw card data touch your code.** Use a PCI-validated SDK (Stripe, Adyen, Checkout.com) that presents its own UI for card entry. The SDK submits the card directly to the gateway and hands your code a token. Your server stores the token, not the PAN. Your app uses the token for all subsequent operations.

---

### OTP, HOTP, and TOTP — From First Principles

Understanding the algorithm behind your OTP system means you can defend it in code review and explain what breaks if you get it wrong.

**HOTP (RFC 4226)** is counter-based:
`HOTP(secret, counter) = Truncate(HMAC-SHA1(secret, counter))`

Both client and server share an incrementing counter. The risk: counter desynchronization. If the user generates codes without submitting them, the client counter advances while the server counter doesn't.

**TOTP (RFC 6238)** replaces the incrementing counter with a time-derived counter:
`counter = floor(unix_time / 30)`

Both parties compute the same counter from wall-clock time. No synchronization needed — only clock agreement (with ±1 window tolerance for skew).

Here is a complete RFC 6238 implementation, built from the algorithm specification:

```swift
import CryptoKit

struct TOTPGenerator {
    let secret: Data
    let digits: Int         = 6
    let period: TimeInterval = 30

    func generate(at date: Date = Date()) -> String {
        let counter = UInt64(floor(date.timeIntervalSince1970 / period))
        return hotp(counter: counter)
    }

    // Validate with ±1 window tolerance for clock skew
    func validate(code: String, at date: Date = Date()) -> Bool {
        let counter  = UInt64(floor(date.timeIntervalSince1970 / period))
        // Bitwise overflow operators (&-) prevent UInt64 underflow at counter=0
        return [counter &- 1, counter, counter &+ 1].contains { hotp(counter: $0) == code }
    }

    // RFC 4226 §5 — HOTP core
    private func hotp(counter: UInt64) -> String {
        // Step 1: 8-byte big-endian counter
        var bigEndian = counter.bigEndian
        let msg       = Data(bytes: &bigEndian, count: 8)

        // Step 2: HMAC-SHA1 (SHA-1 is specified by RFC 4226; acceptable for HOTP/TOTP contexts)
        let mac = Data(HMAC<Insecure.SHA1>.authenticationCode(
            for: msg, using: SymmetricKey(data: secret)
        ))

        // Step 3: Dynamic truncation (RFC 4226 §5.4)
        let offset  = Int(mac[mac.count - 1] & 0x0F)
        let binCode: UInt32 =
            (UInt32(mac[offset])     & 0x7F) << 24 |
            (UInt32(mac[offset + 1]) & 0xFF) << 16 |
            (UInt32(mac[offset + 2]) & 0xFF) << 8  |
            (UInt32(mac[offset + 3]) & 0xFF)

        // Step 4: Modulo and zero-pad
        let otp = binCode % UInt32(pow(10.0, Double(digits)))
        return String(format: "%0\(digits)d", otp)
    }
}
```

One non-obvious security property: your server must track which codes have been used within the current time window. Without this, a code is valid for the entire 30-second window — an attacker who intercepts it has 30 seconds to replay it. Per-code consumption is the countermeasure.

---

### Session Management — The JWT Architecture That Doesn't Fail

JWTs are not inherently secure. The security comes from the *architecture* around them.

A production FinTech session uses three token types:

**Access Token (JWT)** — Short-lived (15 minutes). In-memory only — never written to disk. Sent in every API request as a Bearer token. Contains: `sub` (user ID), `walletId`, `deviceId`, `exp`, `iat`, `roles`, `sessionId`.

**Refresh Token** — Long-lived (7–30 days). Opaque random string, not a JWT. Stored in Keychain with `WhenUnlockedThisDeviceOnly`. Single-use with rotation: each refresh call invalidates the old token and issues a new one. If a server sees an old refresh token presented again, it revokes the entire token family and forces re-login. This detects and limits the damage from stolen refresh tokens.

**Step-Up Authorization Token** — Very short-lived (2 minutes). Issued after biometric re-confirmation. Required for transactions above a threshold. A stolen session cannot drain an account — the attacker needs the user's biometric too.

```swift
actor SessionService {
    // Access token: in memory only. Never write to disk.
    private var accessToken:    String?
    private var accessTokenExp: Date?

    // Refresh serialization: prevents the double-refresh race
    private var refreshTask: Task<String, Error>?

    func validAccessToken() async throws -> String {
        // 60-second safety buffer before actual expiry
        if let token = accessToken,
           let expiry = accessTokenExp,
           expiry > Date().addingTimeInterval(60) {
            return token
        }

        // Join an in-flight refresh rather than starting another
        if let existing = refreshTask {
            return try await existing.value
        }

        let task = Task<String, Error> {
            let refreshToken = try KeychainService.load(key: .refreshToken)
            let bundle       = try await AuthBackend.refresh(token: refreshToken)

            // ROTATION: the new refresh token replaces the old one.
            // Server invalidates the old token. If it's replayed: alarm.
            try KeychainService.save(bundle.refreshToken, key: .refreshToken)
            await self.store(accessToken: bundle.accessToken, expiresIn: bundle.expiresIn)
            return bundle.accessToken
        }
        refreshTask = task

        do {
            let result  = try await task.value
            refreshTask = nil
            return result
        } catch {
            refreshTask  = nil
            await logout()   // genuine refresh failure = session is dead
            throw SessionError.sessionExpired
        }
    }

    func logout() async {
        accessToken    = nil
        accessTokenExp = nil
        refreshTask    = nil
        KeychainService.wipeSessionData()
        // Post notification to UI layer to show login screen
        NotificationCenter.default.post(name: .sessionExpired, object: nil)
    }
}
```

One architectural note on JWTs that is frequently misunderstood: the JWT payload is base64url-encoded, not encrypted. Anyone who intercepts a JWT can decode and read all the claims without a key. Never put a PIN, card number, balance, or any sensitive value in a JWT payload. The security property of a JWT is in the *signature* — proving the token came from your auth server — not in the confidentiality of its contents.

---

## Part 4: Runtime Integrity — Defending Against Reverse Engineering

### Jailbreak Detection: Defense in Depth

A jailbroken device has its security model broken. The sandbox is bypassed. Frida can hook any function at runtime. SSL Kill Switch 2 can override certificate pinning entirely. For a payment app, a jailbroken device is a hostile environment that you cannot trust.

No single detection signal is reliable — each can be bypassed individually on a sufficiently motivated adversary. The strategy is to layer many diverse signals so the cost of bypassing all of them is prohibitively high:

```swift
enum JailbreakDetector {
    static func isCompromised() -> Bool {
        // 1. Known jailbreak filesystem artifacts
        let jailbreakPaths = [
            "/Applications/Cydia.app", "/Applications/Sileo.app",
            "/usr/sbin/sshd", "/bin/bash", "/etc/apt",
            "/var/jb",                          // rootless jailbreak (Dopamine, etc.)
            "/usr/lib/libhooker.dylib",          // LibHooker
            "/usr/lib/TweakInject.dylib"         // TweakInject
        ]
        if jailbreakPaths.contains(where: FileManager.default.fileExists(atPath:)) {
            return true
        }

        // 2. Sandbox escape: apps cannot write to /private/var on stock iOS
        let testPath = "/private/var/mobile/jb_probe_\(arc4random())"
        if (try? "test".write(toFile: testPath, atomically: true, encoding: .utf8)) != nil {
            try? FileManager.default.removeItem(atPath: testPath)
            return true
        }

        // 3. Injected hooking libraries (Substrate, Frida, SSL Kill Switch)
        let suspiciousLibs = ["SubstrateLoader", "frida", "SSLKillSwitch",
                               "libhooker", "cycript", "TweakInject"]
        let imageCount = _dyld_image_count()
        for i in 0..<UInt32(imageCount) {
            if let name = _dyld_get_image_name(i) {
                let imgName = String(cString: name).lowercased()
                if suspiciousLibs.contains(where: imgName.contains) {
                    return true
                }
            }
        }

        // 4. fork() entitlement: App Store apps cannot fork
        let pid = fork()
        if pid >= 0 {
            if pid > 0 { kill(pid, SIGTERM) }
            return true
        }

        // 5. Debugger detection via sysctl
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        sysctl(&mib, 4, &info, &size, nil, 0)
        if (info.kp_proc.p_flag & P_TRACED) != 0 { return true }

        return false
    }
}
```

**What attackers do to bypass this:** A Frida script can hook the `isCompromised` function by name and always return `false`. The countermeasures: don't name your function `isCompromised`. Distribute the checks throughout the codebase rather than concentrating them in one place. Use C-level functions where possible — they're harder to swizzle than Swift methods. Combine with commercial obfuscation (Guardsquare iXGuard) for production. And run checks not just at launch but immediately before every transaction.

---

## Part 5: The OWASP Mobile Top 10 — Mapped to Your Codebase

OWASP Mobile Top 10 2024 is not an abstract checklist. Each entry is a concrete failure mode with a concrete fix. PCI DSS v4.0 Requirement 6.3 explicitly requires addressing this list.

**M1 — Improper Credential Usage:** Hardcoded API keys in source code. An attacker runs `strings YourApp.app/YourApp | grep -i key` and finds your production secret. Fix: all secrets from secure runtime config, zero credentials in source or Info.plist.

**M2 — Inadequate Supply Chain Security:** A dependency update silently reads the clipboard — which may contain a copied OTP. Fix: lock all dependency versions, audit each SDK's privacy manifest (`PrivacyInfo.xcprivacy`), review requested entitlements.

**M3 — Insecure Authentication:** App makes authorization decisions based on JWT claims without the server re-verifying. An attacker modifies the payload (not the signature portion — the server never checked) and gets elevated access. Fix: all authorization decisions server-side, always.

**M5 — Insecure Communication:** No certificate pinning. A corporate MDM installs an SSL inspection certificate, and all transaction data is visible to the network operator. Fix: SPKI pinning on all payment endpoints.

**M6 — Inadequate Privacy Controls:** Crashlytics has default settings. When the app crashes mid-transaction, the crash report includes a full UIView hierarchy dump, which contains rendered transaction amounts and wallet numbers. Fix: configure crash reporters to exclude sensitive views, implement the scrubbing logger shown above.

**M9 — Insecure Data Storage:** Auth token in `UserDefaults`. On a jailbroken device, any app can read another app's `UserDefaults` if the sandbox is bypassed. Fix: Keychain with `WhenUnlockedThisDeviceOnly`, always.

**M10 — Insufficient Cryptography:** MD5 for transaction ID generation. MD5 produces collisions — two distinct transactions can have the same ID, causing server-side confusion. Fix: Use `UUID()` (CSPRNG-backed on Apple platforms) for all identifiers. Use CryptoKit for all cryptography — its API physically cannot use deprecated algorithms.

---

## Putting It Together: The Security Timeline for a Money Transfer

A complete secure payment flow, from user intent to transaction settlement:

```
T+0s   User taps "Send ৳500"
       → JailbreakDetector.isCompromised() — abort if true

T+0.1s Biometry changed detection
       → Compare LAContext.evaluatedPolicyDomainState to stored value
       → If changed: force re-authentication before proceeding

T+0.2s Fetch server-issued nonce
       → POST /api/v3/nonce (HMAC-signed request)
       → Server returns single-use nonce (TTL: 5 minutes)

T+0.5s Build canonical transaction bytes
       → txId|from|to|amountPaisa|timestamp|nonce|currency (UTF-8)
       → Amount is Int64 paisa — no floating-point

T+0.6s Sign with Secure Enclave
       → SecureEnclave.P256.Signing.PrivateKey.signature(for: canonical)
       → Face ID prompt fires — hardware-enforced biometric confirmation
       → Returns DER-encoded ECDSA P-256 signature

T+1.2s Fetch valid access token
       → TokenStore.validToken() — refreshes transparently if within 60s buffer
       → Actor serializes concurrent requests — one refresh, always

T+1.3s Encrypt payload
       → AES.GCM.seal(transactionJSON, using: sessionKey)
       → Fresh nonce generated for each encryption

T+1.4s Sign the HTTP request
       → HMAC-SHA256(secret, canonical_request_string)
       → Set X-Fintech-Signature header

T+1.5s Transmit
       → HTTPS over TLS 1.3 with ECDHE
       → Certificate pinning validates on URLSession delegate
       → URLSessionConfiguration.ephemeral — no disk cache

T+1.8s Server processing
       → Verify HMAC signature
       → Validate nonce (consumed — cannot be replayed)
       → Validate timestamp (reject if >5 minutes old)
       → AES-GCM decrypt payload (authentication tag verified)
       → ECDSA P-256 signature verification against registered public key
       → Process payment

T+2.1s Response
       → AES-GCM encrypted response body
       → Audit event logged (PCI Req 10, no CHD in log)

T+2.2s UI update
       → Decrypt response
       → Display confirmation
       → Wipe plaintext amounts from memory
```

Every step in this chain has a specific threat it neutralizes. Jailbreak detection addresses runtime manipulation. Nonce + timestamp addresses replay. HMAC addresses tampering in transit. AES-GCM addresses eavesdropping. Certificate pinning addresses MITM. Secure Enclave signing addresses session hijacking and non-repudiation. The Keychain with `ThisDeviceOnly` addresses device theft. None of them is sufficient alone.

---

## The Demo Project

All of the concepts in this guide — AES-GCM encryption, HMAC request signing, ECDH session key establishment, RSA key wrapping, Secure Enclave transaction signing, PCI-DSS tokenization, TOTP/OTP implementation, and JWT session management — are implemented as a complete, working SwiftUI project with a mock backend, SOLID architecture, and a Swift Testing test suite.

Each topic is an interactive tab where you can enter real transaction values, observe the cryptographic operations at each step, simulate tampering and watch the authentication fail, and read the audit log that proves no sensitive data was leaked.

**GitHub Repository:**
[https://github.com/rokon-uddin/FinTechSecurityDemo.git](https://github.com/rokon-uddin/FinTechSecurityDemo.git)

The project is structured around the principle that security knowledge should be *demonstrable*, not just declarable. Clone it, run it on a real device, and watch Face ID gate a hardware-bound transaction signature.

---

## Closing Thoughts

Security in a FinTech iOS app is not a feature you add at the end. It's a set of architectural decisions made at the beginning that either constrain or enable everything that follows. Using `URLSession.shared` instead of a custom delegate is not a minor convenience — it's the decision to have no certificate pinning. Using `UserDefaults` instead of Keychain is not laziness — it's leaving session tokens readable without the device passcode.

The engineers who are genuinely dangerous in this space are the ones who understand not just *what* the security controls are, but *why* they exist — what attack they neutralize, what happens when they're absent, and how they interact with every other layer of the stack. That understanding is what makes the difference between an app that passes a security review and an app that actually protects real people's money.

---

*Tagged: iOS Development, Swift, Mobile Security, Cryptography, FinTech, PCI-DSS, TLS, Secure Enclave, Payment Systems*