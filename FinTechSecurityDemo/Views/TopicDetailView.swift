//
//  TopicDetailView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//




import SwiftUI

// MARK: - Topic Data Model

struct TopicDetail {
    let title: String
    let icon: String
    let accentColor: Color
    let brief: String
    let whenToUse: [String]
    let whenNotToUse: [String]
    let advantages: [String]
    let disadvantages: [String]
    let resources: [TopicResource]
    let realWorldExample: String?
    let keyTakeaway: String?
}

struct TopicResource: Identifiable {
    let id = UUID()
    let label: String
    let title: String
    let urlString: String?
}

// MARK: - All Topic Details

enum TopicDetails {

    static let aesGCM = TopicDetail(
        title: "AES-256-GCM",
        icon: "lock.shield.fill",
        accentColor: .ftAccent,
        brief: "AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) is an authenticated encryption algorithm that provides both confidentiality and integrity in a single operation. It encrypts data using a 256-bit symmetric key and produces a 16-byte authentication tag that detects any tampering. Apple's CryptoKit makes AES-GCM the default choice for symmetric encryption on iOS.",
        whenToUse: [
            "Encrypting payment transaction payloads before sending to server",
            "Encrypting sensitive data at rest (cached transactions, local storage)",
            "Any scenario needing both confidentiality and tamper detection",
            "Application-layer encryption on top of TLS for defense-in-depth",
            "Encrypting PIN change payloads over ECDH-derived session keys"
        ],
        whenNotToUse: [
            "When you only need to verify data integrity without encryption — use HMAC instead",
            "For asymmetric (public/private key) scenarios — use RSA or ECDH",
            "When the same key+nonce pair might be reused — GCM catastrophically fails on nonce reuse",
            "For password hashing — use bcrypt, scrypt, or Argon2 instead",
            "For digital signatures or non-repudiation — use ECDSA"
        ],
        advantages: [
            "Single-pass authenticated encryption: confidentiality + integrity in one operation",
            "Hardware-accelerated on Apple Silicon (AES-NI instructions)",
            "CryptoKit provides a safe, hard-to-misuse API",
            "Authentication tag detects even a single flipped bit",
            "Stream cipher mode: ciphertext is same length as plaintext (no padding overhead)",
            "Supports Associated Data (AAD) — authenticate metadata without encrypting it"
        ],
        disadvantages: [
            "Nonce reuse with the same key is catastrophic — reveals plaintext XOR and breaks authentication",
            "Requires a shared symmetric key — key distribution is a separate problem (see ECDH, RSA)",
            "Maximum ~64 GB per single encryption with one nonce (practical limit rarely hit)",
            "Not suitable for very large streaming data without chunking",
            "GCM's GHASH is vulnerable to key-recovery if nonces are reused — no recovery possible"
        ],
        resources: [
            TopicResource(label: "Apple Docs", title: "CryptoKit — AES.GCM", urlString: "https://developer.apple.com/documentation/cryptokit/aes/gcm"),
            TopicResource(label: "NIST", title: "SP 800-38D — GCM Recommendation", urlString: "https://csrc.nist.gov/publications/detail/sp/800-38d/final"),
            TopicResource(label: "WWDC", title: "WWDC 2019 — Cryptography and Your Apps", urlString: "https://developer.apple.com/videos/play/wwdc2019/709/"),
            TopicResource(label: "RFC", title: "RFC 5116 — AEAD Interface", urlString: "https://datatracker.ietf.org/doc/html/rfc5116")
        ],
        realWorldExample: "In FinTech, every transaction payload is AES-GCM encrypted before transmission. Even if TLS is compromised, the payload remains encrypted. The authentication tag ensures an attacker cannot modify the amount or recipient without detection.",
        keyTakeaway: "AES-GCM = Encrypt + Authenticate in one step. Never reuse a nonce. Let CryptoKit generate nonces for you."
    )

    static let hmac = TopicDetail(
        title: "HMAC-SHA256",
        icon: "signature",
        accentColor: Color(red: 0.95, green: 0.50, blue: 0.10),
        brief: "HMAC (Hash-based Message Authentication Code) uses a shared secret key and a cryptographic hash function (SHA-256) to produce an authentication code for a message. It proves that a message was created by someone holding the secret key and that it was not modified in transit. Unlike encryption, HMAC does not hide the message — it only authenticates it.",
        whenToUse: [
            "API request signing — every request includes an HMAC signature header",
            "Webhook verification — validate that callbacks come from a trusted source",
            "Verifying data integrity without needing confidentiality",
            "Replay attack prevention (combined with timestamp + nonce in the signed string)",
            "Session token validation where the server needs to verify token authenticity"
        ],
        whenNotToUse: [
            "When you need to hide (encrypt) the data — HMAC only authenticates, it doesn't encrypt",
            "For digital signatures with non-repudiation — HMAC uses a shared secret, so either party could have produced it",
            "For password storage — use bcrypt/Argon2 instead (HMAC is not a password hash)",
            "When you already have AEAD encryption (AES-GCM includes authentication)"
        ],
        advantages: [
            "Simple, fast, and well-understood — minimal implementation risk",
            "Constant-time verification via CryptoKit's isValidAuthenticationCode (prevents timing attacks)",
            "Based on battle-tested hash functions (SHA-256)",
            "Small output size — 32 bytes for SHA-256",
            "Works with any data size — no block size limitations"
        ],
        disadvantages: [
            "Requires a shared secret — both parties must have the same key",
            "No non-repudiation — either party holding the key could have generated the HMAC",
            "Does not provide confidentiality — message is sent in plaintext",
            "Key distribution problem — how do client and server agree on the secret securely?"
        ],
        resources: [
            TopicResource(label: "RFC", title: "RFC 2104 — HMAC Specification", urlString: "https://datatracker.ietf.org/doc/html/rfc2104"),
            TopicResource(label: "Apple Docs", title: "CryptoKit — HMAC", urlString: "https://developer.apple.com/documentation/cryptokit/hmac"),
            TopicResource(label: "OWASP", title: "REST Security — Request Signing", urlString: "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"),
            TopicResource(label: "Article", title: "AWS Signature V4 (uses HMAC-SHA256)", urlString: "https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html")
        ],
        realWorldExample: "Every FinTech API request includes an X-FinTech-Signature header containing HMAC-SHA256(secret, METHOD|PATH|TIMESTAMP|NONCE|SHA256(body)). The server reconstructs the same string and verifies using constant-time comparison.",
        keyTakeaway: "HMAC = 'This message is authentic and untampered.' Always use constant-time comparison. Include a timestamp and nonce in the signed string to prevent replay attacks."
    )

    static let ecdh = TopicDetail(
        title: "ECDH Key Agreement",
        icon: "arrow.triangle.2.circlepath",
        accentColor: Color(red: 0.30, green: 0.70, blue: 1.0),
        brief: "ECDH (Elliptic Curve Diffie-Hellman) allows two parties to establish a shared secret over an insecure channel without ever transmitting the secret itself. Each party generates an ephemeral key pair, exchanges public keys, and independently computes the same shared secret using the Elliptic Curve Discrete Logarithm Problem. The raw shared secret is then passed through HKDF to derive a usable AES session key.",
        whenToUse: [
            "Establishing end-to-end encrypted sessions (PIN change, device registration)",
            "When both parties need to derive the same key without a pre-shared secret",
            "Perfect Forward Secrecy — ephemeral keys mean past sessions stay safe if long-term keys are compromised",
            "TLS 1.3 handshakes (ECDHE is mandatory)",
            "Any scenario requiring a secure key agreement protocol"
        ],
        whenNotToUse: [
            "When you already have a pre-shared symmetric key — just use AES-GCM directly",
            "For one-way key transport where only one party generates the key — use RSA-OAEP wrapping",
            "When you need non-repudiation or digital signatures — use ECDSA instead",
            "For encrypting data directly — ECDH produces a key, not ciphertext"
        ],
        advantages: [
            "Perfect Forward Secrecy with ephemeral keys — compromise of long-term keys doesn't expose past sessions",
            "Small key sizes: P-256 provides 128-bit security with only 32-byte keys (vs. 384 bytes for RSA-3072)",
            "Fast on mobile hardware — elliptic curve math is hardware-accelerated on Apple devices",
            "Neither party ever transmits the shared secret",
            "CryptoKit provides a clean, type-safe API (P256.KeyAgreement)"
        ],
        disadvantages: [
            "Requires a round-trip — both parties must exchange public keys before deriving the shared secret",
            "Vulnerable to man-in-the-middle if public keys aren't authenticated (pin or sign them)",
            "The raw ECDH output has mathematical structure — must use HKDF to derive a uniform AES key",
            "Does not provide authentication by itself — combine with signatures or a pre-authenticated channel"
        ],
        resources: [
            TopicResource(label: "Apple Docs", title: "CryptoKit — P256.KeyAgreement", urlString: "https://developer.apple.com/documentation/cryptokit/p256/keyagreement"),
            TopicResource(label: "RFC", title: "RFC 5869 — HKDF", urlString: "https://datatracker.ietf.org/doc/html/rfc5869"),
            TopicResource(label: "Visual", title: "tls13.xargs.org — TLS 1.3 Handshake", urlString: "https://tls13.xargs.org"),
            TopicResource(label: "NIST", title: "SP 800-56A — Key Agreement Schemes", urlString: "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final")
        ],
        realWorldExample: "When a FinTech user initiates a PIN change, the app performs ECDH with the server to derive a session-specific AES key. The new PIN is encrypted with this key before transmission. Even FinTech's own infrastructure cannot read the PIN in transit.",
        keyTakeaway: "ECDH = Two parties compute the SAME secret without ever sending it. Always use ephemeral keys for PFS. Always use HKDF to derive the final AES key."
    )

    static let rsa = TopicDetail(
        title: "RSA-OAEP Key Wrapping",
        icon: "key.fill",
        accentColor: Color(red: 0.70, green: 0.45, blue: 1.0),
        brief: "RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm where data encrypted with the public key can only be decrypted with the private key. In fintech, RSA is used for key wrapping — encrypting a small symmetric key (AES-256) so only the server's private key can recover it. RSA-OAEP (Optimal Asymmetric Encryption Padding) is the secure padding mode; PKCS#1 v1.5 is vulnerable to Bleichenbacher's padding oracle attack.",
        whenToUse: [
            "Key transport — securely delivering an AES key to a server using its public key",
            "Hybrid encryption — RSA wraps the AES key, AES-GCM encrypts the actual data",
            "Device registration — wrapping client-generated keys with a server certificate",
            "When you need one-way key delivery without a round-trip (unlike ECDH)",
            "Legacy system integration where RSA is the established standard"
        ],
        whenNotToUse: [
            "Encrypting large data directly — RSA-2048 can only encrypt ~190 bytes with OAEP",
            "When Perfect Forward Secrecy is required — use ECDH instead (RSA keys are long-lived)",
            "For digital signatures on iOS — prefer ECDSA P-256 (smaller, faster, SE-compatible)",
            "Never use PKCS#1 v1.5 padding — vulnerable to Bleichenbacher's 1998 attack",
            "When performance matters — RSA is orders of magnitude slower than ECC"
        ],
        advantages: [
            "Well-understood, decades of cryptanalysis — very mature algorithm",
            "One-way delivery: no round-trip needed (unlike ECDH)",
            "OAEP padding is provably secure under standard assumptions",
            "Widely supported across all platforms and languages",
            "Probabilistic encryption — same plaintext produces different ciphertext each time with OAEP"
        ],
        disadvantages: [
            "Large key sizes: RSA-2048 = 256-byte keys and ciphertexts (vs. 32 bytes for P-256)",
            "Slow: modular exponentiation is expensive, especially on mobile",
            "No Perfect Forward Secrecy: if the server's private key is compromised, all past wrapped keys are exposed",
            "Plaintext size limit: RSA-2048 with OAEP-SHA256 can wrap at most ~190 bytes",
            "PKCS#1 v1.5 padding is still widely used despite being broken — easy to misconfigure"
        ],
        resources: [
            TopicResource(label: "Apple Docs", title: "Security Framework — SecKeyCreateEncryptedData", urlString: "https://developer.apple.com/documentation/security/seckeycreatencrypteddata(_:_:_:_:)"),
            TopicResource(label: "RFC", title: "RFC 8017 — PKCS#1 v2.2 (RSA + OAEP)", urlString: "https://datatracker.ietf.org/doc/html/rfc8017"),
            TopicResource(label: "Attack", title: "Bleichenbacher '98 Padding Oracle Attack", urlString: "https://link.springer.com/chapter/10.1007/BFb0055716"),
            TopicResource(label: "WWDC", title: "WWDC 2019 — Cryptography and Your Apps", urlString: "https://developer.apple.com/videos/play/wwdc2019/709/")
        ],
        realWorldExample: "During FinTech device registration, the app generates an AES-256 key and wraps it with the server's RSA-2048 public key using OAEP-SHA256. The wrapped key is sent to the server, which unwraps it with its private key. Both sides now share an AES key for encrypting card tokenization data.",
        keyTakeaway: "RSA is for key wrapping, not data encryption. Always use OAEP padding. Pattern: RSA wraps AES key, AES-GCM encrypts data."
    )

    static let secureEnclave = TopicDetail(
        title: "Secure Enclave",
        icon: "cpu",
        accentColor: Color(red: 0.10, green: 0.80, blue: 0.55),
        brief: "The Secure Enclave is a dedicated hardware security coprocessor in Apple devices with its own encrypted memory, boot ROM, and hardware random number generator. Private keys generated inside never leave the chip — not even the main CPU can read them. Signing operations happen inside the enclave; only the signature exits. Combined with biometric gating (Face ID / Touch ID), this provides hardware-backed non-repudiation for transaction signing.",
        whenToUse: [
            "Transaction signing — cryptographic proof that a specific device authorized a payment",
            "Non-repudiation — user cannot deny authorizing a transaction signed by their SE key",
            "Biometric-gated operations — Face ID must confirm before the SE key can be used",
            "Device attestation — proving a request came from a genuine, uncompromised device",
            "Any scenario where the private key must never be extractable"
        ],
        whenNotToUse: [
            "For symmetric encryption (AES) — SE only supports P-256 ECDSA and key agreement",
            "When you need to export or back up the private key — SE keys are non-exportable by design",
            "For Simulator testing — SE is unavailable; use software P-256 fallback with clear labeling",
            "For server-side operations — SE is a client-side hardware feature",
            "When cross-device key sharing is required — each SE generates unique, device-bound keys"
        ],
        advantages: [
            "Hardware isolation: private key never leaves the coprocessor chip",
            "Biometric gating at the hardware level — even a jailbroken device can't bypass it",
            "Immune to software key extraction attacks (memory dumps, debugging)",
            "Non-repudiation: signature proves user presence + specific device + specific transaction",
            "CryptoKit provides clean API: SecureEnclave.P256.Signing.PrivateKey",
            "Keys survive app reinstalls (tied to Keychain + hardware)"
        ],
        disadvantages: [
            "Only supports P-256 (secp256r1) — no RSA, no Ed25519, no P-384",
            "Not available on Simulator — requires real hardware for full testing",
            "Key is invalidated if biometric enrollment changes (new face/fingerprint registered)",
            "No key backup or migration — if device is lost, key is gone (server must handle re-registration)",
            "Opaque key handle — you can't inspect or export the raw private key bytes"
        ],
        resources: [
            TopicResource(label: "Apple Docs", title: "SecureEnclave.P256.Signing — CryptoKit", urlString: "https://developer.apple.com/documentation/cryptokit/secureenclave"),
            TopicResource(label: "Apple", title: "Apple Platform Security Guide — Secure Enclave", urlString: "https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web"),
            TopicResource(label: "FIDO", title: "FIDO2 / WebAuthn Specification", urlString: "https://fidoalliance.org/fido2/"),
            TopicResource(label: "NIST", title: "FIPS 186-5 — Digital Signature Standard (ECDSA)", urlString: "https://csrc.nist.gov/publications/detail/fips/186/5/final")
        ],
        realWorldExample: "During FinTech device registration, a P-256 key pair is generated inside the Secure Enclave. The public key is uploaded to FinTech servers. For every high-value transaction, the app signs the canonical transaction bytes inside the SE (Face ID required). The server verifies the signature — proving this specific device, confirmed by biometrics, authorized this exact transaction.",
        keyTakeaway: "Secure Enclave = Private key that NEVER leaves the hardware chip. Face ID gates every signing operation. This is cryptographic non-repudiation."
    )

    static let pciTokenization = TopicDetail(
        title: "PCI Tokenization",
        icon: "creditcard.fill",
        accentColor: Color(red: 0.95, green: 0.20, blue: 0.15),
        brief: "Tokenization replaces sensitive payment data (card numbers, wallet accounts) with a random, meaningless token. Unlike encryption, tokens cannot be reversed without access to a separate, hardened token vault. This dramatically reduces PCI-DSS scope — your app stores tokens, never real card numbers. PCI-DSS v4.0 Requirements 3, 4, 6, 8, and 10 directly impact iOS code handling payment data.",
        whenToUse: [
            "Storing payment card references on device or server — always tokenize",
            "Displaying card info to users — show only last 4 digits from the token metadata",
            "Recurring payments — store and reuse the payment token, never the card number",
            "Any scenario where PCI-DSS scope reduction is desired",
            "When integrating with payment gateways (Stripe, Adyen) — they handle tokenization"
        ],
        whenNotToUse: [
            "For data that needs to be reversed frequently — tokenization is one-way without vault access",
            "For non-payment data where encryption is sufficient",
            "When you need the actual card number for processing — that's the gateway's job, not your app's"
        ],
        advantages: [
            "Dramatically reduces PCI-DSS scope — tokens are not cardholder data",
            "If app is compromised, tokens are worthless without vault access",
            "Token vault is a separate, isolated, PCI Level 1 certified system",
            "Tokens can be format-preserving (same length as original) for compatibility",
            "No key management burden on the app — unlike encryption"
        ],
        disadvantages: [
            "Requires a token vault service (Stripe, Adyen, or self-hosted)",
            "One more network dependency — vault must be available for detokenization",
            "Not suitable for offline scenarios where original data is needed",
            "Token-to-card mapping is a high-value target — vault security is critical"
        ],
        resources: [
            TopicResource(label: "Standard", title: "PCI DSS v4.0", urlString: "https://www.pcisecuritystandards.org"),
            TopicResource(label: "PCI SSC", title: "Tokenization Product Security Guidelines", urlString: "https://www.pcisecuritystandards.org/documents/Tokenization_Product_Security_Guidelines.pdf"),
            TopicResource(label: "Stripe", title: "How Tokenization Works", urlString: "https://stripe.com/docs/security/guide"),
            TopicResource(label: "NIST", title: "SP 800-63B — Authentication Guidelines", urlString: "https://pages.nist.gov/800-63-3/sp800-63b.html")
        ],
        realWorldExample: "When a FinTech user adds a card, the raw card data goes to a PCI-validated SDK (e.g., Stripe Elements). The SDK tokenizes it and returns pm_8f3bKL9qR2. Your app stores only this token. For payments, the app sends { amount, token, signature } — the real card number never touches your code or server.",
        keyTakeaway: "Never store real card numbers. Tokenize everything. If your app is breached, tokens are permanently useless without the isolated vault."
    )

    static let otpTotp = TopicDetail(
        title: "OTP & TOTP",
        icon: "lock.rotation",
        accentColor: Color(red: 0.30, green: 0.80, blue: 1.0),
        brief: "OTP (One-Time Password) is a single-use code for authentication. SMS OTP sends a random code via text message. TOTP (Time-based OTP, RFC 6238) generates codes locally using HMAC-SHA1(secret, floor(time/30)) — no network call needed. Both app and server independently compute the same code from a shared secret and the current time window. HOTP (RFC 4226) is the counter-based variant.",
        whenToUse: [
            "Two-factor authentication for login and high-value operations",
            "Step-up authentication for transactions above a threshold",
            "TOTP: when you want offline-capable MFA (authenticator apps)",
            "SMS OTP: as a fallback when TOTP is not enrolled",
            "Device registration and account recovery flows"
        ],
        whenNotToUse: [
            "As the sole authentication factor — always combine with something the user knows or has",
            "SMS OTP for high-security flows — vulnerable to SIM swapping and SS7 interception",
            "When you need non-repudiation — OTP proves possession, not identity",
            "For long-lived sessions — OTP is a point-in-time verification, not a session token"
        ],
        advantages: [
            "TOTP works offline — only needs clock synchronization",
            "Single-use: each code is valid once, limiting replay window",
            "Time-limited: 30-second window limits brute-force opportunity",
            "TOTP is standardized (RFC 6238) — works with any authenticator app",
            "Simple to implement with CryptoKit's HMAC API"
        ],
        disadvantages: [
            "SMS OTP vulnerable to SIM swapping, SS7 attacks, social engineering",
            "TOTP requires clock synchronization (+/-30s tolerance with +/-1 window)",
            "Shared secret must be securely stored on both client and server",
            "HOTP has counter desync risk if codes are generated but not submitted",
            "6-digit codes have limited entropy (1 million possibilities) — rate limiting is essential"
        ],
        resources: [
            TopicResource(label: "RFC", title: "RFC 6238 — TOTP", urlString: "https://datatracker.ietf.org/doc/html/rfc6238"),
            TopicResource(label: "RFC", title: "RFC 4226 — HOTP", urlString: "https://datatracker.ietf.org/doc/html/rfc4226"),
            TopicResource(label: "NIST", title: "SP 800-63B — Digital Identity Guidelines", urlString: "https://pages.nist.gov/800-63-3/sp800-63b.html"),
            TopicResource(label: "OWASP", title: "MFA Cheat Sheet", urlString: "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html")
        ],
        realWorldExample: "FinTech uses TOTP for in-app two-factor authentication. During enrollment, a shared secret is generated and stored securely. For each login or high-value transaction, the app computes HMAC-SHA1(secret, floor(time/30)), truncates to 6 digits, and the server independently verifies. No SMS needed — works offline.",
        keyTakeaway: "TOTP > SMS OTP for security. Both sides compute HMAC(secret, time) independently. Always enforce single-use, rate limiting, and +/-1 window tolerance."
    )

    static let transactionSigning = TopicDetail(
        title: "Transaction Signing",
        icon: "signature",
        accentColor: Color(red: 0.10, green: 0.80, blue: 0.55),
        brief: "Transaction signing uses ECDSA P-256 (via the Secure Enclave) to create a cryptographic signature over the canonical representation of a transaction. The signature proves that a specific device, confirmed by biometrics, authorized a specific transaction at a specific time. This provides non-repudiation — the user cannot credibly deny having authorized the transaction.",
        whenToUse: [
            "High-value financial transactions requiring non-repudiation",
            "Any operation where the user must provably authorize the action",
            "Regulatory compliance requiring cryptographic proof of user intent",
            "Dispute resolution — signature serves as unforgeable evidence",
            "Combined with Secure Enclave for hardware-backed proof"
        ],
        whenNotToUse: [
            "For low-value, high-frequency operations where biometric prompts would degrade UX",
            "When you only need message authentication (not non-repudiation) — use HMAC",
            "For server-to-server communication — SE is a client-side feature",
            "When the Secure Enclave is unavailable and software-only signing is unacceptable for compliance"
        ],
        advantages: [
            "Non-repudiation: cryptographic proof linking a specific device + biometric to a transaction",
            "Tamper detection: any modification to the transaction after signing invalidates the signature",
            "Hardware-backed with Secure Enclave — private key never extractable",
            "Small signature size: ~70-72 bytes DER-encoded ECDSA P-256",
            "Canonical format ensures deterministic, unambiguous signing (integer paisa, pipe-separated, fixed order)"
        ],
        disadvantages: [
            "Requires Face ID / Touch ID for every signing operation — adds friction",
            "Secure Enclave only supports P-256 — no algorithm flexibility",
            "Device-bound keys: lost device = lost signing capability (must re-register)",
            "Canonical format must be identical on client and server — any divergence breaks verification",
            "Biometric enrollment changes invalidate the key"
        ],
        resources: [
            TopicResource(label: "NIST", title: "FIPS 186-5 — Digital Signature Standard", urlString: "https://csrc.nist.gov/publications/detail/fips/186/5/final"),
            TopicResource(label: "Apple Docs", title: "SecureEnclave.P256.Signing — CryptoKit", urlString: "https://developer.apple.com/documentation/cryptokit/secureenclave"),
            TopicResource(label: "FIDO", title: "FIDO2 / WebAuthn Specification", urlString: "https://fidoalliance.org/fido2/"),
            TopicResource(label: "Apple", title: "Apple Platform Security Guide", urlString: "https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web")
        ],
        realWorldExample: "For a FinTech transfer above 500 BDT: the app builds a canonical string (txId|from|to|amountPaisa|timestamp|nonce|currency), triggers Face ID which gates the SE key, signs inside the hardware, and includes the DER signature in the request header. The server verifies with the registered public key.",
        keyTakeaway: "Transaction signing = unforgeable proof of user intent. Canonical format is pipe-separated with integer amounts. Secure Enclave + Face ID = hardware-backed non-repudiation."
    )

    static let sessionManagement = TopicDetail(
        title: "Session Management",
        icon: "clock.badge.checkmark",
        accentColor: Color(red: 0.60, green: 0.40, blue: 1.0),
        brief: "Session management keeps users authenticated between requests using a three-token architecture: short-lived access tokens (JWT, 15 min), long-lived refresh tokens (Keychain, single-use with rotation), and very short-lived transaction authorization tokens (2 min, biometric-gated). Actor isolation prevents double-refresh race conditions. Refresh token rotation detects token theft via family tracking.",
        whenToUse: [
            "Any authenticated API communication — every request needs a valid access token",
            "Transparent token refresh — user never sees re-authentication during normal usage",
            "Step-up authentication for high-value transactions (transaction auth tokens)",
            "When you need to balance security (short token lifetime) with UX (seamless refresh)"
        ],
        whenNotToUse: [
            "For stateless, unauthenticated endpoints — no session needed",
            "As a replacement for per-transaction signing — sessions prove identity, not intent",
            "For long-lived offline scenarios — sessions require server connectivity to refresh"
        ],
        advantages: [
            "Three-token hierarchy provides defense-in-depth",
            "Access token in memory only — never written to disk",
            "Refresh token rotation: each use invalidates the old token (detects theft)",
            "Actor isolation eliminates double-refresh race conditions",
            "Step-up auth prevents stolen sessions from draining accounts",
            "JWT claims provide stateless authorization decisions"
        ],
        disadvantages: [
            "Complexity: three token types with different lifetimes, storage, and rotation rules",
            "Refresh token in Keychain survives app reinstall — must handle orphaned tokens",
            "JWT size grows with claims — consider payload size for every request",
            "Clock skew between client and server can cause premature token rejection",
            "Refresh token theft before rotation = full session compromise until detected"
        ],
        resources: [
            TopicResource(label: "RFC", title: "RFC 7519 — JSON Web Token (JWT)", urlString: "https://datatracker.ietf.org/doc/html/rfc7519"),
            TopicResource(label: "RFC", title: "RFC 6749 — OAuth 2.0 Framework", urlString: "https://datatracker.ietf.org/doc/html/rfc6749"),
            TopicResource(label: "OWASP", title: "Session Management Cheat Sheet", urlString: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
            TopicResource(label: "Auth0", title: "Refresh Token Rotation", urlString: "https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation")
        ],
        realWorldExample: "FinTech uses 15-minute access tokens stored in memory, refresh tokens in Keychain with single-use rotation, and 2-minute transaction auth tokens for transfers above 500 BDT. The SessionService actor ensures only one refresh request runs at a time, even under concurrent API calls.",
        keyTakeaway: "Access token = memory only, 15 min. Refresh token = Keychain, single-use rotation. Transaction auth = 2 min, biometric-gated. Use an Actor to prevent double-refresh races."
    )
}

// MARK: - Topic Detail View

struct TopicDetailView: View {
    let topic: TopicDetail

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {

                    header

                    briefSection

                    whenToUseSection

                    whenNotToUseSection

                    advantagesSection

                    disadvantagesSection

                    if let example = topic.realWorldExample {
                        realWorldSection(example)
                    }

                    if let takeaway = topic.keyTakeaway {
                        keyTakeawaySection(takeaway)
                    }

                    resourcesSection

                    Spacer(minLength: 40)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                .padding(.bottom, 32)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.dark)
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: topic.icon)
                .font(.system(size: 32))
                .foregroundStyle(topic.accentColor)
            VStack(alignment: .leading, spacing: 4) {
                Text(topic.title)
                    .font(.system(size: 22, weight: .bold))
                    .foregroundStyle(.white)
                Text("Deep Dive")
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundStyle(topic.accentColor)
            }
        }
        .padding(.bottom, 4)
    }

    private var briefSection: some View {
        detailCard(title: "Overview", icon: "doc.text", accent: topic.accentColor) {
            Text(topic.brief)
                .font(.system(size: 14))
                .foregroundStyle(Color.ftText)
                .lineSpacing(4)
        }
    }

    private var whenToUseSection: some View {
        detailCard(title: "When to Use", icon: "checkmark.circle.fill", accent: .ftGreen) {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(topic.whenToUse, id: \.self) { item in
                    bulletRow(item, color: .ftGreen)
                }
            }
        }
    }

    private var whenNotToUseSection: some View {
        detailCard(title: "When NOT to Use", icon: "xmark.circle.fill", accent: .ftRed) {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(topic.whenNotToUse, id: \.self) { item in
                    bulletRow(item, color: .ftRed)
                }
            }
        }
    }

    private var advantagesSection: some View {
        detailCard(title: "Advantages", icon: "hand.thumbsup.fill", accent: .ftGreen) {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(topic.advantages, id: \.self) { item in
                    bulletRow(item, color: .ftGreen, symbol: "plus.circle.fill")
                }
            }
        }
    }

    private var disadvantagesSection: some View {
        detailCard(title: "Disadvantages", icon: "hand.thumbsdown.fill", accent: .ftAmber) {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(topic.disadvantages, id: \.self) { item in
                    bulletRow(item, color: .ftAmber, symbol: "minus.circle.fill")
                }
            }
        }
    }

    private func realWorldSection(_ example: String) -> some View {
        detailCard(title: "Real-World Example", icon: "building.2.fill", accent: topic.accentColor) {
            Text(example)
                .font(.system(size: 13, design: .monospaced))
                .foregroundStyle(Color.ftText)
                .lineSpacing(4)
        }
    }

    private func keyTakeawaySection(_ takeaway: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "star.fill")
                .font(.system(size: 16))
                .foregroundStyle(Color.ftAmber)
            Text(takeaway)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
                .lineSpacing(3)
        }
        .padding(16)
        .background(Color.ftAmber.opacity(0.1))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.ftAmber.opacity(0.3), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var resourcesSection: some View {
        detailCard(title: "Resources", icon: "book.fill", accent: .ftAccent) {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(topic.resources) { res in
                    if let urlString = res.urlString, let url = URL(string: urlString) {
                        Link(destination: url) {
                            HStack(alignment: .top, spacing: 10) {
                                Text(res.label)
                                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                                    .foregroundStyle(Color.ftDark)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 3)
                                    .background(topic.accentColor)
                                    .clipShape(RoundedRectangle(cornerRadius: 4))
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(res.title)
                                        .font(.system(size: 13, weight: .medium))
                                        .foregroundStyle(topic.accentColor)
                                    Text(urlString)
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundStyle(Color.ftTextDim)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }
                            }
                        }
                    } else {
                        HStack(alignment: .top, spacing: 10) {
                            Text(res.label)
                                .font(.system(size: 9, weight: .bold, design: .monospaced))
                                .foregroundStyle(Color.ftDark)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 3)
                                .background(topic.accentColor)
                                .clipShape(RoundedRectangle(cornerRadius: 4))
                            Text(res.title)
                                .font(.system(size: 13, weight: .medium))
                                .foregroundStyle(Color.ftText)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func detailCard<Content: View>(
        title: String,
        icon: String,
        accent: Color,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(accent)
                Text(title)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(.white)
            }
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.ftSurface)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.ftBorder, lineWidth: 1)
        )
    }

    @ViewBuilder
    private func bulletRow(_ text: String, color: Color, symbol: String = "circle.fill") -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 7))
                .foregroundStyle(color)
                .padding(.top, 6)
            Text(text)
                .font(.system(size: 13))
                .foregroundStyle(Color.ftText)
                .lineSpacing(3)
        }
    }
}
