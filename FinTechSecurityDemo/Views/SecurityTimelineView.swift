//
//  SecurityTimelineView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Comprehensive A-to-Z FinTech security timeline.
// Covers every layer from device boot to incident response.
// Also hosts the Live Payment Flow (Login → Payment) via AtoZContainerView.

import SwiftUI

// MARK: - A→Z Container (Timeline + Live Flow picker)

struct AtoZContainerView: View {
    @State private var selectedTab = 0
    var paymentFlowVM: PaymentFlowViewModel

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            VStack(spacing: 0) {
                Picker("View", selection: $selectedTab) {
                    Text("Timeline").tag(0)
                    Text("Live Flow").tag(1)
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(Color.ftSurface)

                if selectedTab == 0 {
                    SecurityTimelineView()
                } else {
                    PaymentFlowView(vm: paymentFlowVM)
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}

// MARK: - Data Model

struct SecurityPhase: Identifiable {
    let id = UUID()
    let order: Int
    let icon: String
    let title: String
    let category: PhaseCategory
    let threat: String
    let measures: [SecurityMeasure]

    enum PhaseCategory: String {
        case device      = "DEVICE LAYER"
        case application = "APPLICATION LAYER"
        case network     = "NETWORK LAYER"
        case auth        = "AUTHENTICATION LAYER"
        case transaction = "TRANSACTION LAYER"
        case monitoring  = "MONITORING & RESPONSE"
    }
}

struct SecurityMeasure: Identifiable {
    let id = UUID()
    let title: String
    let description: String
    let technology: String
    let implementation: String
}

// MARK: - Timeline Data

enum SecurityTimeline {

    static let phases: [SecurityPhase] = [

        // ──────────────────────────────────────────────
        // PHASE 1: Device Boot & Hardware Integrity
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 1,
            icon: "🔌",
            title: "Device Boot & Hardware Integrity",
            category: .device,
            threat: "Compromised bootloader, modified firmware, hardware implants, or bootkit malware that persists across OS reinstalls.",
            measures: [
                SecurityMeasure(
                    title: "Secure Boot Chain Verification",
                    description: "Apple's Secure Boot chain ensures every piece of software loaded during startup is cryptographically signed by Apple. The Boot ROM (hardware root of trust) verifies iBoot, which verifies the kernel, which verifies kernel extensions. If any link in the chain is tampered with, the device refuses to boot. For FinTech apps, this means the OS your app runs on hasn't been modified at the firmware level.",
                    technology: "Apple Secure Boot (T2/Apple Silicon), Hardware Root of Trust, iBoot verification chain",
                    implementation: "No app-level action required — this is enforced by hardware. However, your app should verify it's running on genuine Apple hardware by checking device attestation via DeviceCheck framework."
                ),
                SecurityMeasure(
                    title: "Secure Enclave Processor (SEP)",
                    description: "The Secure Enclave is a dedicated security coprocessor isolated from the main processor. It manages all cryptographic keys, biometric data (Face ID/Touch ID templates), and performs crypto operations in hardware. Keys generated inside the SEP never leave it — even if the main OS is fully compromised, an attacker cannot extract the private keys. This is critical for FinTech because transaction signing keys and biometric verification happen entirely in hardware.",
                    technology: "Apple Secure Enclave (SEP), Hardware-bound keys, P-256 ECDSA, Biometric coprocessor",
                    implementation: "Use SecureEnclave.P256.Signing.PrivateKey for transaction signing keys. Set kSecAttrTokenID to kSecAttrTokenIDSecureEnclave when storing keys in Keychain. Biometric keys should always use .privateKeyUsage access control with .biometryCurrentSet."
                ),
                SecurityMeasure(
                    title: "Device Attestation",
                    description: "DeviceCheck and App Attest allow your server to verify that requests come from a genuine Apple device running your legitimate app. DeviceCheck provides two persistent bits per device for fraud tracking. App Attest generates a hardware-backed key pair and produces attestation objects that Apple's servers can verify, proving the request originates from your unmodified app on real hardware — not a simulator, jailbroken device, or replay attack.",
                    technology: "Apple DeviceCheck, App Attest (DCAppAttestService), CBOR attestation format",
                    implementation: "Generate an App Attest key with DCAppAttestService.shared.generateKey(). Attest it with attestKey(_:clientDataHash:). Send the attestation to your server, which validates it with Apple's attestation verification endpoint. For subsequent requests, use generateAssertion(_:clientDataHash:) to prove each API call is genuine."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 2: Jailbreak & Environment Detection
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 2,
            icon: "🛡️",
            title: "Jailbreak & Environment Detection",
            category: .device,
            threat: "Jailbroken/rooted devices disable OS security controls, allow runtime hooking (Frida, Cycript), method swizzling, binary patching, and keychain dumping. An attacker on a jailbroken device can intercept every function call your app makes.",
            measures: [
                SecurityMeasure(
                    title: "Multi-Signal Jailbreak Detection",
                    description: "No single check is sufficient — sophisticated jailbreaks (e.g., Dopamine, palera1n) actively hide their presence. A robust detection system uses 10+ signals: check for known jailbreak files (/Applications/Cydia.app, /private/var/lib/apt, /usr/sbin/sshd), attempt to write outside the sandbox, check if fork() succeeds (it shouldn't on non-jailbroken devices), verify code signing integrity, check for suspicious environment variables, detect attached debuggers, verify dyld image list for injected libraries, and test URL scheme handlers for jailbreak tools.",
                    technology: "File existence checks, Sandbox escape tests, fork() detection, dyld inspection, sysctl debugger detection",
                    implementation: "Implement checks at multiple app lifecycle points — not just launch. Periodically re-check during sensitive operations (login, payment). Never rely on a single boolean flag; use a risk score. Example: FileManager.default.fileExists(atPath: \"/Applications/Cydia.app\"), canOpenURL for cydia://, check stat() for suspicious binaries. Run checks on background threads to avoid blocking UI."
                ),
                SecurityMeasure(
                    title: "Runtime Integrity & Anti-Hooking",
                    description: "Frida, Cycript, and similar tools work by injecting dynamic libraries into your process and hooking (swizzling) methods at runtime. This lets attackers bypass authentication, modify transaction amounts, or extract encryption keys from memory. Detection involves: checking the integrity of critical function pointers, scanning loaded dylibs for known hooking frameworks, detecting Frida's default port (27042), verifying that critical methods haven't been swizzled by comparing IMPs, and using inline assembly checks.",
                    technology: "dyld image inspection, Method IMP verification, Frida detection (port scanning, named pipes), DYLD_INSERT_LIBRARIES check",
                    implementation: "Check _dyld_image_count() and _dyld_get_image_name() for unexpected libraries like FridaGadget.dylib or libcycript.dylib. Verify DYLD_INSERT_LIBRARIES environment variable is empty. For critical security functions, store the original IMP at startup and periodically verify it hasn't changed. Use dladdr() to verify function pointers resolve to your binary, not injected code."
                ),
                SecurityMeasure(
                    title: "Emulator & Simulator Detection",
                    description: "Attackers use simulators and emulators to reverse-engineer your app in a controlled environment where they can inspect memory, set breakpoints, and bypass hardware-bound security. Detection checks include: verifying the processor architecture (arm64 vs x86_64), checking for Simulator-specific environment variables, verifying the machine model string, checking for the absence of hardware features (camera, Secure Enclave, gyroscope), and detecting virtualization artifacts.",
                    technology: "ProcessInfo checks, uname() system calls, sysctl hardware queries, TARGET_OS_SIMULATOR compile flags",
                    implementation: "Check ProcessInfo.processInfo.environment for SIMULATOR_DEVICE_NAME. Use uname() to verify machine architecture. Verify Secure Enclave availability with SecureEnclave.isAvailable — its absence is a strong signal. Combine with App Attest which inherently fails on simulators."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 3: App Launch & Binary Integrity
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 3,
            icon: "📱",
            title: "App Launch & Binary Integrity",
            category: .application,
            threat: "Repackaged apps with injected malware, binary patching to disable security checks, debugger attachment for runtime analysis, and code injection via dynamic library loading.",
            measures: [
                SecurityMeasure(
                    title: "Code Signing Verification",
                    description: "iOS enforces mandatory code signing, but attackers can re-sign your app with their own certificate after modification (enterprise distribution, sideloading). Your app should verify its own code signature at runtime. Check the embedded provisioning profile, verify the signing identity matches your team ID, and compare a hash of your executable against a known-good value. This catches repackaged versions that may have had security checks stripped out or malicious code injected.",
                    technology: "SecStaticCodeCheckValidityWithErrors, Embedded provisioning profile validation, Bundle signature verification",
                    implementation: "Read the embedded.mobileprovision file and verify the TeamIdentifier matches your expected team ID. Hash your main executable and compare against a server-provided hash on first launch. Use SecCodeCopySelf and SecCodeCheckValidity on macOS. On iOS, check Bundle.main.appStoreReceiptURL for expected provisioning type."
                ),
                SecurityMeasure(
                    title: "Anti-Debug Protection",
                    description: "Debuggers (lldb, gdb) allow attackers to set breakpoints on your security-critical functions, inspect variables containing keys or tokens, and modify execution flow in real time. For example, an attacker can set a breakpoint on your jailbreak detection function and simply skip it. Anti-debug measures include: calling ptrace(PT_DENY_ATTACH) to prevent debugger attachment, using sysctl to detect if a debugger is currently attached, checking the P_TRACED flag in process info, and implementing timing-based detection (debugger breakpoints introduce measurable delays).",
                    technology: "ptrace(PT_DENY_ATTACH), sysctl P_TRACED flag, getppid() checks, Timing-based detection",
                    implementation: "Call ptrace(PT_DENY_ATTACH, 0, nil, 0) early in main() — before any Swift runtime initialization if possible. Periodically check: var info = kinfo_proc(); var size = MemoryLayout<kinfo_proc>.stride; var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]; sysctl(&mib, 4, &info, &size, nil, 0); let isDebugged = (info.kp_proc.p_flag & P_TRACED) != 0. Combine with timing checks between critical operations."
                ),
                SecurityMeasure(
                    title: "App Transport Security & Entitlements",
                    description: "App Transport Security (ATS) enforces HTTPS for all network connections by default. Your app's entitlements define its capabilities and security boundaries. Review entitlements to ensure minimum necessary permissions. Disable NSAllowsArbitraryLoads entirely — there should be zero exceptions for a FinTech app. Verify your entitlements don't include unnecessary capabilities like inter-app communication that could be exploited.",
                    technology: "App Transport Security (ATS), Entitlements.plist, NSAppTransportSecurity strict mode, Capability restrictions",
                    implementation: "Set NSAllowsArbitraryLoads to NO (the default). Do NOT add exceptions. Use only the minimum required entitlements: keychain-access-groups for secure storage, aps-environment for push notifications. Remove any development-only entitlements (get-task-allow) in release builds. Audit Info.plist for URL schemes that could be exploited."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 4: Data Protection at Rest
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 4,
            icon: "💾",
            title: "Data Protection at Rest",
            category: .application,
            threat: "Physical device access, backup extraction (iTunes/iCloud), forensic tools (Cellebrite, GrayKey) that can image the device filesystem, or malware with file system access on jailbroken devices.",
            measures: [
                SecurityMeasure(
                    title: "iOS Data Protection Classes",
                    description: "iOS provides four data protection levels, each defining when a file's encryption key is available. For FinTech, always use the most restrictive class possible. 'Complete Protection' (NSFileProtectionComplete) makes files inaccessible when the device is locked — the encryption key is derived from the user's passcode and evicted from memory 10 seconds after lock. 'Complete Unless Open' allows writes to continue on open files. 'Until First User Authentication' (the default) keeps keys available after first unlock until reboot — this is too permissive for sensitive financial data.",
                    technology: "NSFileProtectionComplete, Data Protection API, Per-file encryption keys, Class keys derived from passcode + hardware UID",
                    implementation: "Set file protection when creating files: try data.write(to: url, options: [.completeFileProtection]). For existing files: try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: path). For SQLite databases, use PRAGMA key and ensure the DB file has Complete protection. Verify protection levels in your security audit."
                ),
                SecurityMeasure(
                    title: "Keychain Services (Secure Storage)",
                    description: "The iOS Keychain is the only appropriate place to store secrets (tokens, keys, passwords, certificates) in a FinTech app. The Keychain is encrypted with a hardware key, sandboxed per-app, and supports fine-grained access control including biometric requirements. Never use UserDefaults, Core Data, or file storage for any sensitive data. Keychain items can be configured to: require biometric authentication for each access, be excluded from backups, be tied to the specific device (non-migratable), and auto-delete when the app is uninstalled.",
                    technology: "Security.framework Keychain Services, kSecAttrAccessible, SecAccessControl, kSecAttrSynchronizable",
                    implementation: "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for most secrets — this prevents backup extraction and device migration of sensitive items. For payment credentials, add biometric access control: SecAccessControlCreateWithFlags(nil, .whenUnlockedThisDeviceOnly, [.biometryCurrentSet, .privateKeyUsage], nil). Set kSecAttrSynchronizable to false to prevent iCloud Keychain sync. Set kSecAttrIsBackupable (if available) to false."
                ),
                SecurityMeasure(
                    title: "Encryption at Rest (AES-256-GCM)",
                    description: "Beyond iOS file-level encryption, FinTech apps should implement application-level encryption for sensitive data stored in databases, caches, or temporary files. AES-256-GCM provides both confidentiality (encryption) and integrity (authentication tag). The authentication tag ensures that if even a single bit of the ciphertext is modified, decryption will fail — preventing tampering attacks. Use unique nonces for every encryption operation; nonce reuse with GCM is catastrophic and reveals the authentication key.",
                    technology: "CryptoKit AES.GCM, 256-bit symmetric keys, 96-bit nonces, 128-bit authentication tags, HKDF for key derivation",
                    implementation: "Generate keys with SymmetricKey(size: .bits256). Encrypt with AES.GCM.seal(plaintext, using: key). The sealed box includes nonce + ciphertext + tag. Never hardcode keys — derive them from Keychain-stored master keys using HKDF with context-specific info strings. Rotate encryption keys periodically. For database encryption, consider SQLCipher with AES-256."
                ),
                SecurityMeasure(
                    title: "Secure Memory Handling",
                    description: "Sensitive data (PINs, card numbers, session tokens) in memory can be extracted through memory dumps, core dumps, or debugger attachment. Even after a variable goes out of scope, the data remains in memory until the page is reused. Mitigations include: zeroing memory immediately after use, avoiding String for sensitive data (use Data or [UInt8] which can be zeroed), disabling core dumps, marking memory pages as non-pageable to prevent swapping to disk, and minimizing the time sensitive data exists in memory.",
                    technology: "memset_s (guaranteed zeroing), mlock() for non-pageable memory, Data with resetBytes, [UInt8] manual zeroing",
                    implementation: "Use var sensitiveData = Data(count: 32) and after use call sensitiveData.resetBytes(in: 0..<sensitiveData.count). For [UInt8], zero with: for i in 0..<buffer.count { buffer[i] = 0 }. Avoid converting sensitive Data to String — String is immutable and copied by the runtime. Use memset_s for C-level zeroing. Consider using mlock() for critical buffers to prevent swap. Disable core dumps with setrlimit(RLIMIT_CORE)."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 5: Biometric Authentication
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 5,
            icon: "🧬",
            title: "Biometric Authentication",
            category: .auth,
            threat: "Fake biometric presentation (spoofed fingerprints, 3D-printed faces), biometric bypass via jailbreak hooks, fallback to weak passcode, or replay attacks using previously captured biometric data.",
            measures: [
                SecurityMeasure(
                    title: "Local Authentication with LAContext",
                    description: "LAContext provides the primary interface for biometric authentication (Face ID/Touch ID). For FinTech, always use .deviceOwnerAuthenticationWithBiometrics policy (not .deviceOwnerAuthentication which falls back to passcode). Set evaluatedPolicyDomainState to detect biometric enrollment changes — if a new fingerprint is added, previously authenticated sessions should be invalidated. Use .biometryCurrentSet in Keychain access control to tie stored secrets to the current biometric enrollment; if biometrics change, those Keychain items become permanently inaccessible.",
                    technology: "LocalAuthentication.framework, LAContext, LAPolicy, evaluatedPolicyDomainState, Biometric enrollment tracking",
                    implementation: "Create LAContext(), call evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics). Store the evaluatedPolicyDomainState in Keychain after successful auth. On next auth, compare states — if different, biometrics were modified, force re-registration. Use .biometryCurrentSet (not .biometryAny) in SecAccessControl to invalidate Keychain items on enrollment change. Set context.touchIDAuthenticationAllowableReuseDuration = 0 to force fresh auth every time."
                ),
                SecurityMeasure(
                    title: "Keychain-Integrated Biometrics",
                    description: "The strongest biometric pattern doesn't use LAContext directly — instead, it stores a secret in the Keychain protected by biometric access control. When your app needs to authenticate, it requests the Keychain item, which triggers the biometric prompt automatically. The critical difference: with LAContext alone, a jailbreak hook can simply return 'true' for the authentication check. With Keychain-integrated biometrics, the secret is genuinely encrypted with the biometric key — without the real biometric, the decryption key doesn't exist. There is nothing to hook.",
                    technology: "SecAccessControlCreateWithFlags, kSecAttrAccessControl, Keychain + Biometry integration, Hardware-bound decryption",
                    implementation: "Create access control: SecAccessControlCreateWithFlags(nil, .whenUnlockedThisDeviceOnly, [.biometryCurrentSet, .privateKeyUsage], nil). Store a random secret with this ACL. To authenticate, query the Keychain item — the OS handles the biometric prompt. If biometric fails, the item is simply inaccessible. This is unhookable because the decryption key is derived from the actual biometric data in the Secure Enclave."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 6: Networking & TLS
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 6,
            icon: "🌐",
            title: "Networking & TLS Configuration",
            category: .network,
            threat: "Man-in-the-middle (MITM) attacks, TLS downgrade attacks, rogue Wi-Fi hotspots, DNS spoofing, BGP hijacking, and compromised certificate authorities issuing fraudulent certificates for your domain.",
            measures: [
                SecurityMeasure(
                    title: "TLS 1.3 Enforcement",
                    description: "TLS 1.3 is a major security improvement over TLS 1.2: it removes all legacy cipher suites (RC4, 3DES, CBC mode), reduces the handshake to one round trip (1-RTT), supports zero round trip resumption (0-RTT), and provides forward secrecy by default on every connection. A FinTech app must enforce TLS 1.3 as the minimum version. TLS 1.2 connections, while still considered secure with proper configuration, have a larger attack surface and more configuration pitfalls (e.g., BEAST, POODLE legacy issues, cipher suite ordering).",
                    technology: "TLS 1.3 (RFC 8446), AES-256-GCM cipher suites, ChaCha20-Poly1305, X25519/P-256 key exchange, Forward secrecy",
                    implementation: "Configure URLSession with a custom TLS policy. In your server configuration, set minimum TLS version to 1.3. On client side, use URLSessionDelegate's urlSession(_:didReceive:completionHandler:) to verify the negotiated TLS version. In the ATS configuration, set NSAllowsArbitraryLoads to false and set minimum TLS version to TLSv1.3 via NSExceptionMinimumTLSVersion for your domains."
                ),
                SecurityMeasure(
                    title: "Certificate Pinning",
                    description: "Even with TLS, a compromised or rogue Certificate Authority (CA) could issue a valid certificate for your domain to an attacker. Certificate pinning solves this by hardcoding which certificates or public keys your app trusts for specific domains. There are two strategies: (1) Pin the leaf certificate — most secure but requires app updates on certificate rotation. (2) Pin the public key (SPKI) — survives certificate renewal as long as the same key pair is used. For FinTech, pin at the public key level with backup pins. Use at least 2 pins (primary + backup key) to prevent lockout during rotation.",
                    technology: "Public Key Pinning (SPKI), TrustKit, URLSessionDelegate server trust evaluation, SHA-256 pin hashes",
                    implementation: "Implement URLSessionDelegate.urlSession(_:didReceive:completionHandler:). Extract the server's public key from the certificate chain. Hash it with SHA-256 and compare against your pinned hash set. Example: SecCertificateCopyKey(cert) → SecKeyCopyExternalRepresentation(key) → SHA256.hash(data: keyData). Store pin hashes in a secure, obfuscated location — not plain Info.plist. Implement pin rotation strategy with backup keys."
                ),
                SecurityMeasure(
                    title: "DNS Security",
                    description: "Traditional DNS is unencrypted and trivially spoofable — an attacker on the same network can redirect your API domain to their server. DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) encrypt DNS queries, preventing eavesdropping and tampering. Apple supports encrypted DNS natively via NEDNSSettingsManager. For maximum security, combine encrypted DNS with certificate pinning — even if DNS is compromised, pinning will reject the attacker's certificate.",
                    technology: "DNS-over-HTTPS (DoH, RFC 8484), DNS-over-TLS (DoT, RFC 7858), NEDNSSettingsManager, NWParameters.PrivacyContext",
                    implementation: "Use NWParameters.PrivacyContext with a DoH server URL for Network.framework connections. For URLSession, configure a NEDNSSettingsManager profile. Consider using a trusted DoH provider (Cloudflare 1.1.1.1, Google 8.8.8.8) or your own DoH server. Always combine with certificate pinning as the ultimate backstop."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 7: MITM Prevention & Request Integrity
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 7,
            icon: "🔒",
            title: "MITM Prevention & Request Integrity",
            category: .network,
            threat: "Proxy-based MITM (Charles, Burp Suite, mitmproxy), SSL stripping attacks, request tampering (modifying transaction amounts, recipient accounts), replay attacks resending captured requests, and API parameter pollution.",
            measures: [
                SecurityMeasure(
                    title: "HMAC Request Signing",
                    description: "Every API request from your app should be signed with HMAC-SHA256 to guarantee integrity and authenticity. The signature covers: the HTTP method, URL path, request body, timestamp, and a nonce. The server recomputes the HMAC with the same shared key and rejects requests with invalid signatures. This means even if an attacker intercepts the request (despite TLS + pinning), they cannot modify any parameter (like the transfer amount) without invalidating the signature. The shared key for HMAC should be derived per-session using HKDF, not hardcoded.",
                    technology: "HMAC-SHA256 (CryptoKit), Canonical request signing, Timestamp validation, Nonce-based replay protection",
                    implementation: "Construct a canonical string: \"METHOD\\nPATH\\nTIMESTAMP\\nNONCE\\nBODY_HASH\". Compute HMAC: CryptoKit.HMAC<SHA256>.authenticationCode(for: Data(canonical.utf8), using: sessionKey). Send as X-Signature header. Server validates: reject if timestamp > 30 seconds old, reject if nonce was seen before (Redis set with TTL), recompute HMAC and compare in constant time."
                ),
                SecurityMeasure(
                    title: "Replay Attack Prevention",
                    description: "A replay attack captures a legitimate, signed request and re-sends it. For example, capturing a 'transfer ৳5,000' request and replaying it 100 times. Three defenses work together: (1) Timestamps — reject requests older than 30 seconds. (2) Nonces — every request includes a unique random value; the server tracks seen nonces and rejects duplicates. (3) Sequence numbers — for critical operations, maintain a monotonically increasing counter that the server validates. All three values must be included in the HMAC signature so they can't be stripped.",
                    technology: "Cryptographic nonces (UUID v4), Server-side nonce cache (Redis SETNX with TTL), Timestamp windowing, Monotonic sequence counters",
                    implementation: "Generate nonce: UUID().uuidString. Include in HMAC: \"\\(timestamp):\\(nonce):\\(body)\". Server stores nonces in Redis: SETNX nonce:<value> 1 EX 120 — if SETNX returns 0, it's a replay. For payment endpoints, also require a sequence number: the server stores the last seen sequence per user and rejects any value ≤ the stored one."
                ),
                SecurityMeasure(
                    title: "Proxy & MITM Detection",
                    description: "Even with certificate pinning, your app should actively detect proxy configurations and MITM attempts. Check the system proxy settings — if a proxy is configured, warn the user or restrict sensitive operations. Detect if the network is routing through known MITM tools by examining the TLS certificate chain depth and issuer. Some sophisticated attacks use kernel extensions to intercept traffic before TLS — detect these by checking CFNetworkCopySystemProxySettings and monitoring for unexpected network configurations.",
                    technology: "CFNetworkCopySystemProxySettings, URLSessionConfiguration.connectionProxyDictionary, Certificate chain validation, Network.framework path monitoring",
                    implementation: "Check proxy: let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]. If HTTPProxy or HTTPSProxy keys exist, a proxy is active. During TLS handshake, verify the certificate chain length and root CA match expected values. Log proxy detection events to your security audit system. Consider blocking payments (not the entire app) when a proxy is detected."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 8: API Authentication & Authorization
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 8,
            icon: "🔑",
            title: "API Authentication & Authorization",
            category: .auth,
            threat: "Credential theft, token hijacking, privilege escalation, brute-force attacks, credential stuffing using leaked password databases, and authorization bypass through IDOR (Insecure Direct Object Reference) or parameter tampering.",
            measures: [
                SecurityMeasure(
                    title: "Three-Token Architecture",
                    description: "Modern FinTech apps use a three-token system: (1) Access Token — short-lived (5-15 minutes) JWT for API authorization. Contains user claims, signed with RS256 or ES256. (2) Refresh Token — medium-lived (7-30 days), stored in Keychain, used only to obtain new access tokens. Single-use with rotation — each refresh invalidates the old token and issues a new pair. (3) Device Token — long-lived, hardware-bound (Secure Enclave), used to validate the device identity across sessions. If any token is compromised, the blast radius is limited by its scope and lifetime.",
                    technology: "JWT (RS256/ES256), OAuth 2.0 + PKCE, Refresh token rotation (RFC 6749), Device-bound tokens via Secure Enclave",
                    implementation: "Access token: decode JWT, check exp claim before every request, refresh proactively 30 seconds before expiry. Refresh token: store in Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly. On 401, use refresh token once — if it fails, force re-authentication. Device token: generate a Secure Enclave P-256 key pair on first install, register the public key with your backend. Sign a device assertion with each refresh request."
                ),
                SecurityMeasure(
                    title: "OAuth 2.0 with PKCE",
                    description: "PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks, which are especially relevant on mobile where custom URL scheme redirects can be hijacked by malicious apps. The flow: your app generates a random code_verifier, computes code_challenge = SHA256(code_verifier), sends the challenge with the auth request. When exchanging the code for tokens, you send the original verifier. The server verifies SHA256(verifier) == challenge. An attacker who intercepts the authorization code cannot exchange it without the verifier, which never left your app.",
                    technology: "OAuth 2.0 Authorization Code + PKCE (RFC 7636), SHA-256 code challenge, ASWebAuthenticationSession",
                    implementation: "Generate code_verifier: 32 random bytes, base64url-encoded. Compute code_challenge: SHA256 hash of verifier, base64url-encoded. Use ASWebAuthenticationSession for the authorization flow — it uses a secure, isolated browser context. Never use WKWebView for OAuth (it allows cookie/credential theft). Set response_type=code, code_challenge_method=S256."
                ),
                SecurityMeasure(
                    title: "Rate Limiting & Brute Force Protection",
                    description: "Client-side rate limiting complements server-side controls. Implement exponential backoff for failed authentication attempts: 1s, 2s, 4s, 8s... up to a maximum. After N failures, require a CAPTCHA or lock the account temporarily. Track failed attempts in Keychain (not UserDefaults — it's not encrypted). For OTP verification, limit attempts to 3-5 before requiring a new OTP. Implement account lockout notifications so users are aware of unauthorized access attempts.",
                    technology: "Exponential backoff, Client-side attempt tracking, Server-side rate limiting (Token Bucket algorithm), Account lockout policies",
                    implementation: "Store attempt count and last attempt time in Keychain. On failure: attempts += 1; delay = min(pow(2, attempts), 300) seconds. After 5 failures, present CAPTCHA challenge. After 10, suggest account recovery. On success, reset counter. Server side: implement token bucket per user/IP with Redis: MULTI, INCR rate:<user>, EXPIRE rate:<user> 300, EXEC — reject if count > threshold."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 9: Key Exchange & Session Establishment
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 9,
            icon: "🤝",
            title: "Key Exchange & Session Establishment",
            category: .auth,
            threat: "Key interception, weak key derivation, session fixation, key reuse across contexts, and forward secrecy violations where compromise of a long-term key reveals all past session communications.",
            measures: [
                SecurityMeasure(
                    title: "ECDH Key Agreement (P-256)",
                    description: "Elliptic Curve Diffie-Hellman (ECDH) allows your app and the server to establish a shared secret over an insecure channel. Both sides generate ephemeral P-256 key pairs, exchange public keys, and compute an identical shared secret. Because ephemeral keys are used per-session, ECDH provides Perfect Forward Secrecy (PFS): even if the server's long-term private key is later compromised, past sessions remain secure because the ephemeral keys were destroyed after use. The shared secret is never transmitted — it's computed independently on both sides.",
                    technology: "ECDH P-256 (CryptoKit), Ephemeral key pairs, Perfect Forward Secrecy (PFS), X25519 as alternative",
                    implementation: "let ephemeralKey = P256.KeyAgreement.PrivateKey(). Send ephemeralKey.publicKey.x963Representation to server. Receive server's public key. Compute shared secret: let shared = try ephemeralKey.sharedSecretFromKeyAgreement(with: serverPublicKey). Derive session key with HKDF: shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: sessionSalt, sharedInfo: contextInfo, outputByteCount: 32). Destroy ephemeral private key immediately."
                ),
                SecurityMeasure(
                    title: "HKDF Key Derivation",
                    description: "A raw ECDH shared secret should never be used directly as an encryption key. HKDF (HMAC-based Key Derivation Function) extracts entropy from the shared secret and derives multiple independent keys for different purposes. The info parameter provides context separation: a key derived with info='encrypt' is cryptographically unrelated to one derived with info='hmac' from the same shared secret. This prevents cross-protocol attacks where a key used for one purpose is exploited in another context.",
                    technology: "HKDF-SHA256 (RFC 5869), Context-specific key derivation, Salt for extraction phase, Info string for expansion phase",
                    implementation: "Derive separate keys for each purpose: let encryptionKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(\"encryption\".utf8), outputByteCount: 32). Derive HMAC key: same call with sharedInfo: Data(\"hmac\".utf8). Derive IV key with sharedInfo: Data(\"iv\".utf8). Use unique salts per session. Never reuse derived keys across sessions."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 10: Multi-Factor Authentication
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 10,
            icon: "🔐",
            title: "Multi-Factor Authentication (MFA)",
            category: .auth,
            threat: "Single-factor compromise (stolen password), SIM-swap attacks intercepting SMS OTPs, phishing attacks capturing both password and OTP in real-time, and social engineering bypassing knowledge-based factors.",
            measures: [
                SecurityMeasure(
                    title: "TOTP (Time-Based One-Time Password)",
                    description: "TOTP (RFC 6238) generates a 6-8 digit code that changes every 30 seconds, based on a shared secret and the current time. Unlike SMS OTP, TOTP is immune to SIM-swap attacks because the secret lives on the user's device, not with the carrier. The algorithm: HMAC-SHA1(secret, floor(time / 30)), then dynamic truncation to extract digits. Allow a window of ±1 time step to handle clock skew. The shared secret must be generated server-side with at least 160 bits of entropy and transmitted to the client via QR code or secure channel during enrollment.",
                    technology: "TOTP (RFC 6238), HMAC-SHA1/SHA256/SHA512, 30-second time steps, Base32-encoded secrets, QR code enrollment",
                    implementation: "Generate server-side: 20-byte random secret, base32-encode. Display as QR code (otpauth://totp/FinTech:user@email?secret=BASE32SECRET&issuer=FinTech&algorithm=SHA256&digits=6&period=30). Client-side verification: compute HMAC-SHA256(secret, timeCounter), extract 6 digits via dynamic truncation. Accept codes from t-1, t, t+1 windows. Rate-limit to 3 attempts per code period."
                ),
                SecurityMeasure(
                    title: "Biometric + PIN Layered MFA",
                    description: "For FinTech, implement layered authentication that combines something you are (biometrics), something you know (PIN/password), and something you have (device). For routine operations (balance check), biometric alone suffices. For sensitive operations (large transfers, adding payees), require biometric + PIN. For administrative changes (password reset, device registration), require biometric + PIN + OTP. This layered approach means each operation's authentication strength matches its risk level.",
                    technology: "LocalAuthentication + Keychain ACL, Risk-based authentication, Step-up authentication, Adaptive MFA",
                    implementation: "Define risk tiers: Low (view balance) → biometric only. Medium (transfer < ৳10,000) → biometric + session token. High (transfer ≥ ৳10,000, new payee) → biometric + PIN + TOTP. Critical (password change, device registration) → biometric + PIN + TOTP + email verification. Implement step-up auth: when a higher tier is needed, prompt for the additional factor without re-authenticating the lower ones."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 11: Session Management
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 11,
            icon: "⏱️",
            title: "Session Management & Token Lifecycle",
            category: .auth,
            threat: "Session hijacking, token theft from memory or storage, stale sessions remaining active indefinitely, concurrent session abuse, and background state leaking through app snapshots.",
            measures: [
                SecurityMeasure(
                    title: "Session Lifecycle Controls",
                    description: "Implement strict session timeouts: absolute timeout (maximum session duration regardless of activity, e.g., 30 minutes for high-security FinTech), idle timeout (inactivity threshold, e.g., 5 minutes), and background timeout (app backgrounded for > 2 minutes triggers re-authentication). When the app enters background, immediately: clear sensitive data from memory, replace the UI with a privacy screen (prevents app switcher screenshots from leaking data), pause any ongoing sensitive operations, and start the background timer. On foreground, verify session validity before showing content.",
                    technology: "UIApplication lifecycle notifications, ScenePhase monitoring, NSUserDefaults-free timer tracking, Keychain-stored session metadata",
                    implementation: "Monitor ScenePhase changes in SwiftUI: .onChange(of: scenePhase) { if scenePhase == .background { showPrivacyScreen(); startBackgroundTimer(); clearSensitiveState() } }. Store lastActiveTime in Keychain. On foreground: if Date().timeIntervalSince(lastActive) > idleTimeout, invalidate session. Use UIApplication.willResignActiveNotification for UIKit apps. Implement a ZStack privacy overlay that shows the app logo when backgrounded."
                ),
                SecurityMeasure(
                    title: "Refresh Token Rotation",
                    description: "Refresh token rotation means every time a refresh token is used, both the access token and the refresh token are replaced. The old refresh token is immediately invalidated. If an attacker steals a refresh token and uses it, two things happen: (1) they get a new token pair, but (2) when the legitimate user's old refresh token is used, the server detects the reuse and invalidates ALL tokens for that session/device — a 'family invalidation.' This limits the window of compromise and provides a detection mechanism.",
                    technology: "Refresh token rotation (OAuth 2.0), Token family tracking, Redis-based token invalidation, JWT claims (jti, iat, family_id)",
                    implementation: "Server issues refresh tokens with a family_id. Each rotation: generate new access + refresh tokens with same family_id, mark old refresh token as 'used' in Redis. If a 'used' refresh token is presented again → it was stolen. Invalidate ALL tokens in that family: DEL token_family:<family_id>. Force re-authentication. Alert the user of potential compromise. Client: always persist the latest refresh token pair immediately."
                ),
                SecurityMeasure(
                    title: "Concurrent Session Control",
                    description: "For FinTech, limit active sessions to a reasonable number (e.g., 2-3 devices). When a new session is created beyond the limit, either reject it or terminate the oldest session. Show the user a list of active sessions with device info, IP address, and last activity. Allow remote session termination. On the server, maintain a session registry per user. Each API request updates the session's last_active timestamp. Periodic cleanup removes expired sessions.",
                    technology: "Server-side session registry, Device fingerprinting, GeoIP-based anomaly detection, WebSocket session events",
                    implementation: "On login: check active session count for user. If at limit, show existing sessions and ask which to terminate. Store session metadata: { device_id, device_name, ip, geo, created_at, last_active, push_token }. Expose GET /sessions endpoint for the active sessions list. Implement DELETE /sessions/:id for remote termination. Send push notification when a new session is created from an unfamiliar device/location."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 12: Transaction Security
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 12,
            icon: "💸",
            title: "Transaction Security & Signing",
            category: .transaction,
            threat: "Transaction tampering (modified amounts, changed recipients), unauthorized transactions, transaction replay, race conditions in concurrent transactions, and man-in-the-browser attacks modifying transaction details in transit.",
            measures: [
                SecurityMeasure(
                    title: "Transaction Signing with ECDSA",
                    description: "Every payment transaction must be digitally signed by the sender's device using ECDSA P-256. The signature covers ALL transaction parameters: sender, recipient, amount, currency, timestamp, nonce, and any metadata. The signing key is stored in the Secure Enclave and requires biometric authentication to use. The server verifies the signature using the registered public key before processing. This creates a non-repudiable audit trail — the user cannot deny authorizing a transaction because only their Secure Enclave could have produced the signature.",
                    technology: "ECDSA P-256 (Secure Enclave), CryptoKit Signing, SHA-256 digest, DER-encoded signatures, Non-repudiation",
                    implementation: "Create canonical transaction string: \"SEND|amount:5000|to:01712345678|currency:BDT|nonce:abc123|timestamp:1234567890\". Hash with SHA256. Sign with Secure Enclave key: SecureEnclave.P256.Signing.PrivateKey → signature(for: digest). Send signature + public key ID in the request. Server: look up registered public key, verify P256.Signing.PublicKey.isValidSignature(signature, for: digest). Log signature and all parameters for audit."
                ),
                SecurityMeasure(
                    title: "Transaction Idempotency",
                    description: "Network failures during payment can lead to duplicate transactions if the client retries. Idempotency ensures that submitting the same transaction multiple times produces the same result as submitting it once. The client generates a unique idempotency key (UUID) before the first attempt and includes it in all retries. The server uses this key to detect duplicates: if the key exists in the idempotency store, return the cached result instead of processing again. The idempotency key must be included in the transaction signature to prevent key substitution.",
                    technology: "Idempotency keys (UUID v4), Server-side idempotency store (Redis with TTL), Exactly-once processing semantics",
                    implementation: "Client: generate idempotencyKey = UUID().uuidString before first attempt. Include in request header: X-Idempotency-Key. Include in signed payload. Server: SETNX idempotency:<key> 'processing' EX 86400. If key exists, return stored result. On completion, SET idempotency:<key> '{result_json}' EX 86400. Client: retry with same key on network failure. After 3 retries, check transaction status endpoint."
                ),
                SecurityMeasure(
                    title: "Amount & Recipient Verification",
                    description: "A critical FinTech vulnerability is the 'parameter tampering' attack: an attacker (via MITM or compromised client) modifies the transaction amount or recipient between the user's confirmation screen and the API call. Defense-in-depth: (1) Server validates amount against daily/per-transaction limits. (2) Amount in the signed payload must match the API body. (3) For large amounts, require additional authentication step-up. (4) Implement a confirmation callback: server sends transaction details back to the device for user re-confirmation before final processing. (5) Show the recipient's verified name (pulled from server, not client) on the confirmation screen.",
                    technology: "Server-side amount validation, Transaction limits engine, Step-up authentication triggers, Confirmation callbacks, Verified payee display",
                    implementation: "Client: sign(amount, recipient, nonce). Server: verify signature, then independently validate: amount ≤ per_tx_limit AND daily_total + amount ≤ daily_limit. If amount > step_up_threshold, return 'requires_additional_auth' with a challenge. For new payees, implement a cooling period (first transfer limited to ৳1,000). Show server-resolved recipient name (from KYC database) on confirmation, not the client-provided one."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 13: Payment Processing & PCI Compliance
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 13,
            icon: "💳",
            title: "Payment Processing & PCI Compliance",
            category: .transaction,
            threat: "Card data theft (PAN, CVV), non-compliance penalties (up to $100K/month), payment fraud, card-not-present fraud, and breach notification requirements that can destroy customer trust and trigger regulatory action.",
            measures: [
                SecurityMeasure(
                    title: "PCI-DSS Tokenization",
                    description: "Tokenization replaces sensitive card data (PAN, expiry, CVV) with a random, meaningless token. The token maps to the real card data only inside the payment gateway's secure token vault — your app and servers never see or store the real card number. This reduces your PCI scope from SAQ D (the most burdensome, 300+ requirements) to SAQ A (simplest, ~20 requirements). The token is useless to an attacker — it can only be used by your merchant ID with the specific gateway. Even a complete breach of your systems exposes nothing usable.",
                    technology: "PCI-DSS v4.0 Tokenization (Req 3), Stripe/Adyen/Braintree tokenization SDKs, Format-preserving tokens, Token vault architecture",
                    implementation: "Integrate a PCI-validated SDK (Stripe Elements, Adyen Drop-in). Card data is entered in the SDK's secure iframe/native component — your code never receives it. The SDK returns a token (tok_xxx). Store only: token, last4, brand, expiry. For charges, send the token to your server, which calls the gateway. Never log card numbers, never store CVV, never transmit card data through your servers. Use the SDK's built-in fraud detection (Stripe Radar, Adyen risk engine)."
                ),
                SecurityMeasure(
                    title: "3D Secure 2 (3DS2) Authentication",
                    description: "3D Secure 2 is a protocol that adds an authentication step to online card payments. Unlike 3DS1 (the old redirect page), 3DS2 uses a frictionless flow for low-risk transactions and a challenge flow (biometric, OTP, or app-based) only for high-risk ones. It shifts fraud liability from the merchant to the card issuer for authenticated transactions. For FinTech apps, 3DS2 is typically mandatory in the EU (PSD2 SCA requirement) and increasingly adopted globally. It integrates natively via the payment SDK.",
                    technology: "EMV 3D Secure 2.0, SCA (Strong Customer Authentication, PSD2), Frictionless vs Challenge flow, Issuer risk-based authentication",
                    implementation: "Integrate via your payment SDK's 3DS2 module (Stripe PaymentIntent.confirm with payment_method_options.card.request_three_d_secure='any'). The SDK handles the native 3DS2 challenge UI. Collect device fingerprint data for risk scoring (screen size, timezone, language). Handle 3DS2 results: 'authenticated' → proceed, 'attempted' → proceed with merchant liability, 'failed' → reject transaction. Log 3DS2 outcomes for analytics."
                ),
                SecurityMeasure(
                    title: "Fraud Detection & Risk Scoring",
                    description: "Real-time fraud detection evaluates every transaction against multiple risk signals: device fingerprint, geolocation, transaction velocity, amount patterns, time-of-day patterns, behavioral biometrics (typing speed, touch pressure, accelerometer), and deviation from the user's historical pattern. A risk score determines the response: low risk → approve silently, medium risk → step-up authentication, high risk → flag for manual review, critical risk → block and alert. Machine learning models are trained on historical fraud patterns to improve accuracy.",
                    technology: "Device fingerprinting, Behavioral biometrics, ML-based risk scoring, Velocity checks, Geofencing, Graph-based fraud detection",
                    implementation: "Collect signals per transaction: { device_id, ip, geo: {lat,lon}, amount, recipient, time, session_duration, biometric_confidence, typing_cadence }. Send to your risk engine (or use Stripe Radar, Sift Science, Featurespace). Define rules: IF amount > 10x avg_amount OR geo_distance > 500km from last_tx in < 1hr THEN step_up. ML model: train on labeled fraud/legit transactions. Update model weights monthly. Human review queue for flagged transactions."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 14: Audit Logging & Compliance
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 14,
            icon: "📋",
            title: "Audit Logging & Compliance",
            category: .monitoring,
            threat: "Undetected breaches (average dwell time: 200+ days), regulatory non-compliance (PCI Req 10, SOX, PSD2), inability to forensically reconstruct incidents, tampering with log records, and insufficient evidence for legal proceedings.",
            measures: [
                SecurityMeasure(
                    title: "Comprehensive Security Audit Trail",
                    description: "PCI-DSS Requirement 10 mandates logging all access to cardholder data environments. For FinTech, extend this to every security-relevant event: authentication attempts (success and failure), session lifecycle (create, refresh, expire, terminate), transaction operations (initiate, sign, submit, confirm, fail), administrative changes (password reset, device registration, permission changes), security events (jailbreak detection, certificate pinning failure, biometric enrollment change). Each log entry must include: who, what, when, where (IP/device), and the outcome. Critically, never log sensitive data — no PANs, passwords, keys, or full tokens.",
                    technology: "Structured logging (JSON), Immutable append-only log storage, Log signing (HMAC chain), PCI-DSS Req 10 compliance, SOC 2 audit requirements",
                    implementation: "Define a log schema: { event_id: UUID, timestamp: ISO8601, user_id: hashed, session_id, event_type: enum, category: enum, ip, device_id, outcome: success|failure, metadata: {}, signature: HMAC }. Chain signatures: each log entry's HMAC includes the previous entry's HMAC, creating a tamper-evident chain. Ship logs to SIEM in real-time. Retain for 1 year minimum (PCI), 7 years for SOX. Alert on: 3+ failed auths in 5 min, transaction from new device, jailbreak detection."
                ),
                SecurityMeasure(
                    title: "Anomaly Detection & Alerting",
                    description: "Real-time monitoring of security events enables early breach detection. Implement alerting rules: failed authentication spike (possible brute force), unusual transaction patterns (possible account takeover), API errors spike (possible exploitation attempt), new device login from unusual geography, certificate pinning failures (possible MITM), and jailbreak detection triggers. Use both rule-based (deterministic) and ML-based (behavioral) anomaly detection. Alert through multiple channels: push notification to user, SMS/email to security team, PagerDuty for critical severity.",
                    technology: "SIEM (Splunk, ELK, Datadog), Real-time stream processing (Kafka), ML anomaly detection, PagerDuty/OpsGenie alerting, User notification",
                    implementation: "Stream events to Kafka → process with Flink/Spark → write to SIEM. Rule engine: IF failed_auth_count(user, 5min) > 3 THEN alert(medium). IF tx_amount > 5 * user_avg AND new_device THEN alert(high). If jailbreak_detected THEN alert(critical). ML: train isolation forest on user behavior features. Notify: user gets push 'New login from iPhone in Dhaka', security team gets Slack alert, critical triggers PagerDuty page."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 15: Incident Response & Recovery
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 15,
            icon: "🚨",
            title: "Incident Response & Recovery",
            category: .monitoring,
            threat: "Active breaches, data exfiltration, ransomware, insider threats, compromised credentials at scale, and regulatory breach notification deadlines (72 hours under GDPR, 'without unreasonable delay' under PCI-DSS).",
            measures: [
                SecurityMeasure(
                    title: "Remote Kill Switch & Feature Flags",
                    description: "Your app must have the ability to remotely disable features or force-logout all users without requiring an app update. Implement a server-controlled feature flag system that your app checks on launch and periodically. Critical capabilities: (1) Force logout — invalidate all sessions server-side, app checks on next request. (2) Disable payments — turn off transaction endpoints while allowing balance views. (3) Maintenance mode — full app lockout with an informational message. (4) Force update — require users to update to a patched version. (5) Geo-block — restrict app functionality by region during targeted attacks.",
                    technology: "Feature flag services (LaunchDarkly, Firebase Remote Config), Server-side session invalidation, Forced app update mechanism, Runtime configuration",
                    implementation: "On app launch and every 5 minutes: GET /config → { kill_switch: false, min_version: \"3.2.0\", payments_enabled: true, maintenance: false, message: \"\" }. If kill_switch: true, show maintenance screen, clear all local tokens. If min_version > current: show force-update screen with App Store link. Store config in memory only (not persisted). Implement offline fallback: if config fetch fails 3 times, restrict to read-only mode."
                ),
                SecurityMeasure(
                    title: "Secure Data Wipe",
                    description: "When a device is reported lost/stolen, or when a session compromise is detected, your app must be able to securely wipe all local sensitive data. This includes: all Keychain items in your access group, cached data, downloaded files, database contents, and any temporary files. The wipe should be triggerable remotely (via push notification or flag check) and locally (user-initiated or after max failed biometric attempts). After wipe, the app should show a recovery screen, not crash. Implement wipe verification to confirm all data was successfully destroyed.",
                    technology: "Keychain batch deletion, FileManager secure deletion, SQLite VACUUM + overwrite, Silent push notifications for remote wipe, MDM integration",
                    implementation: "Wipe function: (1) Delete all Keychain items: query with kSecMatchLimitAll, delete each. (2) Overwrite DB: write random data to DB file, then delete. (3) Clear UserDefaults (non-sensitive config). (4) Delete app's Documents, Caches, tmp directories. (5) Reset in-memory state. Trigger: silent push { \"action\": \"wipe\", \"reason\": \"device_reported_stolen\" }. After wipe, navigate to a 'Device Wiped — Contact Support' screen. Log the wipe event to server (pre-wipe, so it gets through)."
                ),
                SecurityMeasure(
                    title: "Incident Response Playbook",
                    description: "A documented, rehearsed incident response plan is as critical as the technical controls. Define roles (Incident Commander, Security Lead, Communications Lead), escalation paths, and communication templates. Categorize incidents by severity: P1 (active data breach, payment system compromise) → all-hands response within 15 minutes. P2 (suspected unauthorized access, API anomaly) → security team response within 1 hour. P3 (policy violation, minor vulnerability) → next business day. Include regulatory notification timelines: GDPR requires breach notification within 72 hours, PCI-DSS requires notification to card brands and acquiring bank immediately upon confirmation.",
                    technology: "Incident response frameworks (NIST SP 800-61), PCI-DSS Incident Response (Req 12.10), Regulatory notification procedures, Post-incident review process",
                    implementation: "Document and maintain: (1) Detection — automated alerts from SIEM, user reports, third-party notifications. (2) Containment — activate kill switch, rotate compromised keys, block affected accounts. (3) Eradication — identify root cause, patch vulnerability, re-deploy. (4) Recovery — restore service, monitor closely for 72 hours. (5) Post-mortem — blameless review within 5 business days, publish internal report, update playbook. Rehearse quarterly with tabletop exercises simulating realistic scenarios."
                )
            ]
        ),

        // ──────────────────────────────────────────────
        // PHASE 16: Code Security & Supply Chain
        // ──────────────────────────────────────────────
        SecurityPhase(
            order: 16,
            icon: "🧱",
            title: "Code Security & Supply Chain",
            category: .application,
            threat: "Vulnerable dependencies (e.g., log4j-level events), malicious packages in the dependency chain, insecure coding practices, hardcoded secrets in source code, and insufficient code review allowing vulnerabilities to reach production.",
            measures: [
                SecurityMeasure(
                    title: "Dependency Security & SCA",
                    description: "Software Composition Analysis (SCA) continuously monitors your third-party dependencies for known vulnerabilities (CVEs). For iOS, this means auditing your Swift Package Manager packages, CocoaPods, and Carthage dependencies. Pin exact versions — never use open ranges in production. Audit each dependency: does it need the permissions it requests? Does it execute arbitrary code at build time? Does it phone home? Prefer Apple's native frameworks (CryptoKit over OpenSSL, URLSession over Alamofire for security-critical paths). Every dependency is an additional attack surface.",
                    technology: "Software Composition Analysis (Snyk, WhiteSource, GitHub Dependabot), Swift Package Manager version pinning, SBOM (Software Bill of Materials)",
                    implementation: "Pin exact versions in Package.swift: .exact(\"5.6.2\"), never .upToNextMajor. Run Dependabot or Snyk weekly. Review dependency tree: swift package show-dependencies. For each dependency, document: purpose, maintainer reputation, last update, known CVEs. Maintain an SBOM. Before adding any new dependency, check: is there a native Apple API? Can we implement the needed functionality in < 200 lines? If yes, prefer in-house."
                ),
                SecurityMeasure(
                    title: "Static Analysis & Secret Detection",
                    description: "Automated static analysis catches security issues before they reach production: hardcoded API keys, insecure random number generation (arc4random vs SecRandomCopyBytes), SQL injection in Core Data predicates, format string vulnerabilities, insecure data storage patterns, and deprecated crypto usage. Secret detection specifically scans for patterns matching API keys, tokens, certificates, and passwords in source code, configuration files, and git history. A single committed AWS key has led to six-figure cloud bills within hours.",
                    technology: "SwiftLint security rules, Semgrep, SonarQube, git-secrets, truffleHog (git history scanning), Pre-commit hooks",
                    implementation: "CI pipeline: (1) SwiftLint with security-focused rules (force_unwrapping, implicitly_unwrapped_optional). (2) Semgrep with swift security rulesets. (3) git-secrets pre-commit hook to block commits containing key patterns (AKIA[0-9A-Z]{16} for AWS, sk_live_ for Stripe). (4) truffleHog scan of full git history quarterly. (5) SonarQube quality gate: zero critical/high security findings. Store all secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault), never in code."
                ),
                SecurityMeasure(
                    title: "Secure Build Pipeline",
                    description: "The build pipeline is a high-value target: compromising it means every user gets the malicious code. Secure your CI/CD: use ephemeral build agents (destroyed after each build), sign builds with a hardware security module (HSM), implement branch protection requiring code review approval, use signed commits, verify the integrity of build artifacts with checksums, and implement reproducible builds where possible. The signing certificate and provisioning profile must be stored in a secrets manager, not in the repository or on developer machines.",
                    technology: "Ephemeral CI agents (GitHub Actions, Bitrise), HSM-based code signing, Signed git commits (GPG/SSH), Reproducible builds, SLSA framework",
                    implementation: "GitHub Actions: use macos-latest with clean runners. Store signing identity in GitHub Secrets (encrypted at rest). Use Fastlane match with a private git repo for provisioning. Require 2 approvals for PRs to main. Enable branch protection: no force push, no deletion, require signed commits. Implement SLSA Level 2+: build on hosted service, generate provenance attestation. Verify artifact checksums before App Store submission."
                )
            ]
        )
    ]
}

// MARK: - View

struct SecurityTimelineView: View {

    private let accent = Color.ftAccent

    @State private var expandedPhases: Set<UUID> = []

    var body: some View {
        ZStack {
            Color.ftDark.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 0) {

                    DemoHeader(
                        icon: "🏦",
                        title: "FinTech Security A → Z",
                        subtitle: "Device Boot to Incident Response",
                        accentColor: accent
                    )

                    InfoCallout(
                        text: "A comprehensive timeline of every security measure required to build a production-grade FinTech application. " +
                              "Each phase represents a layer of defense — from hardware trust roots to incident response playbooks. " +
                              "Defense in depth means every layer assumes the previous one has been compromised.",
                        icon: "shield.lefthalf.filled",
                        accent: accent
                    )
                    .padding(.horizontal, 16)
                    .padding(.top, 16)

                    LazyVStack(spacing: 0) {
                        ForEach(SecurityTimeline.phases) { phase in
                            phaseView(phase)
                        }
                    }
                    .padding(.bottom, 32)
                }
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.dark)
    }

    // MARK: - Phase View

    @ViewBuilder
    private func phaseView(_ phase: SecurityPhase) -> some View {
        let isExpanded = expandedPhases.contains(phase.id)

        VStack(spacing: 0) {

            // Timeline connector
            HStack(spacing: 0) {
                VStack(spacing: 0) {
                    if phase.order > 1 {
                        Rectangle()
                            .fill(categoryColor(phase.category).opacity(0.3))
                            .frame(width: 2, height: 16)
                    } else {
                        Spacer().frame(height: 16)
                    }

                    ZStack {
                        Circle()
                            .fill(categoryColor(phase.category).opacity(0.2))
                            .frame(width: 36, height: 36)
                        Text(phase.icon)
                            .font(.system(size: 16))
                    }

                    if phase.order < SecurityTimeline.phases.count {
                        Rectangle()
                            .fill(categoryColor(phase.category).opacity(0.3))
                            .frame(width: 2)
                            .frame(maxHeight: .infinity)
                    }
                }
                .frame(width: 50)

                // Phase card
                VStack(alignment: .leading, spacing: 0) {

                    // Phase header (tappable)
                    Button {
                        withAnimation(.easeInOut(duration: 0.25)) {
                            if isExpanded {
                                expandedPhases.remove(phase.id)
                            } else {
                                expandedPhases.insert(phase.id)
                            }
                        }
                    } label: {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text("PHASE \(phase.order)")
                                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                                    .foregroundStyle(categoryColor(phase.category))
                                    .tracking(2)

                                Spacer()

                                Text(phase.category.rawValue)
                                    .font(.system(size: 8, weight: .medium, design: .monospaced))
                                    .foregroundStyle(categoryColor(phase.category).opacity(0.7))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(categoryColor(phase.category).opacity(0.1))
                                    .clipShape(Capsule())
                            }

                            Text(phase.title)
                                .font(.system(size: 14, weight: .bold, design: .rounded))
                                .foregroundStyle(Color.ftText)
                                .multilineTextAlignment(.leading)

                            HStack(spacing: 6) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.system(size: 9))
                                    .foregroundStyle(Color.ftAmber)
                                Text(phase.threat)
                                    .font(.system(size: 10))
                                    .foregroundStyle(Color.ftTextDim)
                                    .lineLimit(isExpanded ? nil : 2)
                                    .multilineTextAlignment(.leading)
                            }

                            HStack {
                                Text("\(phase.measures.count) security measures")
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(Color.ftTextDim)
                                Spacer()
                                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundStyle(categoryColor(phase.category))
                            }
                        }
                        .padding(14)
                        .background(Color.ftSurface)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(categoryColor(phase.category).opacity(0.2), lineWidth: 1)
                        )
                    }
                    .buttonStyle(.plain)

                    // Expanded measures
                    if isExpanded {
                        VStack(spacing: 10) {
                            ForEach(phase.measures) { measure in
                                measureView(measure, accent: categoryColor(phase.category))
                            }
                        }
                        .padding(.top, 10)
                        .transition(.opacity.combined(with: .move(edge: .top)))
                    }
                }
                .padding(.trailing, 16)
                .padding(.vertical, 8)
            }
        }
        .padding(.leading, 8)
    }

    // MARK: - Measure View

    @ViewBuilder
    private func measureView(_ measure: SecurityMeasure, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 10) {

            // Title
            Text(measure.title)
                .font(.system(size: 13, weight: .bold, design: .rounded))
                .foregroundStyle(Color.ftText)

            // Description
            Text(measure.description)
                .font(.system(size: 11.5))
                .foregroundStyle(Color.ftText.opacity(0.85))
                .fixedSize(horizontal: false, vertical: true)
                .lineSpacing(2)

            // Technology
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 4) {
                    Image(systemName: "cpu")
                        .font(.system(size: 9))
                        .foregroundStyle(accent)
                    Text("TECHNOLOGY")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundStyle(accent)
                        .tracking(1.5)
                }
                Text(measure.technology)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Color.ftTextDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(accent.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))

            // Implementation
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 4) {
                    Image(systemName: "hammer")
                        .font(.system(size: 9))
                        .foregroundStyle(Color.ftAmber)
                    Text("IMPLEMENTATION")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundStyle(Color.ftAmber)
                        .tracking(1.5)
                }
                Text(measure.implementation)
                    .font(.system(size: 10.5))
                    .foregroundStyle(Color.ftText.opacity(0.75))
                    .fixedSize(horizontal: false, vertical: true)
                    .lineSpacing(1.5)
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.ftAmber.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .padding(12)
        .background(Color.ftSurface2)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.ftBorder, lineWidth: 1)
        )
    }

    // MARK: - Helpers

    private func categoryColor(_ category: SecurityPhase.PhaseCategory) -> Color {
        switch category {
        case .device:      return Color(red: 0.60, green: 0.40, blue: 0.90)
        case .application: return Color.ftAccent
        case .network:     return Color(red: 0.30, green: 0.70, blue: 0.95)
        case .auth:        return Color.ftAmber
        case .transaction: return Color.ftGreen
        case .monitoring:  return Color.ftRed
        }
    }
}
