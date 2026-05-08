//
//  ContentView.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//



// Root navigation — wires up all dependencies and presents all demo tabs.
// All services are created here and injected into ViewModels (DIP).
// The view layer has zero knowledge of concrete service implementations.

import SwiftUI

struct ContentView: View {

    // MARK: - ViewModels (each receives only the services it needs — ISP)

    @State private var tokenizationVM: TokenizationViewModel
    @State private var otpVM:          OTPViewModel
    @State private var signingVM:      TransactionSigningViewModel
    @State private var sessionVM:      SessionViewModel
    @State private var paymentFlowVM:  PaymentFlowViewModel

    init() {
        let storage   = InMemorySecureStorage()
        let auditLog  = AuditLogService()
        let nonces    = NonceService()
        let gateway   = MockTokenizationGateway()
        let otpSvc    = OTPService(nonceService: nonces, auditLog: auditLog)
        let authBack  = MockAuthBackend()

        _tokenizationVM = State(initialValue: TokenizationViewModel(
            tokenService: TokenizationService(
                storage: storage, auditLog: auditLog, gateway: gateway
            ),
            auditLog: auditLog
        ))

        _otpVM = State(initialValue: OTPViewModel(
            otpService:  otpSvc,
            totpService: TOTPService.shared
        ))

        let signingService = TransactionSigningService(storage: storage, auditLog: auditLog)
        _signingVM = State(initialValue: TransactionSigningViewModel(
            signingService:      signingService,
            verificationService: TransactionVerificationService(),
            nonceService:        nonces,
            auditLog:            auditLog
        ))

        _sessionVM = State(initialValue: SessionViewModel(
            sessionService: SessionService(
                storage: storage, auditLog: auditLog, authBackend: authBack
            ),
            auditLog:     auditLog,
            nonceService: nonces
        ))

        let flowStorage  = InMemorySecureStorage()
        let flowAudit    = AuditLogService()
        let flowGateway  = MockTokenizationGateway()
        let flowAuthBack = MockAuthBackend()
        let flowSigning  = TransactionSigningService(storage: flowStorage, auditLog: flowAudit)

        _paymentFlowVM = State(initialValue: PaymentFlowViewModel(
            sessionService:      SessionService(
                storage: flowStorage, auditLog: flowAudit, authBackend: flowAuthBack
            ),
            tokenService:        TokenizationService(
                storage: flowStorage, auditLog: flowAudit, gateway: flowGateway
            ),
            signingService:      flowSigning,
            verificationService: TransactionVerificationService(),
            auditLog:            flowAudit
        ))
    }

    var body: some View {
        TabView {
            Tab("AES-GCM", systemImage: "lock.fill") {
                NavigationStack { AESGCMDemoView() }
            }
            Tab("HMAC", systemImage: "signature") {
                NavigationStack { HMACDemoView() }
            }
            Tab("ECDH", systemImage: "arrow.triangle.2.circlepath") {
                NavigationStack { ECDHDemoView() }
            }
            Tab("RSA", systemImage: "key.fill") {
                NavigationStack { RSADemoView() }
            }
            Tab("SE", systemImage: "cpu") {
                SecureEnclaveDemoView()
            }
            Tab("PCI/Token", systemImage: "creditcard.fill") {
                PCITokenizationView(vm: tokenizationVM)
            }
            Tab("OTP/TOTP", systemImage: "number.circle.fill") {
                OTPDemoView(vm: otpVM)
            }
            Tab("Tx Sign", systemImage: "pencil.and.scribble") {
                TransactionSigningView(vm: signingVM)
            }
            Tab("Session", systemImage: "person.badge.clock.fill") {
                SessionManagementView(vm: sessionVM)
            }
            Tab("A → Z", systemImage: "shield.checkerboard") {
                AtoZContainerView(paymentFlowVM: paymentFlowVM)
            }
        }
        .tint(.teal)
        .preferredColorScheme(.dark)
    }
}

