//
//  OTPViewModel.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/5/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//




import Foundation
import Observation
import Security

@Observable
@MainActor
public final class OTPViewModel {

    // MARK: State — OTP tab
    public var walletInput       = "01800000001"
    public var generatedOTP:     OTP?
    public var otpCodeInput      = ""
    public var otpValidationMsg  = ""
    public var otpValid:         Bool? = nil
    public var isLoadingOTP      = false

    // MARK: State — TOTP tab
    public var totpConfig:       TOTPConfig?
    public var currentTOTP       = ""
    public var totpInput         = ""
    public var totpValidationMsg = ""
    public var totpValid:        Bool? = nil
    public var totpSecondsLeft   = 30
    public var enrollmentURL:    URL?

    // MARK: Dependencies
    private let otpService:  any OTPServiceProtocol
    private let totpService: any TOTPServiceProtocol
    private var totpTimerTask: Task<Void, Never>?

    public init(
        otpService:  any OTPServiceProtocol,
        totpService: any TOTPServiceProtocol
    ) {
        self.otpService  = otpService
        self.totpService = totpService
    }

    // MARK: - OTP Intents

    public func generateOTP() async {
        isLoadingOTP = true
        otpValid     = nil
        otpValidationMsg = ""

        let wallet = WalletID(rawValue: walletInput)
        do {
            let otp = try await otpService.generateOTP(for: wallet)
            generatedOTP = otp
        } catch let err as OTPError {
            otpValidationMsg = describeOTPError(err)
        } catch {
            otpValidationMsg = error.localizedDescription
        }
        isLoadingOTP = false
    }

    public func validateOTP() async {
        let wallet = WalletID(rawValue: walletInput)
        do {
            let valid = try await otpService.validateOTP(code: otpCodeInput, for: wallet)
            otpValid         = valid
            otpValidationMsg = valid
                ? "✓ OTP verified. Authentication successful."
                : "✗ Invalid code. \(generatedOTP.map { _ in "" } ?? "")"
        } catch let err as OTPError {
            otpValid         = false
            otpValidationMsg = describeOTPError(err)
        } catch {
            otpValid         = false
            otpValidationMsg = error.localizedDescription
        }
    }

    // MARK: - TOTP Intents

    public func enrollTOTP() {
        var secretBytes = [UInt8](repeating: 0, count: 20)
        _ = SecRandomCopyBytes(kSecRandomDefault, secretBytes.count, &secretBytes)
        let secret = Data(secretBytes)

        let config = TOTPConfig(
            secret:      secret,
            digits:      6,
            period:      30,
            algorithm:   .sha1,
            issuer:      "FinTech",
            accountName: walletInput
        )
        totpConfig   = config
        enrollmentURL = totpService.enrollmentURI(config: config)

        startTOTPTimer()
        refreshTOTP()
    }

    public func validateTOTP() {
        guard let config = totpConfig else { return }
        let valid        = totpService.validate(code: totpInput, config: config, at: Date.now)
        totpValid        = valid
        totpValidationMsg = valid
            ? "✓ TOTP verified. Code is valid."
            : "✗ Invalid code. Check the time window."
    }

    public func stopTimer() { totpTimerTask?.cancel() }

    // MARK: - Private

    private func startTOTPTimer() {
        totpTimerTask?.cancel()
        totpTimerTask = Task {
            while !Task.isCancelled {
                refreshTOTP()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func refreshTOTP() {
        guard let config = totpConfig else { return }
        currentTOTP   = totpService.generate(config: config, at: Date.now)
        totpSecondsLeft = totpService.secondsRemaining(config: config, at: Date.now)
        if totpSecondsLeft == 30 {
            totpValid = nil; totpValidationMsg = ""
        }
    }

    private func describeOTPError(_ error: OTPError) -> String {
        switch error {
        case .expired:          return "✗ OTP has expired (5-minute window)"
        case .alreadyUsed:      return "✗ OTP already used (single-use)"
        case .invalidCode:      return "✗ Invalid OTP code"
        case .tooManyAttempts:  return "✗ Too many failed attempts — locked"
        case .walletNotFound:   return "✗ Wallet not found or invalid"
        }
    }
}
