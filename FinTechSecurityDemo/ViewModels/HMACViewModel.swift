//
//  HMACViewModel.swift
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
final class HMACViewModel {
    var receiverWallet  = "01987654321"
    var amountBDT       = "1200.00"
    var currentStep     = 0
    var isProcessing    = false

    // Output fields
    var canonicalRequest  = ""
    var hmacSignature     = ""
    var requestBodyJSON   = ""
    var serverResultMsg   = ""
    var serverSuccess     = false
    var tamperAmount      = false

    // Internal state
    private var originalBody: Data?
    private var originalSignature = ""

    // MARK: - Step 1: Build and sign the request

    func buildAndSign() {
        isProcessing = true
        let paise = Int64((Double(amountBDT) ?? 0) * 100)
        let timestamp = Int64(Date.now.timeIntervalSince1970)
        let nonce = UUID().uuidString

        let tx = TransactionPayload(
            transactionId:  UUID().uuidString,
            senderWallet:   "01800000001",
            receiverWallet: receiverWallet,
            amountPaisa:    paise,
            timestampUnix:  timestamp,
            nonce:          nonce,
            currency:       "BDT",
            note:           "Transfer"
        )
        let bodyData = (try? JSONEncoder().encode(tx)) ?? Data()
        originalBody = bodyData

        let bodyHash = SHA256.hash(data: bodyData)
        let bodyHashHex = Data(bodyHash).hexString

        let canonical = [
            "POST",
            "/api/v3/transfer",
            String(timestamp),
            nonce,
            bodyHashHex
        ].joined(separator: "\n")

        canonicalRequest = canonical

        let key  = MockBackend.hmacSecret
        let mac  = HMAC<SHA256>.authenticationCode(
            for: canonical.data(using: .utf8)!,
            using: key
        )
        let sigHex = Data(mac).hexString
        hmacSignature = sigHex
        originalSignature = sigHex

        if let prettyBody = prettyJSON(bodyData) {
            requestBodyJSON = prettyBody
        }

        currentStep  = 1
        isProcessing = false
    }

    // MARK: - Step 2: Send to server

    func sendToServer() {
        guard let body = originalBody else { return }
        isProcessing = true

        var sendBody = body
        let sendSig  = originalSignature

        if tamperAmount {
            if var dict = try? JSONSerialization.jsonObject(with: body) as? [String: Any] {
                dict["amountPaisa"] = Int64(999999_00)
                sendBody = (try? JSONSerialization.data(withJSONObject: dict)) ?? body
            }
        }

        let result = MockBackend.verifyHMACSignature(body: sendBody, signatureHex: sendSig)
        serverResultMsg = result.message
        serverSuccess   = result.valid
        currentStep     = 2
        isProcessing    = false
    }

    func reset() {
        currentStep = 0
        canonicalRequest = ""; hmacSignature = ""; requestBodyJSON = ""
        serverResultMsg = ""; serverSuccess = false; tamperAmount = false
        originalBody = nil; originalSignature = ""
    }

    private func prettyJSON(_ data: Data) -> String? {
        guard let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(withJSONObject: obj,
                                                        options: .prettyPrinted)
        else { return nil }
        return String(data: pretty, encoding: .utf8)
    }
}
