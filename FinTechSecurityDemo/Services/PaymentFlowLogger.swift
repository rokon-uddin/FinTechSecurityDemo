//
//  PaymentFlowLogger.swift
//  FinTechSecurityDemo
//
//  Created by Mohammed Rokon Uddin on 5/8/26.
//  Copyright © 2026 Rokon Uddin. All rights reserved.
//

import OSLog

enum PaymentFlowLogger {

    private static let subsystem = "com.fintech.demo"

    static let flow     = Logger(subsystem: subsystem, category: "paymentFlow")
    static let auth     = Logger(subsystem: subsystem, category: "auth")
    static let crypto   = Logger(subsystem: subsystem, category: "crypto")
    static let token    = Logger(subsystem: subsystem, category: "tokenization")
    static let signing  = Logger(subsystem: subsystem, category: "signing")
    static let network  = Logger(subsystem: subsystem, category: "network")
}
