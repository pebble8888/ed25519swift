//
//  ed25519_utility.swift
//
//  Created by pebble8888 on 2017/05/20.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation
#if NO_USE_CryptoSwift
import CommonCrypto
#else
import CryptoSwift
#endif

extension String {
    public func unhexlify() -> [UInt8] {
        var pos = startIndex
        return (0..<count/2).flatMap { _ in
            defer { pos = index(pos, offsetBy: 2) }
            return UInt8(self[pos...index(after: pos)], radix: 16)
        }
    }
}

extension Collection where Iterator.Element == UInt8 {
    public func hexDescription() -> String {
        return self.map({ String(format: "%02x", $0) }).joined()
    }
}

func sha512(_ s:[UInt8]) -> [UInt8] {
#if NO_USE_CryptoSwift
    let data = Data(bytes:s)
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    data.withUnsafeBytes({
        _ = CC_SHA512($0, CC_LONG(data.count), &digest)
    })
    return digest
#else
    return s.sha512()
#endif
}
