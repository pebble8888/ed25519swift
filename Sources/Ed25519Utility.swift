//
//  Ed25519Other.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/20.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation
import CommonCrypto
import BigInt

protocol Summable {
    static var Zero: Self { get }
    static func +(lhs: Self, rhs: Self) -> Self
}

extension Sequence where Iterator.Element: Summable {
    func sum() -> Iterator.Element {
        return self.reduce(Iterator.Element.Zero, +)
    }
}

extension Int: Summable {
    static var Zero: Int { return 0 }
}

extension BigInt: Summable {
    static var Zero: BigInt { return BigInt(0) }
}

extension String {
    public func unhexlify() -> [UInt8] {
        var pos = startIndex
        return (0..<characters.count/2).flatMap { _ in
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

func sha512(_ s:[UInt8]) -> Ed25519.Digest {
    let data = Data(bytes:s)
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    data.withUnsafeBytes({
        _ = CC_SHA512($0, CC_LONG(data.count), &digest)
    })
    return Ed25519.Digest(data: digest, length: Int(CC_SHA512_DIGEST_LENGTH))
}
