//
//  Ed25519.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/13.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation
import CommonCrypto
import BigInt

public struct Ed25519 {
    
    struct Digest {
        var data:[UInt8]
        var length:Int
        func digest() -> [UInt8] {
            return data
        }
        func hexdiegst() -> String {
            return data.map({ String(format: "%02hhx", $0) }).joined()
        }
    }
    
    static let b:Int = 256
    static let q:BigInt = BigInt(2).power(255) - 19
    static let l:BigInt = BigInt(2).power(252) + BigInt("27742317777372353535851937790883648493")!
    static func H(_ m:[UInt8]) -> [UInt8] {
        return sha512(m).digest()
    }
    
    static func expmod(_ b:BigInt, _ e:BigInt, _ m:BigInt) -> BigInt {
        if e == 0 { return 1 }
        var t = expmod(b, e/2, m).power(2) % m
        if e.odd() != 0 {
            t = (t*b) % m
        }
        return t
    }
    
    static func inv(_ x:BigInt) -> BigInt {
        return expmod(x, q-2, q)
    }
    
    static let d:BigInt = BigInt(-121665) * inv(BigInt(121666)) 
    static let I:BigInt = expmod(2, (q-1)/4, q)
    
    static func xrecover(_ y:BigInt) -> BigInt {
        let xx = (y*y-1) * inv(d*y*y+1)
        var x = expmod(xx,(q+3)/8,q)
        if (x*x - xx) % q != 0 {
            x = (x*I) % q 
        }
        if (x % 2) != 0 {
            x = q-x
        }
        return x
    }
    
    static let By = 4 * inv(5)
    static let Bx = xrecover(By)
    static let B:[BigInt] = [Bx % q, By % q]  
    
    static func edwards(_ P:[BigInt], _ Q:[BigInt]) -> [BigInt] {
        let x1 = P[0]
        let y1 = P[1]
        let x2 = Q[0]
        let y2 = Q[1]
        let x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
        let y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
        return [x3 % q, y3 % q]
    }
    
    static func scalarmult(_ P:[BigInt], _ e:BigInt) -> [BigInt] {
        if e == 0 {
            return [0, 1]
        }
        var Q = scalarmult(P, e/2)
        Q = edwards(Q, Q)
        if e.odd() != 0 {
            Q = edwards(Q, P)
        }
        return Q
    }

    static func encodeint(_ y:BigInt) -> [UInt8] {
        var bits:[Int] = []
        for i in 0 ..< b {
            // TODO:
            bits.append((y.abs >> i).odd())
        }
        var s:[UInt8] = []
        for i in 0 ..< b/8 {
            s.append(UInt8( sum( (0..<8).map({ bits[i*8 + $0] << $0 }) )))
        }
        return s
    }
    
    static func encodepoint(_ P:[BigInt]) -> [UInt8] {
        let x = P[0]
        let y = P[1]
        var bits:[Int] = []
        for i in 0 ..< b-1 {
            // TODO:
            bits.append((y.abs >> i).odd())
        }
        bits.append(x.odd())
        var s:[UInt8] = [] 
        for i in 0 ..< b/8 {
            s.append(UInt8( sum( (0..<8).map({ bits[i*8 + $0] << $0 }) )))
        }
        return s
    }
    
    static func bit(_ h:[UInt8], _ i:Int) -> BigInt {
        // TODO:
        return BigInt((h[i/8] >> UInt8(i%8)) & 1)
    }
    
    static func publickey(_ sk:[UInt8] ) -> [UInt8] {
        let h = H(sk)
        let a:BigInt = BigInt(2).power(b-2) + sum( (3..<b-2).map({BigInt(2).power($0) * bit(h, $0)}) )
        let A = scalarmult(B, a)
        return encodepoint(A)
    }
    
    static func Hint(_ m:[UInt8]) -> BigInt {
        let h = H(m)
        return sum( (0..<2*b).map({BigInt(2).power($0) * bit(h, $0)} ) )
    }
    
    static func signature(_ m:[UInt8] , _ sk:[UInt8], _ pk:[UInt8]) -> [UInt8] {
        let h = H(sk)
        let a = BigInt(2).power(b-2) + sum( (3..<b-2).map({BigInt(2).power($0) * bit(h, $0)}) ) 
        var s:[UInt8] = [] 
        for i in b/8 ..< b/4 {
            s.append(h[i])
        }
        let r = Hint(s+m)
        let R = scalarmult(B,r)
        let S = (r + Hint(encodepoint(R) + pk + m) * a) % l
        return encodepoint(R) + encodeint(S)
    }
    
    static func isoncurve(_ P:[BigInt]) -> Bool {
        let x = P[0]
        let y = P[1]
        let z1 = -x*x
        let z2 = y*y 
        let z3 = BigInt(-1)
        let z4 = -d*x*x*y*y
        let z10 = (z1 + z2 + z3 + z4) % q
        return z10 == 0
    }
    
    static func decodeint(_ s:[UInt8]) -> BigInt {
        return sum( (0..<b).map({ BigInt(2).power($0) * bit(s,$0)}) )
    }
    
    static func decodepoint(_ s:[UInt8]) -> [BigInt] {
        let y = sum( (0..<b-1).map({BigInt(2).power($0) * bit(s, $0)}) )
        var x = xrecover(y)
        if BigInt(x.odd()) != bit(s, b-1) {
            x = q-x
        }
        let P = [x,y]
        if !isoncurve(P) {
            fatalError("decoding point that is not on curve")
        }
        return P
    }
    
    static func checkvalid(_ s:[UInt8], _ m:[UInt8], _ pk:[UInt8]) -> Bool {
        if s.count != b/4 {
            // signature length is wrong
            return false
        }
        if pk.count != b/8 {
            // public-key length is wrong
            return false
        }
        let R = decodepoint(Array(s[0..<b/8]))
        let A = decodepoint(pk)
        let S = decodeint(Array(s[b/8..<b/4]))
        let h = Hint(encodepoint(R) + pk + m)
        if scalarmult(B, S) != edwards(R, scalarmult(A, h)) {
            // Signature does not pass verification
            return false
        }
        return true
    }
}

// TODO:generics
func sum(_ numbers: [BigInt]) -> BigInt {
    var sum:BigInt = 0
    for n in numbers {
        sum += n
    }
    return sum
}

func sum(_ numbers: [Int]) -> Int {
    var sum:Int = 0
    for n in numbers {
        sum += n
    }
    return sum
}

extension String {
    func unhexlify() -> [UInt8] {
        var pos = startIndex
        return (0..<characters.count/2).flatMap { _ in
            defer { pos = index(pos, offsetBy: 2) }
            return UInt8(self[pos...index(after: pos)], radix: 16)
        }
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
