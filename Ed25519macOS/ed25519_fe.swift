//
//  fe25519.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/20.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation

// field element
struct fe: CustomStringConvertible {
    
    // if WINDOWSIZE equal 1, 8bit * 32 = 256bit
    // size:32
    public var v:[UInt32]

    public var description: String {
        return v.map({ String(format:"%d ", $0)}).joined()
    }
    
    public init(){
        v = [UInt32](repeating:0, count:32)
    }
    public init(_ v:[UInt32]){
        self.v = v
    }

    static let WINDOWSIZE:Int = 1 /* Should be 1,2, or 4 */
    static let WINDOWMASK:Int = ((1<<WINDOWSIZE)-1)

    static func equal(_ a:UInt32, _ b:UInt32) -> UInt32  /* 16-bit inputs */
    {
        return a == b ? 1 : 0
    }
    
    // greater equal
    static func ge(_ a:UInt32 ,_ b:UInt32) -> UInt32 /* 16-bit inputs */
    {
        return a >= b ? 1 : 0
    }
    
    // 19 * a = (2^4 + 2^1 + 2^0) * a
    static func times19(_ a:UInt32) -> UInt32
    {
        return (a << 4) + (a << 1) + a
    }
    
    // 38 * a = (2^5 + 2^2 + 2^1) * a
    static func times38(_ a:UInt32) -> UInt32
    {
        return (a << 5) + (a << 2) + (a << 1)
    }

    // ffff ffff ... ffff
    // ffff ffff ... ffed
    // 0xed = 1110 1101
    static func reduce_add_sub(_ r:inout fe)
    {
        var t:UInt32
        // 32bit / 8bit = 4
        for _ in 0..<4
        {
            t = r.v[31] >> 7
            r.v[31] &= 127
            t = times19(t)
            r.v[0] += t
            for i in 0..<31
            {
                t = r.v[i] >> 8
                r.v[i+1] += t
                r.v[i] &= 255
            }
        }
    }

    static func reduce_mul(_ r:inout fe)
    {
        var t:UInt32
        for _ in 0..<2
        {
            t = r.v[31] >> 7
            r.v[31] &= 127
            t = times19(t)
            r.v[0] += t
            for i in 0..<31
            {
                t = r.v[i] >> 8
                r.v[i+1] += t
                r.v[i] &= 255
            }
        }
    }

    /* reduction modulo 2^255-19 */
    static func fe25519_freeze(_ r:inout fe) 
    {
        var m:UInt32 = equal(r.v[31], 127)
        for i in stride(from:30, to:0, by: -1) {
            m &= equal(r.v[i], 255)
        }
        m &= ge(r.v[0], 237)
        
        m = UInt32(bitPattern:Int32(m) * -1)
        
        r.v[31] -= (m&127)
        for i in stride(from:30, to:0, by: -1) {
            r.v[i] -= m&255
        }
        r.v[0] -= m&237
    }

    static func fe25519_unpack(_ r:inout fe, _ x:[UInt8]/* 32 */)
    {
        for i in 0..<32 {
            r.v[i] = UInt32(x[i])
        }
        r.v[31] &= 127
    }

    /* Assumes input x being reduced mod 2^255 */
     static func fe25519_pack(_ r:inout [UInt8] /* 32 */ , _ x:fe)
    {
        var y:fe = x
        fe.fe25519_freeze(&y)
        for i in 0..<32 {
            r[i] = UInt8(y.v[i])
        }
    }

    // freeze input before calling iszero
    static func fe25519_iszero(_ x:fe) -> Bool {
        var t:fe = x
        fe.fe25519_freeze(&t)
        var r = fe.equal(t.v[0], 0)
        for i in 1..<32 {
            r &= fe.equal(t.v[i],0)
        }
        return r != 0
    }

    // is euqal after freeze
    static func fe25519_iseq_vartime(_ x:fe, _ y:fe) -> Bool
    {
        var t1:fe = x
        var t2:fe = y
        fe.fe25519_freeze(&t1)
        fe.fe25519_freeze(&t2)
        for i in 0..<32 {
            if t1.v[i] != t2.v[i] {
                return false
            }
        }
        return true
    }

    static func fe25519_cmov(_ r:inout fe, _ x:fe, _ b:UInt8)
    {
        let mask:UInt32 = UInt32(bitPattern:Int32(b) * -1)
        for i in 0..<32 {
            r.v[i] ^= mask & (x.v[i] ^ r.v[i])
        }
    }

    // odd:1 even:0
    static func fe25519_getparity(_ x:fe) -> UInt8
    {
        var t:fe = x
        fe.fe25519_freeze(&t)
        return UInt8(t.v[0] & 1)
    }

    // set 1
    static func fe25519_setone(_ r:inout fe)
    {
        r.v[0] = 1
        for i in 1..<32 {
            r.v[i] = 0
        }
    }

    // set 0
    static func fe25519_setzero(_ r:inout fe)
    {
        for i in 0..<32 {
            r.v[i] = 0
        }
    }

    static func fe25519_neg(_ r:inout fe, _ x:fe)
    {
        var t:fe = fe()
        for i in 0..<32 {
            t.v[i] = x.v[i]
        }
        fe25519_setzero(&r)
        fe25519_sub(&r, r, t)
    }

    static func fe25519_add(_ r:inout fe, _ x:fe, _ y:fe)
    {
        for i in 0..<32 {
            r.v[i] = x.v[i] + y.v[i]
        }
        fe.reduce_add_sub(&r)
    }

    // q = 2 ** 256 - 19
    /**
     ffff ffff ffff ffff ffff ffff ffff ffff
     ffff ffff ffff ffff ffff ffff ffff ffed
     2 * ff = 1fe
     2 * ed = 1da
     */
    static func fe25519_sub(_ r:inout fe, _ x:fe, _ y:fe)
    {
        var t:[UInt32] = [UInt32](repeating:0, count:32)
        t[0] = x.v[0] + 0x1da
        t[31] = x.v[31] + 0xfe // TODO: why not 0x1fe?
        for i in 1..<31 { t[i] = x.v[i] + 0x1fe }
        for i in 0..<32 { r.v[i] = t[i] - y.v[i] }
        fe.reduce_add_sub(&r)
    }

    // r = x * y
    static func fe25519_mul(_ r:inout fe, _ x:fe, _ y:fe)
    {
        var t:[UInt32] = [UInt32](repeating:0, count:63)

        for i in 0..<32 {
            for j in 0..<32 {
                t[i+j] += x.v[i] * y.v[j]
            }
        }
        
        for i in 32..<63 {
            r.v[i-32] = t[i-32] + fe.times38(t[i])
        }
        r.v[31] = t[31] /* result now in r[0]...r[31] */
        
        fe.reduce_mul(&r)
    }

    // r = x^2
    static func fe25519_square(_ r:inout fe, _ x:fe)
    {
        fe25519_mul(&r, x, x)
    }

    // q=2^255-19
    // 1/a = a^(q-2)
    // q-2 = 2^255-21
    static func fe25519_invert(_ r:inout fe, _ x:fe)
    {
        var z2:fe = fe()
        var z9:fe = fe()
        var z11:fe = fe()
        var z2_5_0:fe = fe()
        var z2_10_0:fe = fe()
        var z2_20_0:fe = fe()
        var z2_50_0:fe = fe()
        var z2_100_0:fe = fe()
        var t0:fe = fe()
        var t1:fe = fe()
        
        /* 2 */ fe25519_square(&z2,x)
        /* 4 */ fe25519_square(&t1,z2)
        /* 8 */ fe25519_square(&t0,t1)
        /* 9 */ fe25519_mul(&z9,t0,x)
        /* 11 */ fe25519_mul(&z11,z9,z2)
        /* 22 */ fe25519_square(&t0,z11)
        /* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0,t0,z9)
        
        /* 2^6 - 2^1 */ fe25519_square(&t0,z2_5_0)
        /* 2^7 - 2^2 */ fe25519_square(&t1,t0)
        /* 2^8 - 2^3 */ fe25519_square(&t0,t1)
        /* 2^9 - 2^4 */ fe25519_square(&t1,t0)
        /* 2^10 - 2^5 */ fe25519_square(&t0,t1)
        /* 2^10 - 2^0 */ fe25519_mul(&z2_10_0,t0,z2_5_0)
        
        /* 2^11 - 2^1 */ fe25519_square(&t0,z2_10_0)
        /* 2^12 - 2^2 */ fe25519_square(&t1,t0)
        /* 2^20 - 2^10 */ for _ in stride(from:2, to:10, by: 2) { fe25519_square(&t0,t1); fe25519_square(&t1,t0) }
        /* 2^20 - 2^0 */ fe25519_mul(&z2_20_0,t1,z2_10_0)
        
        /* 2^21 - 2^1 */ fe25519_square(&t0,z2_20_0)
        /* 2^22 - 2^2 */ fe25519_square(&t1,t0)
        /* 2^40 - 2^20 */ for _ in stride(from:2, to: 20, by: 2) { fe25519_square(&t0,t1); fe25519_square(&t1,t0) }
        /* 2^40 - 2^0 */ fe25519_mul(&t0,t1,z2_20_0)
        
        /* 2^41 - 2^1 */ fe25519_square(&t1,t0)
        /* 2^42 - 2^2 */ fe25519_square(&t0,t1)
        /* 2^50 - 2^10 */ for _ in stride(from: 2, to: 10, by: 2) { fe25519_square(&t1,t0); fe25519_square(&t0,t1) }
        /* 2^50 - 2^0 */ fe25519_mul(&z2_50_0,t0,z2_10_0)
        
        /* 2^51 - 2^1 */ fe25519_square(&t0,z2_50_0)
        /* 2^52 - 2^2 */ fe25519_square(&t1,t0)
        /* 2^100 - 2^50 */ for _ in stride(from: 2, to: 50, by: 2) { fe25519_square(&t0,t1); fe25519_square(&t1,t0) }
        /* 2^100 - 2^0 */ fe25519_mul(&z2_100_0,t1,z2_50_0)
        
        /* 2^101 - 2^1 */ fe25519_square(&t1,z2_100_0)
        /* 2^102 - 2^2 */ fe25519_square(&t0,t1)
        /* 2^200 - 2^100 */ for _ in stride(from: 2, to: 100, by: 2) { fe25519_square(&t1,t0); fe25519_square(&t0,t1) }
        /* 2^200 - 2^0 */ fe25519_mul(&t1,t0,z2_100_0)
        
        /* 2^201 - 2^1 */ fe25519_square(&t0,t1)
        /* 2^202 - 2^2 */ fe25519_square(&t1,t0)
        /* 2^250 - 2^50 */ for _ in stride(from: 2, to: 50, by: 2) { fe25519_square(&t0,t1); fe25519_square(&t1,t0) }
        /* 2^250 - 2^0 */ fe25519_mul(&t0,t1,z2_50_0)
        
        /* 2^251 - 2^1 */ fe25519_square(&t1,t0)
        /* 2^252 - 2^2 */ fe25519_square(&t0,t1)
        /* 2^253 - 2^3 */ fe25519_square(&t1,t0)
        /* 2^254 - 2^4 */ fe25519_square(&t0,t1)
        /* 2^255 - 2^5 */ fe25519_square(&t1,t0)
        /* 2^255 - 21 */ fe25519_mul(&r,t1,z11)
    }

    // q = 2^255-19
    // (q-5)/8 = 2^252 - 3
    static func fe25519_pow2523(_ r:inout fe, _ x:fe)
    {
        var z2:fe = fe()
        var z9:fe = fe()
        var z11:fe = fe()
        var z2_5_0:fe = fe()
        var z2_10_0:fe = fe()
        var z2_20_0:fe = fe()
        var z2_50_0:fe = fe()
        var z2_100_0:fe = fe()
        var t:fe = fe()
        
        /* 2 */ fe25519_square(&z2,x)
        /* 4 */ fe25519_square(&t,z2)
        /* 8 */ fe25519_square(&t,t)
        /* 9 */ fe25519_mul(&z9,t,x)
        /* 11 */ fe25519_mul(&z11,z9,z2)
        /* 22 */ fe25519_square(&t,z11)
        /* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0,t,z9)
        
        /* 2^6 - 2^1 */ fe25519_square(&t,z2_5_0)
        /* 2^10 - 2^5 */ for _ in 1..<5 { fe25519_square(&t,t) }
        /* 2^10 - 2^0 */ fe25519_mul(&z2_10_0,t,z2_5_0)
        
        /* 2^11 - 2^1 */ fe25519_square(&t,z2_10_0)
        /* 2^20 - 2^10 */ for _ in 1..<10 { fe25519_square(&t,t) }
        /* 2^20 - 2^0 */ fe25519_mul(&z2_20_0,t,z2_10_0)
        
        /* 2^21 - 2^1 */ fe25519_square(&t,z2_20_0)
        /* 2^40 - 2^20 */ for _ in 1..<20 { fe25519_square(&t,t) }
        /* 2^40 - 2^0 */ fe25519_mul(&t,t,z2_20_0)
        
        /* 2^41 - 2^1 */ fe25519_square(&t,t)
        /* 2^50 - 2^10 */ for _ in 1..<10 { fe25519_square(&t,t) }
        /* 2^50 - 2^0 */ fe25519_mul(&z2_50_0,t,z2_10_0)
        
        /* 2^51 - 2^1 */ fe25519_square(&t,z2_50_0)
        /* 2^100 - 2^50 */ for _ in 1..<50 { fe25519_square(&t,t) }
        /* 2^100 - 2^0 */ fe25519_mul(&z2_100_0,t,z2_50_0)
        
        /* 2^101 - 2^1 */ fe25519_square(&t,z2_100_0)
        /* 2^200 - 2^100 */ for _ in 1..<100 { fe25519_square(&t,t) }
        /* 2^200 - 2^0 */ fe25519_mul(&t,t,z2_100_0)
        
        /* 2^201 - 2^1 */ fe25519_square(&t,t)
        /* 2^250 - 2^50 */ for _ in 1..<50 { fe25519_square(&t,t) }
        /* 2^250 - 2^0 */ fe25519_mul(&t,t,z2_50_0)
        
        /* 2^251 - 2^1 */ fe25519_square(&t,t)
        /* 2^252 - 2^2 */ fe25519_square(&t,t)
        /* 2^252 - 3 */ fe25519_mul(&r,t,x)
    }
}

