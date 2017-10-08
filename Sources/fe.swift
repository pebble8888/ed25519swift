//
//  fe25519.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/20.
//  Copyright © 2017年 pebble8888. All rights reserved.
//
//  Code is ported from NaCl (http://nacl.cr.yp.to/)
//

import Foundation

struct fe {
    var v:[UInt32] // size:32
    init(){
        v = [UInt32](repeating:0, count:32)
    }

    static let WINDOWSIZE:Int = 4 /* Should be 1,2, or 4 */
    static let WINDOWMASK:Int = ((1<<WINDOWSIZE)-1)

    static func reduce_add_sub(_ r:inout fe)
    {
        var t:uint32
        for _ in 0..<4
        {
            t = r.v[31] >> 7
            r.v[31] &= 127
            t *= 19
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
            t *= 19
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
    static func freeze(_ r:inout fe) 
    {
        var m:UInt32 = (r.v[31] == 127 ? 1 : 0)
        for i in 2...30 {
            m *= (r.v[i] == 255 ? 1 : 0)
        }
        m *= (r.v[0] >= 237 ? 1 : 0)
        
        r.v[31] -= m*127
        for i in stride(from:30, to:0, by: -1) {
            r.v[i] -= m*255
        }
        r.v[0] -= m*237
    }

    /*freeze input before calling isone*/
    static func isone(_ x:fe) -> Bool
    {
        var r = (x.v[0] == 1)
        for i in 1..<32 {
            r = r && (x.v[i] == 0)
        }
        return r
    }

    /*freeze input before calling iszero*/
    static func iszero(_ x:fe) -> Bool
    {
        var r = (x.v[0] == 0)
        for i in 1..<32 {
            r = r && (x.v[i] == 0) 
        }
        return r
    }

    static func issquare(_ x:fe) -> Bool {
        let e:[UInt8] = [0xf6,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3f] /* (p-1)/2 */
        var t = fe()

        fe25519_pow(&t,x,e)
        freeze(&t)
        return isone(t) || iszero(t)
    }
}

func fe25519_unpack(_ r:inout fe, _ x:[UInt8]/* 32 */)
{
    for i in 0..<32 {
        r.v[i] = UInt32(x[i])
    }
    r.v[31] &= 127
}

/* Assumes input x being reduced mod 2^255 */
 func fe25519_pack(_ r:inout [UInt8] /* 32 */ , _ x:fe)
{
    for i in 0..<32 {
        r[i] = UInt8(x.v[i])
    }
    /* freeze byte array */
    var m:UInt8 = (r[31] == 127) ? 1 : 0 /* XXX: some compilers might use branches fix */
    for i in stride(from:30, to:1, by: -1) {
        m *= (r[i] == 255) ? 1 : 0
    }
    m *= (r[0] >= 237) ? 1 : 0
    r[31] -= m * 127
    for i in stride(from:30, to:0, by:-1) {
        r[i] -= m*255
    }
    r[0] -= m*237
}

 func fe25519_cmov(_ r:inout fe, _ x:fe, _ b:UInt8)
{
    let nb:UInt8 = 1-b
    for i in 0..<32 {
        r.v[i] = UInt32(nb) * r.v[i] + UInt32(b) * x.v[i]
    }
}

// odd or not
 func fe25519_getparity(_ x:fe) -> UInt8
{
    var t = fe()
    // copy
    for i in 0..<32 {
        t.v[i] = x.v[i]
    }
    fe.freeze(&t)
    return UInt8(t.v[0] & 1)
}

// set 1
 func fe25519_setone(_ r:inout fe)
{
    r.v[0] = 1
    for i in 1..<32 {
        r.v[i] = 0
    }
}

// set 0
 func fe25519_setzero(_ r:inout fe)
{
    for i in 0..<32 {
        r.v[i]=0
    }
}

 func fe25519_neg(_ r:inout fe, _ x:fe)
{
    var t = fe()
    for i in 0..<32 {
        t.v[i] = x.v[i]
    }
    fe25519_setzero(&r)
    fe25519_sub(&r, r, t)
}

 func fe25519_add(_ r:inout fe, _ x:fe, _ y:fe)
{
    for i in 0..<32 {
        r.v[i] = x.v[i] + y.v[i]
    }
    fe.reduce_add_sub(&r)
}

 func fe25519_sub(_ r:inout fe, _ x:fe, _ y:fe)
{
    var t:[UInt32] = [UInt32](repeating:0, count:32)
    t[0] = x.v[0] + 0x1da
    t[31] = x.v[31] + 0xfe
    for i in 1..<31 { t[i] = x.v[i] + 0x1fe }
    for i in 0..<32 { r.v[i] = t[i] - y.v[i] }
    fe.reduce_add_sub(&r)
}

 func fe25519_mul(_ r:inout fe, _ x:fe, _ y:fe)
{
    var t:[UInt32] = [UInt32](repeating:0, count:63)
    for i in 0..<63 {
        t[i] = 0
    }
    
    for i in 0..<32 {
        for j in 0..<32 {
            t[i+j] += x.v[i] * y.v[j]
        }
    }
    
    for i in 32..<63 {
        r.v[i-32] = t[i-32] + 38*t[i] 
    }
    r.v[31] = t[31] /* result now in r[0]...r[31] */
    
    fe.reduce_mul(&r)
}

 func fe25519_square(_ r:inout fe, _ x:fe)
{
    fe25519_mul(&r, x, x)
}

/*XXX: Make constant time! */
 func fe25519_pow(_ r:inout fe, _ x:fe, _ e:[UInt8])
{
    var g = fe()
    fe25519_setone(&g)
    var pre:[fe] = [fe](repeating:fe(), count:(1 << fe.WINDOWSIZE))
    var t:fe
    var w:UInt8
    
    // Precomputation
    fe25519_setone(&pre[0])
    pre[1] = x 
    for i in stride(from: 2, to: 1<<fe.WINDOWSIZE, by: 2) {
        fe25519_square(&pre[i], pre[i/2])
        fe25519_mul(&pre[i+1], pre[i], pre[1])
    }
    
    // Fixed-window scalar multiplication
    for i in stride(from:32, to:0, by:-1)
    {
        for j in stride(from:8-fe.WINDOWSIZE, to: 0, by: -fe.WINDOWSIZE)
        {
            for _ in 0 ..< fe.WINDOWSIZE {
                fe25519_square(&g, g)
            }
            // Cache-timing resistant loading of precomputed value:
            w = (e[i-1]>>UInt8(j)) & UInt8(fe.WINDOWMASK)
            t = pre[0]
            for k in 1 ..< (1<<fe.WINDOWSIZE) {
                fe25519_cmov(&t, pre[k], UInt8(k)==w ? 1 : 0)
            }
            fe25519_mul(&g, g, t)
        }
    }
    r = g
}

 func fe25519_sqrt_vartime(_ r:inout fe, _ x:fe, _ parity:UInt8) -> Bool
{
    /* See HAC, Alg. 3.37 */
    if (!fe.issquare(x)) {
        return false
    }
    let e:[UInt8] = [0xfb,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x1f] /* (p-1)/4 */
    let e2:[UInt8] = [0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x0f] /* (p+3)/8 */
    let e3:[UInt8] = [0xfd,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x0f] /* (p-5)/8 */
    let p:fe = fe()
    var d:fe = fe()
    fe25519_pow(&d,x,e)
    fe.freeze(&d)
    if(fe.isone(d)){
        fe25519_pow(&r,x,e2)
    }
    else
    {
        for i in 0..<32 {
            d.v[i] = 4*x.v[i]
        }
        fe25519_pow(&d, d, e3)
        for i in 0..<32 {
            r.v[i] = 2*x.v[i]
        }
        fe25519_mul(&r,r,d)
    }
    fe.freeze(&r)
    if(UInt8(r.v[0] & 1) != (parity & 1))
    {
        fe25519_sub(&r,p,r)
    }
    return true
}

 func fe25519_invert(_ r:inout fe, _ x:fe)
{
    var z2 = fe()
    var z9 = fe()
    var z11 = fe()
    var z2_5_0 = fe()
    var z2_10_0 = fe()
    var z2_20_0 = fe()
    var z2_50_0 = fe()
    var z2_100_0 = fe()
    var t0 = fe()
    var t1 = fe()
    
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
