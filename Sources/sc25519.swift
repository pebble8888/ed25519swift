//
//  sc25519.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/21.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation

struct sc25519 {
    var v:[UInt32]
    init(){
        v = [UInt32](repeating:0, count:32)
    }
    
    /*Arithmetic modulo the group order n = 2^252 +  27742317777372353535851937790883648493 = 7237005577332262213973186563042994240857116359379907606001950938285454250989 */
    
    static let m:[UInt32] = [0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]
    
    static let mu:[UInt32] = [0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED, 0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21, 
    0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]
    
    /* Reduce coefficients of r before calling reduce_add_sub */
    static func reduce_add_sub(_ r:inout sc25519)
    {
        var b:Int = 0
        var pb:Int = 0
        var nb:Int
        var t:[UInt8] = [UInt8](repeating:0, count:32)
        
        for i in 0..<32 
        {
            b = (r.v[i] < UInt32(pb) + m[i]) ? 1 : 0
            let vv:Int32 = Int32(r.v[i]) - Int32(pb) - Int32(m[i]) + Int32(b) * 256
            t[i] =  UInt8(vv)
            pb = b
        }
        nb = 1-b
        for i in 0..<32 {
            r.v[i] = r.v[i]*UInt32(b) + UInt32(t[i])*UInt32(nb)
        }
    }
    
    /* Reduce coefficients of x before calling barrett_reduce */
    static func barrett_reduce(_ r:inout sc25519, _ x:[UInt32] /* 64 */)
    {
        /* See HAC, Alg. 14.42 */
        var q2:[UInt32] = [UInt32](repeating:0, count:66)
        var r1:[UInt32] = [UInt32](repeating:0, count:33)
        var r2:[UInt32] = [UInt32](repeating:0, count:33)
        var carry:UInt32
        var b:UInt32
        var pb:UInt32 = 0
        
        for i in 0..<33 {
            for j in 0..<33 {
                if i+j >= 31 {
                    q2[i+j] += mu[i]*x[j+31];
                }
            }
        }
        carry = q2[31] >> 8;
        q2[32] += carry;
        carry = q2[32] >> 8;
        q2[33] += carry;
        
        for i in 0..<33 { r1[i] = x[i] }
        for i in 0..<32 {
            for j in 0..<33 {
                if i+j < 33 {
                    r2[i+j] += m[i]*q2[33+j]
                }
            }
        }
        
        for i in 0..<32 {
            carry = r2[i] >> 8;
            r2[i+1] += carry;
            r2[i] &= 0xff;
        }
        
        for i in 0..<32 {
            b = (r1[i] < pb + r2[i]) ? 1 : 0
            let vv:Int32 = Int32(r1[i]) - Int32(pb) - Int32(r2[i]) + Int32(b*256)
            r.v[i] = UInt32(vv) 
            pb = b;
        }
        
        /* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3 
         * If so: Handle  it here!
         */
        
        reduce_add_sub(&r);
        reduce_add_sub(&r);
    }
}
    
func sc25519_from32bytes(_ r:inout sc25519, _ x:[UInt8] /* 32 */)
{
    var t:[UInt32] = [UInt32](repeating:0, count:64)
    for i in 0..<32 {
        t[i] = UInt32(x[i])
    }
    sc25519.barrett_reduce(&r, t)
}

 func sc25519_from64bytes(_ r:inout sc25519, _ x:[UInt8] /* 64 */)
{
    var t:[UInt32] = [UInt32](repeating:0, count:64)
    for i in 0..<64 {
        t[i] = UInt32(x[i])
    }
    sc25519.barrett_reduce(&r, t)
}

/* XXX: What we actually want for crypto_group is probably just something like
 * void sc25519_frombytes(sc25519 *r, const unsigned char *x, size_t xlen)
 */

 func sc25519_to32bytes(_ r:inout [UInt8] /* 32 */, _ x:sc25519)
{
    for i in 0..<32 {
        r[i] = UInt8(x.v[i])
    }
}

 func sc25519_add(_ r:inout sc25519, _ x:sc25519, _ y:sc25519)
{
    var carry:UInt32
    for i in 0..<32 {
        r.v[i] = x.v[i] + y.v[i];
    }
    for i in 0..<31 {
        carry = r.v[i] >> 8
        r.v[i+1] += carry
        r.v[i] &= 0xff
    }
    sc25519.reduce_add_sub(&r)
}

 func sc25519_mul(_ r:inout sc25519, _ x:sc25519, _ y:sc25519)
{
    var carry:UInt32
    var t:[UInt32] = [UInt32](repeating:0, count:64)
    for i in 0..<64 { 
        t[i] = 0;
    }
    
    for i in 0..<32 {
        for j in 0..<32 {
            t[i+j] += x.v[i] * y.v[j];
        }
    }
    
    /* Reduce coefficients */
    for i in 0..<63 {
        carry = t[i] >> 8
        t[i+1] += carry
        t[i] &= 0xff
    }
    
    sc25519.barrett_reduce(&r, t)
}

func sc25519_square(_ r:inout sc25519, _ x:sc25519)
{
    sc25519_mul(&r, x, x);
} 
