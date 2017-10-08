//
//  ge25519.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/20.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation

struct ge25519 {
    var x:fe25519
    var y:fe25519
    var z:fe25519
    var t:fe25519
    init(){
        x = fe25519()
        y = fe25519()
        z = fe25519()
        t = fe25519()
    }

    var toP2:P2 {
        return P2(x:self.x, y:self.y, z:self.z)
    }
    
    mutating func setFromP2(_ p2:P2){
        x = p2.x
        y = p2.y
        z = p2.z
    }
   
    /* 
     * Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2 
     * with d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
     * Base point: (15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960)
     */
    
    struct P1P2 {
        var x:fe25519
        var y:fe25519
        var z:fe25519
        var t:fe25519
        init(){
            x = fe25519()
            y = fe25519()
            z = fe25519()
            t = fe25519()
        }
    } 
    
    struct P2 {
        var x:fe25519
        var y:fe25519
        var z:fe25519
        init(){
            x = fe25519()
            y = fe25519()
            z = fe25519()
        }
        init(x:fe25519, y:fe25519, z:fe25519){
            self.x = x
            self.y = y
            self.z = z
        }
    }
    
    
    /* Windowsize for fixed-window scalar multiplication */
    static let WINDOWSIZE:Int = 2                      /* Should be 1,2, or 4 */
    static let WINDOWMASK:Int = ((1<<WINDOWSIZE)-1)
    
    /* packed parameter d in the Edwards curve equation */
    static let ecd:[UInt8] = [0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00, 
    0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52]
    
    /* Packed coordinates of the base point */
    static let base_x:[UInt8] = [0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9, 0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69, 
    0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0, 0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21]
    static let base_y:[UInt8] = [0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66]
    static let base_z:[UInt8] = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    static let base_t:[UInt8] = [0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D, 0xF5, 0x52, 0x51, 0x77, 0x80, 0x9F, 0xF0, 0x20, 
    0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66, 0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67]
    
    /* Packed coordinates of the neutral element */
    static let neutral_x:[UInt8] = [UInt8](repeating:0, count:32)
    static let neutral_y:[UInt8] = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    static let neutral_z:[UInt8] = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    static let neutral_t:[UInt8] = [UInt8](repeating:0, count:32)
    
    static func p1p1_to_p2(_ r:inout P2, _ p:P1P2)
    {
        fe25519_mul(&r.x, p.x, p.t)
        fe25519_mul(&r.y, p.y, p.z)
        fe25519_mul(&r.z, p.z, p.t)
    }
    
    static func p1p1_to_p3(_ r:inout ge25519, _ p:P1P2)
    {
        var p2 = P2()
        p1p1_to_p2(&p2, p)
        r.setFromP2(p2)
        fe25519_mul(&r.t, p.x, p.y)
    }
    
    /* Constant-time version of: if(b) r = p */
    static func cmov_p3(_ r:inout ge25519, _ p: ge25519, _ b:UInt8)
    {
        fe25519_cmov(&r.x, p.x, b)
        fe25519_cmov(&r.y, p.y, b)
        fe25519_cmov(&r.z, p.z, b)
        fe25519_cmov(&r.t, p.t, b)
    }
    
    /* See http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd */
    static func dbl_p1p1(_ r:inout P1P2, _ p:P2)
    {
        var a = fe25519()
        var b = fe25519()
        var c = fe25519()
        var d = fe25519()
        fe25519_square(&a, p.x)
        fe25519_square(&b, p.y)
        fe25519_square(&c, p.z)
        fe25519_add(&c, c, c)
        fe25519_neg(&d, a)
        
        fe25519_add(&r.x, p.x, p.y)
        fe25519_square(&r.x, r.x)
        fe25519_sub(&r.x, r.x, a)
        fe25519_sub(&r.x, r.x, b)
        fe25519_add(&r.z, d, b)
        fe25519_sub(&r.t, r.z, c)
        fe25519_sub(&r.y, d, b)
    }
    
    static func add_p1p1(_ r:inout P1P2, _ p:ge25519, _ q:ge25519)
    {
        var a = fe25519()
        var b = fe25519()
        var c = fe25519()
        var d = fe25519()
        var t = fe25519()
        var fd = fe25519()
        fe25519_unpack(&fd, ecd)
        
        fe25519_sub(&a, p.y, p.x) // A = (Y1-X1)*(Y2-X2)
        fe25519_sub(&t, q.y, q.x)
        fe25519_mul(&a, a, t)
        fe25519_add(&b, p.x, p.y) // B = (Y1+X1)*(Y2+X2)
        fe25519_add(&t, q.x, q.y)
        fe25519_mul(&b, b, t)
        fe25519_mul(&c, p.t, q.t) //C = T1*k*T2
        fe25519_mul(&c, c, fd)
        fe25519_add(&c, c, c)       //XXX: Can save this addition by precomputing 2*ecd
        fe25519_mul(&d, p.z, q.z) //D = Z1*2*Z2
        fe25519_add(&d, d, d)
        fe25519_sub(&r.x, b, a) // E = B-A
        fe25519_sub(&r.t, d, c) // F = D-C
        fe25519_add(&r.z, d, c) // G = D+C
        fe25519_add(&r.y, b, a) // H = B+A
    }
}
    
/* ********************************************************************
 *                    EXPORTED FUNCTIONS
 ******************************************************************** */

func ge25519_unpack_vartime(_ r:inout ge25519, _ p:[UInt8] /* 32 */) -> Bool
{
    var ret:Bool
    var t = fe25519()
    var fd = fe25519()
    fe25519_setone(&r.z)
    fe25519_unpack(&fd, ge25519.ecd)
    let par:UInt8 = p[31] >> 7
    fe25519_unpack(&r.y, p)
    fe25519_square(&r.x, r.y)
    fe25519_mul(&t, r.x, fd)
    fe25519_sub(&r.x, r.x, r.z)
    fe25519_add(&t, r.z, t)
    fe25519_invert(&t, t)
    fe25519_mul(&r.x, r.x, t)
    ret = fe25519_sqrt_vartime(&r.x, r.x, par)
    fe25519_mul(&r.t, r.x, r.y)
    return ret
}

func ge25519_pack(_ r:inout [UInt8] /* 32 */, _ p:ge25519)
{
    var tx = fe25519()
    var ty = fe25519()
    var zi = fe25519()
    fe25519_invert(&zi, p.z) 
    fe25519_mul(&tx, p.x, zi)
    fe25519_mul(&ty, p.y, zi)
    fe25519_pack(&r, ty)
    r[31] ^= fe25519_getparity(tx) << 7
}

func ge25519_add(_ r:inout ge25519, _ p:ge25519, _ q:ge25519)
{
    var grp1p1 = ge25519.P1P2()
    ge25519.add_p1p1(&grp1p1, p, q)
    ge25519.p1p1_to_p3(&r, grp1p1)
}

 func ge25519_double(_ r:inout ge25519, _ p:ge25519)
{
    var grp1p1 = ge25519.P1P2()
    ge25519.dbl_p1p1(&grp1p1, p.toP2)
    ge25519.p1p1_to_p3(&r, grp1p1)
}

 func ge25519_scalarmult(_ r:inout ge25519, _ p:ge25519, _ s:sc25519)
{
    var g = ge25519()
    fe25519_unpack(&g.x, ge25519.neutral_x)
    fe25519_unpack(&g.y, ge25519.neutral_y)
    fe25519_unpack(&g.z, ge25519.neutral_z)
    fe25519_unpack(&g.t, ge25519.neutral_t)
    
    var pre:[ge25519] = [ge25519](repeating:ge25519(), count:(1 << ge25519.WINDOWSIZE))
    var t:ge25519
    var tp1p1 = ge25519.P1P2()
    var w:UInt8
    var sb:[UInt8] = [UInt8](repeating:0, count:32)
    sc25519_to32bytes(&sb, s)
    
    // Precomputation
    pre[0] = g
    pre[1] = p
    for i in stride(from:2, to:1<<ge25519.WINDOWSIZE, by:2)
    {
        ge25519.dbl_p1p1(&tp1p1, pre[i/2].toP2)
        ge25519.p1p1_to_p3(&pre[i], tp1p1)
        ge25519.add_p1p1(&tp1p1, pre[i], pre[1])
        ge25519.p1p1_to_p3(&pre[i+1], tp1p1)
    }
    
    // Fixed-window scalar multiplication
    for i in stride(from:32, to:0, by: -1)
    {
        for j in stride(from:8-ge25519.WINDOWSIZE, through:0, by:-ge25519.WINDOWSIZE)
        {
            for _ in 0..<ge25519.WINDOWSIZE-1
            {
                ge25519.dbl_p1p1(&tp1p1, g.toP2)
                var tt = ge25519.P2()
                ge25519.p1p1_to_p2(&tt, tp1p1)
                g.setFromP2(tt)
            }
            ge25519.dbl_p1p1(&tp1p1, g.toP2)
            ge25519.p1p1_to_p3(&g, tp1p1)
            // Cache-timing resistant loading of precomputed value:
            w = (sb[i-1]>>UInt8(j)) & UInt8(ge25519.WINDOWMASK)
            t = pre[0]
            for k in 1..<(1<<ge25519.WINDOWSIZE) {
                ge25519.cmov_p3(&t, pre[k], UInt8(k)==w ? 1 : 0)
            }
        
            ge25519.add_p1p1(&tp1p1, g, t)
            if j != 0 {
                var tt = ge25519.P2()
                ge25519.p1p1_to_p2(&tt, tp1p1)
                g.setFromP2(tt)
            }
            else {
                ge25519.p1p1_to_p3(&g, tp1p1) /* convert to p3 representation at the end */
            }
        }
    }
    r.x = g.x
    r.y = g.y
    r.z = g.z
    r.t = g.t
}

 func ge25519_scalarmult_base(_ r:inout ge25519, _ s:sc25519)
{
    /* XXX: Better algorithm for known-base-point scalar multiplication */
    var t = ge25519()
    fe25519_unpack(&t.x, ge25519.base_x)
    fe25519_unpack(&t.y, ge25519.base_y)
    fe25519_unpack(&t.z, ge25519.base_z)
    fe25519_unpack(&t.t, ge25519.base_t)
    ge25519_scalarmult(&r, t, s)          
}
