//
//  ge25519.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/20.
//  Copyright © 2017年 pebble8888. All rights reserved.
//
//  Code is ported from NaCl (http://nacl.cr.yp.to/)
//

import Foundation

public struct ge :CustomStringConvertible {
    var x:fe
    var y:fe
    var z:fe
    var t:fe
    public var description:String {
        return
        "x:\(x)\n" +
        "y:\(y)\n" +
        "z:\(z)\n" +
        "t:\(t)\n"
    }
    
    init(){
        x = fe() // zero
        y = fe() // zero
        z = fe() // zero
        t = fe() // zero
    }
    init(_ x:fe, _ y:fe, _ z:fe, _ t:fe){
        self.x = x
        self.y = y
        self.z = z
        self.t = t
    }

    var toP2:P2 {
        return P2(self.x, self.y, self.z)
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
    
    /* d */
    static let ecd:fe = fe([0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00,
    0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52])
    /* 2*d */
    static let ec2d:fe = fe([0x59, 0xF1, 0xB2, 0x26, 0x94, 0x9B, 0xD6, 0xEB, 0x56, 0xB1, 0x83, 0x82, 0x9A, 0x14, 0xE0, 0x00,
    0x30, 0xD1, 0xF3, 0xEE, 0xF2, 0x80, 0x8E, 0x19, 0xE7, 0xFC, 0xDF, 0x56, 0xDC, 0xD9, 0x06, 0x24])
    /* sqrt(-1) */
    static let sqrtm1:fe = fe([0xB0, 0xA0, 0x0E, 0x4A, 0x27, 0x1B, 0xEE, 0xC4, 0x78, 0xE4, 0x2F, 0xAD, 0x06, 0x18, 0x43, 0x2F,
    0xA7, 0xD7, 0xFB, 0x3D, 0x99, 0x00, 0x4D, 0x2B, 0x0B, 0xDF, 0xC1, 0x4F, 0x80, 0x24, 0x83, 0x2B])

    struct P1P1 {
        var x:fe
        var y:fe
        var z:fe
        var t:fe
        init(){
            x = fe()
            y = fe()
            z = fe()
            t = fe()
        }
    } 
    
    struct P2 {
        var x:fe
        var y:fe
        var z:fe
        init(){
            x = fe()
            y = fe()
            z = fe()
        }
        init(_ x:fe, _ y:fe, _ z:fe){
            self.x = x
            self.y = y
            self.z = z
        }
    }
    
    public struct aff
    {
        var x:fe
        var y:fe
        init(){
            x = fe()
            y = fe()
        }
        init(_ x:fe, _ y:fe){
            self.x = x
            self.y = y
        }
    }
    
    /* Packed coordinates of the base point */
    static let ge25519_base:ge = ge(
    fe([0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9, 0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
        0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0, 0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21]),
    fe([0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66]),
    fe([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    fe([0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D, 0xF5, 0x52, 0x51, 0x77, 0x80, 0x9F, 0xF0, 0x20,
        0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66, 0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67]))
    

    static func p1p1_to_p2(_ r:inout P2, _ p:P1P1)
    {
        fe.fe25519_mul(&r.x, p.x, p.t)
        fe.fe25519_mul(&r.y, p.y, p.z)
        fe.fe25519_mul(&r.z, p.z, p.t)
    }
    
    static func p1p1_to_p3(_ r:inout ge, _ p:P1P1)
    {
        var p2 = P2()
        p1p1_to_p2(&p2, p)
        r.setFromP2(p2)
        fe.fe25519_mul(&r.t, p.x, p.y)
    }
    
    static func ge25519_mixadd2(_ r: inout ge, _ q:aff)
    {
        var a = fe()
        var b = fe()
        var t1 = fe()
        var t2 = fe()
        var c = fe()
        var d = fe()
        var e = fe()
        var f = fe()
        var g = fe()
        var h = fe()
        var qt = fe()
        fe.fe25519_mul(&qt, q.x, q.y);
        fe.fe25519_sub(&a, r.y, r.x); /* A = (Y1-X1)*(Y2-X2) */
        fe.fe25519_add(&b, r.y, r.x); /* B = (Y1+X1)*(Y2+X2) */
        fe.fe25519_sub(&t1, q.y, q.x);
        fe.fe25519_add(&t2, q.y, q.x);
        fe.fe25519_mul(&a, a, t1);
        fe.fe25519_mul(&b, b, t2);
        fe.fe25519_sub(&e, b, a); /* E = B-A */
        fe.fe25519_add(&h, b, a); /* H = B+A */
        fe.fe25519_mul(&c, r.t, qt); /* C = T1*k*T2 */
        fe.fe25519_mul(&c, c, ge.ec2d);
        fe.fe25519_add(&d, r.z, r.z); /* D = Z1*2 */
        fe.fe25519_sub(&f, d, c); /* F = D-C */
        fe.fe25519_add(&g, d, c); /* G = D+C */
        fe.fe25519_mul(&r.x, e, f);
        fe.fe25519_mul(&r.y, h, g);
        fe.fe25519_mul(&r.z, g, f);
        fe.fe25519_mul(&r.t, e, h);
    }

    static func add_p1p1(_ r: inout ge.P1P1, _ p:ge, _ q:ge)
    {
        var a = fe()
        var b = fe()
        var c = fe()
        var d = fe()
        var t = fe()
    
        fe.fe25519_sub(&a, p.y, p.x); /* A = (Y1-X1)*(Y2-X2) */
        fe.fe25519_sub(&t, q.y, q.x);
        fe.fe25519_mul(&a, a, t);
        fe.fe25519_add(&b, p.x, p.y); /* B = (Y1+X1)*(Y2+X2) */
        fe.fe25519_add(&t, q.x, q.y);
        fe.fe25519_mul(&b, b, t);
        fe.fe25519_mul(&c, p.t, q.t); /* C = T1*k*T2 */
        fe.fe25519_mul(&c, c, ge.ec2d);
        fe.fe25519_mul(&d, p.z, q.z); /* D = Z1*2*Z2 */
        fe.fe25519_add(&d, d, d);
        fe.fe25519_sub(&r.x, b, a); /* E = B-A */
        fe.fe25519_sub(&r.t, d, c); /* F = D-C */
        fe.fe25519_add(&r.z, d, c); /* G = D+C */
        fe.fe25519_add(&r.y, b, a); /* H = B+A */
    }
    
    static func dbl_p1p1(_ r:inout P1P1, _ p:P2)
    {
        var a = fe()
        var b = fe()
        var c = fe()
        var d = fe()
        fe.fe25519_square(&a, p.x)
        fe.fe25519_square(&b, p.y)
        fe.fe25519_square(&c, p.z)
        fe.fe25519_add(&c, c, c)
        fe.fe25519_neg(&d, a)
        
        fe.fe25519_add(&r.x, p.x, p.y)
        fe.fe25519_square(&r.x, r.x)
        fe.fe25519_sub(&r.x, r.x, a)
        fe.fe25519_sub(&r.x, r.x, b)
        fe.fe25519_add(&r.z, d, b)
        fe.fe25519_sub(&r.t, r.z, c)
        fe.fe25519_sub(&r.y, d, b)
    }
    
    /* Constant-time version of: if(b) r = p */
    static func cmov_aff(_ r:inout aff, _ p:aff, _ b:UInt8)
    {
        fe.fe25519_cmov(&r.x, p.x, b);
        fe.fe25519_cmov(&r.y, p.y, b);
    }
    
    static func equal(_ b:Int8, _ c:Int8) -> UInt8
    {
        return b == c ? 1 : 0
    }
    
    static func negative(_ b:Int8) -> UInt8
    {
        return b < 0 ? 1 : 0
    }
    
    static func choose_t(_ t:inout aff, _ pos:Int, _ b:Int8)
    {
        /* constant time */
        var v = fe();
        t = ge25519_base_multiples_affine[5*pos+0];
        cmov_aff(&t, ge25519_base_multiples_affine[5*pos+1],equal(b,1) | equal(b,-1));
        cmov_aff(&t, ge25519_base_multiples_affine[5*pos+2],equal(b,2) | equal(b,-2));
        cmov_aff(&t, ge25519_base_multiples_affine[5*pos+3],equal(b,3) | equal(b,-3));
        cmov_aff(&t, ge25519_base_multiples_affine[5*pos+4],equal(b,-4));
        fe.fe25519_neg(&v, t.x);
        fe.fe25519_cmov(&t.x, v, negative(b));
    }
    
    static func setneutral(_ r:inout ge)
    {
        fe.fe25519_setzero(&r.x);
        fe.fe25519_setone(&r.y);
        fe.fe25519_setone(&r.z);
        fe.fe25519_setzero(&r.t);
    }

    
    /* ********************************************************************
     *                    EXPORTED FUNCTIONS
     ******************************************************************** */

    /* return 0 on success, -1 otherwise */
    static func ge25519_unpackneg_vartime(_ r:inout ge, _ p:[UInt8] /* 32 */) -> Int32
    {
        var par:UInt8;
        var t = fe()
        var chk = fe()
        var num = fe()
        var den = fe()
        var den2 = fe()
        var den4 = fe()
        var den6 = fe()
        fe.fe25519_setone(&r.z);
        par = p[31] >> 7;
        fe.fe25519_unpack(&r.y, p);
        fe.fe25519_square(&num, r.y); /* x = y^2 */
        fe.fe25519_mul(&den, num, ge.ecd); /* den = dy^2 */
        fe.fe25519_sub(&num, num, r.z); /* x = y^2-1 */
        fe.fe25519_add(&den, r.z, den); /* den = dy^2+1 */
        
        /* Computation of sqrt(num/den) */
        /* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
        fe.fe25519_square(&den2, den);
        fe.fe25519_square(&den4, den2);
        fe.fe25519_mul(&den6, den4, den2);
        fe.fe25519_mul(&t, den6, num);
        fe.fe25519_mul(&t, t, den);
        
        fe.fe25519_pow2523(&t, t);
        /* 2. computation of r->x = t * num * den^3 */
        fe.fe25519_mul(&t, t, num);
        fe.fe25519_mul(&t, t, den);
        fe.fe25519_mul(&t, t, den);
        fe.fe25519_mul(&r.x, t, den);
        
        /* 3. Check whether sqrt computation gave correct result, multiply by sqrt(-1) if not: */
        fe.fe25519_square(&chk, r.x);
        fe.fe25519_mul(&chk, chk, den);
        if (!fe.fe25519_iseq_vartime(chk, num)){
            fe.fe25519_mul(&r.x, r.x, ge.sqrtm1);
        }
        /* 4. Now we have one of the two square roots, except if input was not a square */
        fe.fe25519_square(&chk, r.x);
        fe.fe25519_mul(&chk, chk, den);
        if (!fe.fe25519_iseq_vartime(chk, num)){
            return -1;
        }
        
        /* 5. Choose the desired square root according to parity: */
        if(fe.fe25519_getparity(r.x) != (1-par)){
            fe.fe25519_neg(&r.x, r.x);
        }
        
        fe.fe25519_mul(&r.t, r.x, r.y);
        return 0;
    }

    static func ge25519_pack(_ r:inout [UInt8] /* 32 */, _ p:ge)
    {
        var tx = fe()
        var ty = fe()
        var zi = fe()
        fe.fe25519_invert(&zi, p.z);
        fe.fe25519_mul(&tx, p.x, zi);
        fe.fe25519_mul(&ty, p.y, zi);
        fe.fe25519_pack(&r, ty);
        r[31] ^= fe.fe25519_getparity(tx) << 7;
    }

    static func ge25519_isneutral_vartime(_ p:ge) -> Int32
    {
        var ret:Int32 = 1
        if(!fe.fe25519_iszero(p.x)) { ret = 0; }
        if(!fe.fe25519_iseq_vartime(p.y, p.z)) { ret = 0; }
        return ret;
    }

    /* computes [s1]p1 + [s2]p2 */
    static func ge25519_double_scalarmult_vartime(_ r:inout ge, _ p1:ge, _ s1:sc, _ p2:ge, _ s2:sc)
    {
        var tp1p1 = ge.P1P1();
        var pre:[ge] = [ge](repeating:ge(), count:16)
        var b:[UInt8] = [UInt8](repeating:0, count:127)
        
        /* precomputation                                                        s2 s1 */
        ge.setneutral(&pre[0]);                                                      /* 00 00 */
        pre[1] = p1;                                                         /* 00 01 */
        ge.dbl_p1p1(&tp1p1,p1.toP2);             ge.p1p1_to_p3( &pre[2], tp1p1); /* 00 10 */
        ge.add_p1p1(&tp1p1,pre[1], pre[2]);      ge.p1p1_to_p3( &pre[3], tp1p1); /* 00 11 */
        pre[4] = p2;                                                         /* 01 00 */
        ge.add_p1p1(&tp1p1,pre[1], pre[4]);      ge.p1p1_to_p3( &pre[5], tp1p1); /* 01 01 */
        ge.add_p1p1(&tp1p1,pre[2], pre[4]);      ge.p1p1_to_p3( &pre[6], tp1p1); /* 01 10 */
        ge.add_p1p1(&tp1p1,pre[3], pre[4]);      ge.p1p1_to_p3( &pre[7], tp1p1); /* 01 11 */
        ge.dbl_p1p1(&tp1p1,p2.toP2);             ge.p1p1_to_p3( &pre[8], tp1p1); /* 10 00 */
        ge.add_p1p1(&tp1p1,pre[1], pre[8]);      ge.p1p1_to_p3( &pre[9], tp1p1); /* 10 01 */
        ge.dbl_p1p1(&tp1p1,pre[5].toP2);         ge.p1p1_to_p3(&pre[10], tp1p1); /* 10 10 */
        ge.add_p1p1(&tp1p1,pre[3], pre[8]);      ge.p1p1_to_p3(&pre[11], tp1p1); /* 10 11 */
        ge.add_p1p1(&tp1p1,pre[4], pre[8]);      ge.p1p1_to_p3(&pre[12], tp1p1); /* 11 00 */
        ge.add_p1p1(&tp1p1,pre[1],pre[12]);      ge.p1p1_to_p3(&pre[13], tp1p1); /* 11 01 */
        ge.add_p1p1(&tp1p1,pre[2],pre[12]);      ge.p1p1_to_p3(&pre[14], tp1p1); /* 11 10 */
        ge.add_p1p1(&tp1p1,pre[3],pre[12]);      ge.p1p1_to_p3(&pre[15], tp1p1); /* 11 11 */
        
        sc.sc25519_2interleave2(&b,s1,s2);
        
        /* scalar multiplication */
        r = pre[Int(b[126])];
        for i in stride(from:125, through:0, by: -1)
        {
            ge.dbl_p1p1(&tp1p1, r.toP2);
            var t = ge.P2()
            ge.p1p1_to_p2(&t, tp1p1);
            r.setFromP2(t)
            
            ge.dbl_p1p1(&tp1p1, r.toP2);
            if(b[i] != 0)
            {
                ge.p1p1_to_p3(&r, tp1p1);
                ge.add_p1p1(&tp1p1, r, pre[Int(b[i])])
            }
            if(i != 0) {
                var t = ge.P2()
                ge.p1p1_to_p2(&t, tp1p1);
                r.setFromP2(t)
            }
            else {
                ge.p1p1_to_p3(&r, tp1p1);
            }
        }
    }

    static func ge25519_scalarmult_base(_ r:inout ge, _ s:sc)
    {
        var b = [Int8](repeating:0, count:85)
        var t = ge.aff();
        sc.sc25519_window3(&b, s);
        
        var tmpaff = ge.aff()
        ge.choose_t(&tmpaff, 0, b[0])
        r.x = tmpaff.x
        r.y = tmpaff.y

        fe.fe25519_setone(&r.z);
        fe.fe25519_mul(&r.t, r.x, r.y);
        for i in 1..<85
        {
            ge.choose_t(&t, i, b[i]);
            ge.ge25519_mixadd2(&r, t);
        }
    }
}

