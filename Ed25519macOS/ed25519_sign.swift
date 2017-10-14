//
//  sign.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/21.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation

/**
 * ed25519 fast calculation implementation
 * ported from SUPERCOP https://bench.cr.yp.to/supercop.html
 */
public struct ed25519 {
    
    static func crypto_hash_sha512(_ r:inout [UInt8], _ k:[UInt8], len:Int)
    {
        r = sha512(Array(k[0..<len]))
    }

    private static func randombytes(_ r:inout [UInt8], len:Int)
    {
        r = [UInt8](repeating:0, count:len)
        let result = SecRandomCopyBytes(kSecRandomDefault, len, &r)
        assert(result == 0)
    }

    private static func crypto_verify_32(_ x:[UInt8], _ y:[UInt8]) -> Bool
    {
        if x.count != 32 || y.count != 32 {
            return false
        }
        for i in 0..<32 {
            if x[i] != y[i] {
                return false
            }
        }
        return true
    }

    // pk: 32bytes, sk: 32bytes
    public static func crypto_sign_keypair() -> (pk:[UInt8], sk:[UInt8])
    {
        var scsk = sc()
        var gepk = ge()
        var pk:[UInt8] = [UInt8](repeating:0, count:32)
        var sk:[UInt8] = [UInt8](repeating:0, count:32)
        
        // create secret key 32byte
        randombytes(&sk, len:32)

        // sha512 of sk
        crypto_hash_sha512(&sk, sk, len:32)

        // calc public key
        sk[0] &= 248 // clear lowest 3bit
        sk[31] &= 127 // clear highest bit
        sk[31] |= 64 // set bit
        sc.sc25519_from32bytes(&scsk,sk)
        // gepk = a * G
        ge.ge25519_scalarmult_base(&gepk, scsk)
        //
        ge.ge25519_pack(&pk, gepk)
        
        return (pk, sk)
    }

    // signing
    // sm: 64 bytes + message length
    // m: message
    // return : R + m + S
    public static func crypto_sign(_ sm:inout [UInt8], _ m:[UInt8], _ skpk:[UInt8]) -> UInt8
    {
        assert(skpk.count == 64)
        let mlen:Int = m.count
        let _ = sm.count
        var pk = [UInt8](repeating:0, count:32)
        var az = [UInt8](repeating:0, count:64)
        var nonce = [UInt8](repeating:0, count:64)
        var hram = [UInt8](repeating:0, count:64)
        var sck = sc()
        var scs = sc()
        var scsk = sc()
        var ger = ge()
        for i in 0..<32 {
            pk[i] = skpk[32+i]
        }
        /* pk: 32-byte public key A */
        
        crypto_hash_sha512(&az, skpk, len: 32)
        az[0] &= 248
        az[31] &= 127
        az[31] |= 64
        
        sm = [UInt8](repeating:0, count:mlen+64)
        for i in 0..<mlen {
            sm[64+i] = m[i]
        }
        for i in 0..<32 {
            sm[32+i] = az[32+i]
        }
        
        /* az: 32-byte scalar a, 32-byte rendomizer z */
        let data:[UInt8] = Array(sm[32..<(mlen+64)])
        crypto_hash_sha512(&nonce, data, len:mlen+32)
        /* nonce: 64-byte H(z,m) */
        // sck = r
        sc.sc25519_from64bytes(&sck, nonce)
        // r * B
        ge.ge25519_scalarmult_base(&ger, sck)
        
        // R
        ge.ge25519_pack(&sm, ger)
        
        // set pk
        for i in 0..<32 {
            sm[i+32] = pk[i]
        }
        // k
        crypto_hash_sha512(&hram, sm, len: mlen+64)
        // scs = k
        sc.sc25519_from64bytes(&scs, hram)
        // scsk = s
        sc.sc25519_from32bytes(&scsk, az)
        // scs = k * s
        sc.sc25519_mul(&scs, scs, scsk)
        // add, modulo L
        sc.sc25519_add(&scs, scs, sck)
        
        // S
        var a:[UInt8] = [UInt8](repeating:0, count:32)
        sc.sc25519_to32bytes(&a, scs) /* cat s */
        // set S
        for i in 0..<32 {
            sm[32+i] = a[i]
        }
        return 0
    }
}
