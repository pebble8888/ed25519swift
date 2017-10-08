//
//  sign.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/21.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation

let CRYPTO_SECRETKEYBYTES = 64
let CRYPTO_PUBLICKEYBYTES = 32
let CRYPTO_BYTES = 64
let crypto_hash_sha512_BYTES = 64

func crypto_hash_sha512(_ r:inout [UInt8], _ k:[UInt8], _ len:Int)
{
    r = sha512(Array(k[0..<len])).digest()
}

func randombytes(_ r:inout [UInt8], _ len:Int)
{
    r = [UInt8](repeating:0, count:len)
    let result = SecRandomCopyBytes(kSecRandomDefault, len, &r)
    assert(result == 0)
}

func crypto_verify_32(_ x:[UInt8], _ y:[UInt8]) -> Bool
{
    /*
    if x.count != 32 || y.count != 32 {
        return false
    }
    for i in 0..<32 {
        if x[i] != y[i] {
            return false
        }
    }
    return true
    */
    var differentbits:UInt8 = 0
    for i in 0..<32 {
        differentbits |= x[i] ^ y[i]
    }
    let a:Int32 = (1 & ((Int32(differentbits) - 1) >> 8)) - 1
    return a == 0
}

// -----------

public func crypto_sign_keypair() -> (pk:[UInt8], sk:[UInt8])
{
    var scsk = sc25519()
    var gepk = ge25519()
    var pk:[UInt8] = [UInt8](repeating:0, count:32)
    var sk:[UInt8] = [UInt8](repeating:0, count:32)
    
    randombytes(&sk, 32)
    crypto_hash_sha512(&sk, sk, 32)
    sk[0] &= 248
    sk[31] &= 127
    sk[31] |= 64
    
    sc25519_from32bytes(&scsk,sk)
    
    ge25519_scalarmult_base(&gepk, scsk)
   
    ge25519_pack(&pk, gepk)
    
    return (pk, sk)
}

// crypt
// +64
public func crypto_sign(_ m:[UInt8], _ sk:[UInt8]) -> [UInt8]
{
    let mlen:Int = m.count
    let smlen = mlen+64
    var sm:[UInt8] = [UInt8](repeating:0, count: smlen)
    var sck = sc25519()
    var scs = sc25519()
    var scsk = sc25519()
    var ger = ge25519()
    var r:[UInt8] = [UInt8](repeating: 0, count:32)
    var s:[UInt8] = [UInt8](repeating: 0, count:32)
    var hmg:[UInt8] = [UInt8](repeating: 0, count: crypto_hash_sha512_BYTES)
    var hmr:[UInt8] = [UInt8](repeating: 0, count: crypto_hash_sha512_BYTES)
    
    for i in 0..<mlen {
        sm[32 + i] = m[i]
    }
    for i in 0..<32 {
        sm[i] = sk[32+i]
    }
    crypto_hash_sha512(&hmg, sm, mlen+32) /* Generate k as h(m,sk[32],...,sk[63]) */
    
    sc25519_from64bytes(&sck, hmg)
    ge25519_scalarmult_base(&ger, sck)
    ge25519_pack(&r, ger)
    
    for i in 0..<32 {
        sm[i] = r[i]
    }
    
    crypto_hash_sha512(&hmr, sm, mlen+32) /* Compute h(m,r) */
    sc25519_from64bytes(&scs, hmr)
    sc25519_mul(&scs, scs, sck)
    
    sc25519_from32bytes(&scsk, sk)
    sc25519_add(&scs, scs, scsk)
    
    sc25519_to32bytes(&s,scs) /* cat s */
    for i in 0..<32 {
        sm[mlen+32+i] = s[i] 
    }
    return sm
}

public enum DecryptError : Swift.Error {
    case general
}

// decrypt
// -64
public func crypto_sign_open(_ sm:[UInt8], _ pk:[UInt8]) throws -> [UInt8] {
    let smlen = sm.count
    var m:[UInt8] = [UInt8](repeating:0, count: smlen - 64)
    //var t1:[UInt8] = [UInt8](repeating:0, count:32)
    var t2:[UInt8] = [UInt8](repeating:0, count:32)
    var get1 = ge25519()
    var get2 = ge25519()
    var gepk = ge25519()
    
    //var schmr = sc25519()
    var scs = sc25519()
    //var hmr:[UInt8] = [UInt8](repeating:0, count:crypto_hash_sha512_BYTES)
    
    if smlen < 64 { throw DecryptError.general }
    if ge25519_unpack_vartime(&get1, sm) { throw DecryptError.general }
    if ge25519_unpack_vartime(&gepk, pk) { throw DecryptError.general }
    
    //crypto_hash_sha512(&hmr,sm,smlen-32)
    
    //sc25519_from64bytes(&schmr, hmr)
    //ge25519_scalarmult(&get1, get1, schmr)
    //ge25519_add(&get1, get1, gepk)
    //ge25519_pack(&t1, get1)
    
    sc25519_from32bytes(&scs, Array(sm[smlen-32..<smlen]))
    ge25519_scalarmult_base(&get2, scs)
    ge25519_pack(&t2, get2)
    
    for i in 0..<smlen-64 {
        m[i] = sm[i + 32]
    }
    
    //print("m:\(m.utf8Description())")
    
    /*
    if !crypto_verify_32(t1, t2) {
        print("t1:\(t1.hexDescription())")
        print("t2:\(t2.hexDescription())")
        throw DecryptError.general
    }
    */
    return m
}
