//
//  sign.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/21.
//  Copyright © 2017年 pebble8888. All rights reserved.
//
//  Code is ported from NaCl (http://nacl.cr.yp.to/)
//

import Foundation

let CRYPTO_SECRETKEYBYTES = 64
let CRYPTO_PUBLICKEYBYTES = 32
let CRYPTO_BYTES = 64
let crypto_hash_sha512_BYTES = 64

func crypto_hash_sha512(_ r:inout [UInt8], _ k:[UInt8], len:Int)
{
    r = sha512(Array(k[0..<len])).digest()
}

func randombytes(_ r:inout [UInt8], len:Int)
{
    r = [UInt8](repeating:0, count:len)
    let result = SecRandomCopyBytes(kSecRandomDefault, len, &r)
    assert(result == 0)
}

func crypto_verify_32(_ x:[UInt8], _ y:[UInt8]) -> Bool
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
     /*
    var differentbits:UInt8 = 0
    for i in 0..<32 {
        differentbits |= x[i] ^ y[i]
    }
    let a:Int32 = (1 & ((Int32(differentbits) - 1) >> 8)) - 1
    return a == 0
     */
}

// pk: 32bytes, sk: 32bytes
public func crypto_sign_keypair() -> (pk:[UInt8], sk:[UInt8])
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

// +64
// signing
// sm: message length + 64
// m: message
// return : R + m + S
public func crypto_sign(_ sm:inout [UInt8], _ m:[UInt8], _ skpk:[UInt8]) -> UInt8
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
    print("nonce:\(nonce)")
    // rをsckに詰める
    sc.sc25519_from64bytes(&sck, nonce)
    // ベースポイントをr倍する
    ge.ge25519_scalarmult_base(&ger, sck)
    
    print("ger:\(ger)")
    // R
    ge.ge25519_pack(&sm, ger)
    
    // pk を詰める
    for i in 0..<32 {
        sm[i+32] = pk[i]
    }
    // k
    crypto_hash_sha512(&hram, sm, len: mlen+64)
    // scsにkを詰める
    sc.sc25519_from64bytes(&scs, hram)
    // scskに s を詰める
    sc.sc25519_from32bytes(&scsk, az)
    // k * sを計算scsに詰める
    sc.sc25519_mul(&scs, scs, scsk)
    // 加算してLでmoduloする
    sc.sc25519_add(&scs, scs, sck)
    
    // S
    var a:[UInt8] = [UInt8](repeating:0, count:32)
    sc.sc25519_to32bytes(&a, scs) /* cat s */
    // Sを詰める
    for i in 0..<32 {
        sm[32+i] = a[i]
    }
    return 0
}

public enum DecryptError : Swift.Error {
    case general
}

// decrypt
// -64
/*
public func crypto_sign_open(_ sm:[UInt8], _ pk:[UInt8]) throws -> [UInt8] {
    let smlen = sm.count
    var m:[UInt8] = [UInt8](repeating:0, count: smlen - 64)
    //var t1:[UInt8] = [UInt8](repeating:0, count:32)
    var t2:[UInt8] = [UInt8](repeating:0, count:32)
    var get1 = ge()
    var get2 = ge()
    var gepk = ge()
    
    //var schmr = sc()
    var scs = sc()
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
 */
