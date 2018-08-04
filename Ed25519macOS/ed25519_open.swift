//
//  open.swift
//  Ed25519macOS
//
//  Created by pebble8888 on 2017/10/14.
//  Copyright 2017 pebble8888. All rights reserved.
//

import Foundation

public extension Ed25519 {
    // decrypt
    // @param sm  sinagure 64bytes + message
    // @param pk  primary key 32bytes
    public static func crypto_sign_open(_ sm:[UInt8], _ pk:[UInt8]) -> Bool {
        let smlen = sm.count
        var m:[UInt8] = [UInt8](repeating:0, count: smlen + 64)
        var pkcopy = [UInt8](repeating:0, count:32)
        var rcopy = [UInt8](repeating:0, count:32)
        var hram = [UInt8](repeating:0, count:64)
        var rcheck = [UInt8](repeating:0, count:32)
        var get1 = ge()
        var get2 = ge()
        var schram = sc()
        var scs = sc()
        
        if pk.count != 32 { return false }
        if smlen < 64 { return false }
        if sm[63] & UInt8(224) != 0 { return false }
        if !ge.ge25519_unpackneg_vartime(&get1, pk) { return false }
        
        for i in 0..<32 {
            pkcopy[i] = pk[i]
            rcopy[i] = sm[i]
        }
        
        sc.sc25519_from32bytes(&scs, Array(sm[32..<sm.count]))
        
        for i in 0..<smlen {
            m[i] = sm[i]
        }
        for i in 0..<32 {
            m[i+32] = pkcopy[i]
        }
        crypto_hash_sha512(&hram, m, len:smlen)
        
        sc.sc25519_from64bytes(&schram, hram)
        
        ge.ge25519_double_scalarmult_vartime(&get2, get1, schram, ge.ge25519_base, scs)
        ge.ge25519_pack(&rcheck, get2)
        
        return rcopy == rcheck
    }
}
