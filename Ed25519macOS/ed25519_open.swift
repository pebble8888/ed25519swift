//
//  open.swift
//  Ed25519macOS
//
//  Created by pebble8888 on 2017/10/14.
//  Copyright 2017 pebble8888. All rights reserved.
//

import Foundation

public extension Ed25519 {
    /// verify
	/// - Parameters:
	///   - sm: signature 64bytes + message
	///   - pk: public key 32bytes
    public static func crypto_sign_open(_ sm:[UInt8], _ pk:[UInt8]) -> Bool {
        let smlen = sm.count
        var m:[UInt8] = [UInt8](repeating:0, count: smlen + 64)
		var pkcopy:[UInt8] = [UInt8](repeating:0, count:32)
		var rcopy:[UInt8] = [UInt8](repeating:0, count:32) // point R
		var k:[UInt8] = [UInt8](repeating:0, count:64)
		var rcheck:[UInt8] = [UInt8](repeating:0, count:32)
		var ge_a:ge = ge() // unpacked public info from pk argument
		var ge_b:ge = ge()
		var sc_k:sc = sc() // integer k
		var sc_s:sc = sc()
        
        if pk.count != 32 { return false }
        if smlen < 64 { return false }
        if sm[63] & UInt8(224) != 0 {
			// S must smaller than group order L
			return false
		}
        if !ge.ge25519_unpackneg_vartime(&ge_a, pk) { return false }
        
        for i in 0..<32 {
            pkcopy[i] = pk[i]
            rcopy[i] = sm[i] // point R
        }
        
        sc.sc25519_from32bytes(&sc_s, Array(sm[32..<sm.count])) // integer S
		// FIXME:if sc_s >= L else { return false }

		// signature 64 bytes(R 32byte + S 32byte) + message
        for i in 0..<smlen {
            m[i] = sm[i]
        }
		// R 32byte + A 32byte(replaced) + message
        for i in 0..<32 {
            m[i+32] = pkcopy[i]
        }
        crypto_hash_sha512(&k, m, len:smlen)
        sc.sc25519_from64bytes(&sc_k, k) // integer k
        
        // - A k + G s
        ge.ge25519_double_scalarmult_vartime(&ge_b, ge_a, sc_k, ge.ge25519_base, sc_s)
        ge.ge25519_pack(&rcheck, ge_b)
		
		// check R == - A k + G s
        return rcopy == rcheck
    }
}
