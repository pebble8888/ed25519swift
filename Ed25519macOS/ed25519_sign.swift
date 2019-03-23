//
//  ed25519_sign.swift
//
//  Copyright 2017 pebble8888. All rights reserved.
//
//  This software is provided 'as-is', without any express or implied
//  warranty. In no event will the authors be held liable for any damages
//	arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose,
//	including commercial applications, and to alter it and redistribute it
//	freely, subject to the following restrictions:
//
//	1. The origin of this software must not be misrepresented; you must not
//	claim that you wrote the original software. If you use this software
//	in a product, an acknowledgment in the product documentation would be
//	appreciated but is not required.
//
//	2. Altered source versions must be plainly marked as such, and must not be
//	misrepresented as being the original software.
//
//	3. This notice may not be removed or altered from any source distribution.
//

import Foundation

/**
 * ed25519 fast calculation implementation
 * ported from SUPERCOP https://bench.cr.yp.to/supercop.html
 */
public struct Ed25519 {

    static func crypto_hash_sha512(_ r: inout [UInt8], _ k: [UInt8], len: Int) {
        r = sha512(Array(k[0..<len]))
    }

    private static func randombytes(_ r: inout [UInt8], len: Int) {
        r = [UInt8](repeating: 0, count: len)
        // @note Apple API
        let result = SecRandomCopyBytes(kSecRandomDefault, len, &r)
        assert(result == 0)
    }

    private static func crypto_verify_32(_ x: [UInt8], _ y: [UInt8]) -> Bool {
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

    /// create keypair
	/// - Parameters:
    ///   - pk: private key 32bytes
    ///   - sk: secret key 32bytes
    public static func generateKeyPair() -> (pk: [UInt8], sk: [UInt8]) {
        var sk = [UInt8](repeating: 0, count: 32)
        // create secret key 32byte
        randombytes(&sk, len: 32)
        let pk = calcPublicKey(sk)
        return (pk, sk)
    }

    /// calc public key from secret key
	/// - Parameters:
    ///   - sk: secret key
    public static func calcPublicKey(_ sk: [UInt8]) -> [UInt8] {
        assert(sk.count == 32)
        var scsk = sc()
        var gepk = ge()
        var az = [UInt8](repeating: 0, count: 64)
        var pk = [UInt8](repeating: 0, count: 32)
        // sha512 of sk
        crypto_hash_sha512(&az, sk, len: 32)
        // calc public key
        az[0] &= 248 // clear lowest 3bit
        az[31] &= 127 // clear highest bit
        az[31] |= 64 // set second highest bit

        sc.sc25519_from32bytes(&scsk, az)

        // gepk = a * G
        ge.ge25519_scalarmult_base(&gepk, scsk)
        ge.ge25519_pack(&pk, gepk)
        assert(pk.count == 32)
        return pk
    }

	/// validate key pair
	/// - Parameters:
	///   - pk: public key 32bytes
	///   - sk: secret key 32bytes
    public static func isValidKeypair(_ pk: [UInt8], _ sk: [UInt8]) -> Bool {
        if pk.count != 32 { return false }
        if sk.count != 32 { return false }
        let calc_pk = calcPublicKey(sk)
        for i in 0..<32 {
            if calc_pk[i] != pk[i] { return false }
        }
        return true
    }

    /// signing
	/// - Parameters:
	///   - sig: 64 bytes signature
    ///   - m: message
	///   - sk: 32 bytes secret key
	public static func sign(_ sig: inout [UInt8], _ m: [UInt8], _ sk: [UInt8]) {
		assert(sk.count == 32)
        let mlen: Int = m.count
        var az = [UInt8](repeating: 0, count: 64)
        var nonce = [UInt8](repeating: 0, count: 64)
        var hram = [UInt8](repeating: 0, count: 64)
        var sck = sc()
        var scs = sc()
        var scsk = sc()
        var ger = ge()
        /* pk: 32-byte public key A */
		var pk = calcPublicKey(sk)
        crypto_hash_sha512(&az, sk, len: 32)
        az[0] &= 248 // clear lowest 3bit
        az[31] &= 127 // clear highest bit
        az[31] |= 64 // set second highest bit

        var sm = [UInt8](repeating: 0, count: mlen+64)
        for i in 0..<mlen {
            sm[64+i] = m[i]
        }
        for i in 0..<32 {
            sm[32+i] = az[32+i]
        }

        /* az: 32-byte scalar a, 32-byte rendomizer z */
        let data: [UInt8] = Array(sm[32..<(mlen+64)])
        crypto_hash_sha512(&nonce, data, len: mlen+32)
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
        var a = [UInt8](repeating: 0, count: 32)
        sc.sc25519_to32bytes(&a, scs) /* cat s */
        // set S
        for i in 0..<32 {
            sm[32+i] = a[i]
        }

		sig = [UInt8](repeating: 0, count: 64)
		for i in 0..<64 {
			sig[i] = sm[i]
		}
    }
}
