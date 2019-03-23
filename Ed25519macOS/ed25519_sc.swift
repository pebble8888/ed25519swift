//
//  ed25519_sc.swift
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

struct shortsc {
    var v: [UInt32] // 16
    init() {
        v = [UInt32](repeating: 0, count: 16)
    }
}

struct sc {
    var v: [UInt32] // 32
    init() {
        v = [UInt32](repeating: 0, count: 32)
    }

    /* Arithmetic modulo the group order
	  order
	     = 2^252 + 27742317777372353535851937790883648493
	     = 7237005577332262213973186563042994240857116359379907606001950938285454250989
	     = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed

	  p  = 2^256 - 19
	     = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
	*/

	// little endian group order
    private static let m: [UInt32] =
		[0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]

	/*
	  barrett_reduce algorithm
	  mu = 2^512 // m
	     = 1852673427797059126777135760139006525645217721299241702126143248052143860224795
	     = 0x0fffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c131b
	 */
    private static let mu: [UInt32] =
		[0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED, 0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21,
         0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]

    private static func lt(_ a: UInt32, _ b: UInt32) -> UInt32 /* 16-bit inputs */ {
        if a < b {
            return 1
        } else {
            return 0
        }
    }

    /* Reduce coefficients of r before calling reduce_add_sub */
    private static func reduce_add_sub(_ r: inout sc) {
        var pb: UInt32 = 0
        var b: UInt32 = 0
        var t = [UInt8](repeating: 0, count: 32)

        for i in 0..<32 {
            pb += m[i]
            b = lt(r.v[i], pb)
            let vv = Int64(r.v[i])-Int64(pb)+Int64(b<<8)
            assert(vv >= 0 && vv <= 0xff)
            t[i] = UInt8(vv)
            pb = b
        }
        let mask: UInt32 = UInt32(bitPattern: Int32(b)-1) //b &- 1
        for i in 0..<32 {
            r.v[i] ^= mask & (r.v[i] ^ UInt32(t[i]))
        }
    }

    /* Reduce coefficients of x before calling barrett_reduce */
    private static func barrett_reduce(_ r: inout sc, _ x: [UInt32] /* 64 */) {
		assert(x.count == 64)
        /* See HAC(HANDBOOK OF APPLIED CRYPTOGRAPHY), Alg. 14.42 */
        var q2 = [UInt32](repeating: 0, count: 66)
        var r1 = [UInt32](repeating: 0, count: 33)
        var r2 = [UInt32](repeating: 0, count: 33)
        var carry: UInt32
        var pb: UInt32 = 0
        var b: UInt32

        for i in 0..<33 {
            for j in 0..<33 {
                if i+j >= 31 {
                    q2[i+j] += mu[i] * x[j+31]
                }
            }
        }
        carry = q2[31] >> 8
        q2[32] += carry
        carry = q2[32] >> 8
        q2[33] += carry

        for i in 0..<33 {
			r1[i] = x[i]
		}
        for i in 0..<32 {
            for j in 0..<33 {
                if i+j < 33 {
                    r2[i+j] += m[i] * q2[33+j]
                }
            }
        }

        for i in 0..<32 {
            carry = r2[i] >> 8
            r2[i+1] += carry
            r2[i] &= 0xff
        }

        for i in 0..<32 {
            pb += r2[i]
            b = lt(r1[i], pb)
            let vv = Int64(r1[i]) - Int64(pb) + Int64(b<<8)
            assert(vv>=0 && vv <= 0xff)
            r.v[i] = UInt32(vv)
            pb = b
        }

        /* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3 
         * If so: Handle  it here!
         */

        reduce_add_sub(&r)
        reduce_add_sub(&r)
    }

	// check x is [0, m)
	static func sc25519_less_order(_ x: [UInt8] /* 32 */) -> Bool {
		if x.count != 32 {
			return false
		}
		for i in (0..<32).reversed() {
			if x[i] < m[i] {
				// less
				return true
			} else if x[i] > m[i] {
				// large
				return false
			}
		}
		// equal m
		return false
	}

    static func sc25519_from32bytes(_ r: inout sc, _ x: [UInt8] /* 32 */) {
		assert(x.count >= 32)
        var t = [UInt32](repeating: 0, count: 64)
        for i in 0..<32 {
            t[i] = UInt32(x[i])
        }
        for i in 32..<64 {
            t[i] = 0
        }
        sc.barrett_reduce(&r, t)
    }

    static func sc25519_from16bytes(_ r: inout shortsc, _ x: [UInt8] /* 16 */) {
		assert(x.count >= 16)
        for i in 0..<16 {
			r.v[i] = UInt32(x[i])
		}
    }

    static func sc25519_from64bytes(_ r: inout sc, _ x: [UInt8] /* 64 */) {
		assert(x.count == 64)
        var t = [UInt32](repeating: 0, count: 64)
        for i in 0..<64 {
            t[i] = UInt32(x[i])
        }
        sc.barrett_reduce(&r, t)
    }

    static func sc25519_from_shortsc(_ r: inout sc, _ x: shortsc) {
        for i in 0..<16 {
            r.v[i] = x.v[i]
        }
        for i in 0..<16 {
            r.v[16+i] = 0
        }
    }

    static func sc25519_to32bytes(_ r: inout [UInt8] /* 32 */, _ x: sc) {
		assert(r.count == 32)
        for i in 0..<32 {
			r[i] = UInt8(x.v[i])
		}
    }

    static func sc25519_iszero_vartime(_ x: sc) -> Int {
        for i in 0..<32 {
            if x.v[i] != 0 {
                return 0
            }
        }
        return 1
    }

    static func sc25519_isshort_vartime(_ x: sc) -> Int {
        for i in stride(from: 31, to: 15, by: -1) {
            if x.v[i] != 0 { return 0 }
        }
        return 1
    }

    static func sc25519_lt_vartime(_ x: sc, _ y: sc) -> UInt {
        for i in stride(from: 31, through: 0, by: -1) {
            if x.v[i] < y.v[i] { return 1 }
            if x.v[i] > y.v[i] { return 0 }
        }
        return 0
    }

    static func sc25519_add(_ r: inout sc, _ x: sc, _ y: sc) {
        var carry: UInt32
        for i in 0..<32 {
            r.v[i] = x.v[i] + y.v[i]
        }
        for i in 0..<31 {
            carry = r.v[i] >> 8
            r.v[i+1] += carry
            r.v[i] &= 0xff
        }
        sc.reduce_add_sub(&r)
    }

    static func sc25519_sub_nored(_ r: inout sc, _ x: sc, _ y: sc) {
        var b: UInt32 = 0
        var t: UInt32
        for i in 0..<32 {
            t = x.v[i] - y.v[i] - b
            r.v[i] = t & 255
            b = (t >> 8) & 1
        }
    }

    static func sc25519_mul(_ r: inout sc, _ x: sc, _ y: sc) {
        var carry: UInt32
        var t = [UInt32](repeating: 0, count: 64)

        for i in 0..<32 {
            for j in 0..<32 {
                t[i+j] += x.v[i] * y.v[j]
            }
        }

        /* Reduce coefficients */
        for i in 0..<63 {
            carry = t[i] >> 8
            t[i+1] += carry
            t[i] &= 0xff
        }

        sc.barrett_reduce(&r, t)
    }

    static func sc25519_mul_shortsc(_ r: inout sc, _ x: sc, _ y: shortsc) {
        var t = sc()
        sc25519_from_shortsc(&t, y)
        sc25519_mul(&r, x, t)
    }

    // divide to 3bits
    static func sc25519_window3(_ r: inout [Int8] /* 85 */, _ s: sc) {
		assert(r.count == 85)
        for i in 0..<10 {
            r[8*i+0]  = Int8(bitPattern: UInt8(s.v[3*i+0]       & 7))
            r[8*i+1]  = Int8(bitPattern: UInt8((s.v[3*i+0] >> 3) & 7))
            r[8*i+2]  = Int8(bitPattern: UInt8((s.v[3*i+0] >> 6) & 7))
            r[8*i+2] ^= Int8(bitPattern: UInt8((s.v[3*i+1] << 2) & 7))
            r[8*i+3]  = Int8(bitPattern: UInt8((s.v[3*i+1] >> 1) & 7))
            r[8*i+4]  = Int8(bitPattern: UInt8((s.v[3*i+1] >> 4) & 7))
            r[8*i+5]  = Int8(bitPattern: UInt8((s.v[3*i+1] >> 7) & 7))
            r[8*i+5] ^= Int8(bitPattern: UInt8((s.v[3*i+2] << 1) & 7))
            r[8*i+6]  = Int8(bitPattern: UInt8((s.v[3*i+2] >> 2) & 7))
            r[8*i+7]  = Int8(bitPattern: UInt8((s.v[3*i+2] >> 5) & 7))
        }
        let i = 10
        r[8*i+0]  =  Int8(bitPattern: UInt8(s.v[3*i+0]       & 7))
        r[8*i+1]  = Int8(bitPattern: UInt8((s.v[3*i+0] >> 3) & 7))
        r[8*i+2]  = Int8(bitPattern: UInt8((s.v[3*i+0] >> 6) & 7))
        r[8*i+2] ^= Int8(bitPattern: UInt8((s.v[3*i+1] << 2) & 7))
        r[8*i+3]  = Int8(bitPattern: UInt8((s.v[3*i+1] >> 1) & 7))
        r[8*i+4]  = Int8(bitPattern: UInt8((s.v[3*i+1] >> 4) & 7))

        /* Making it signed */
        var carry: Int8 = 0
        for i in 0..<84 {
            r[i] += carry
            r[i+1] += (r[i] >> 3)
            r[i] &= 7
            carry = r[i] >> 2
            let vv: Int16 = Int16(r[i]) - Int16(carry<<3)
            assert(vv >= -128 && vv <= 127)
            r[i] = Int8(vv)
        }
        r[84] += Int8(carry)
    }

    // divide to 5bits
    static func sc25519_window5(_ r: inout [Int8] /* 51 */, _ s: sc) {
		assert(r.count == 51)
        var carry: Int8
        for i in 0..<6 {
            r[8*i+0]  =  Int8(s.v[5*i+0])       & 31
            r[8*i+1]  = (Int8(s.v[5*i+0]) >> 5) & 31
            r[8*i+1] ^= (Int8(s.v[5*i+1]) << 3) & 31
            r[8*i+2]  = (Int8(s.v[5*i+1]) >> 2) & 31
            r[8*i+3]  = (Int8(s.v[5*i+1]) >> 7) & 31
            r[8*i+3] ^= (Int8(s.v[5*i+2]) << 1) & 31
            r[8*i+4]  = (Int8(s.v[5*i+2]) >> 4) & 31
            r[8*i+4] ^= (Int8(s.v[5*i+3]) << 4) & 31
            r[8*i+5]  = (Int8(s.v[5*i+3]) >> 1) & 31
            r[8*i+6]  = (Int8(s.v[5*i+3]) >> 6) & 31
            r[8*i+6] ^= (Int8(s.v[5*i+4]) << 2) & 31
            r[8*i+7]  = (Int8(s.v[5*i+4]) >> 3) & 31
        }
        let i = 6
        r[8*i+0]  =  Int8(s.v[5*i+0]     ) & 31
        r[8*i+1]  = (Int8(s.v[5*i+0]) >> 5) & 31
        r[8*i+1] ^= (Int8(s.v[5*i+1]) << 3) & 31
        r[8*i+2]  = (Int8(s.v[5*i+1]) >> 2) & 31

        /* Making it signed */
        carry = 0
        for i in 0..<50 {
            r[i] += carry
            r[i+1] += r[i] >> 5
            r[i] &= 31
            carry = r[i] >> 4
            r[i] -= (carry << 5)
        }
        r[50] += carry
    }

    static func sc25519_2interleave2(_ r: inout [UInt8] /* 127 */, _ s1: sc, _ s2: sc) {
		assert(r.count == 127)
        for i in 0..<31 {
            let a1 = UInt8(s1.v[i] & 0xff)
            let a2 = UInt8(s2.v[i] & 0xff)
            r[4*i]   = ((a1 >> 0) & 3) ^ (((a2 >> 0) & 3) << 2)
            r[4*i+1] = ((a1 >> 2) & 3) ^ (((a2 >> 2) & 3) << 2)
            r[4*i+2] = ((a1 >> 4) & 3) ^ (((a2 >> 4) & 3) << 2)
            r[4*i+3] = ((a1 >> 6) & 3) ^ (((a2 >> 6) & 3) << 2)
        }

        let b1 = UInt8(s1.v[31] & 0xff)
        let b2 = UInt8(s2.v[31] & 0xff)
        r[124] = ((b1 >> 0) & 3) ^ (((b2 >> 0) & 3) << 2)
        r[125] = ((b1 >> 2) & 3) ^ (((b2 >> 2) & 3) << 2)
        r[126] = ((b1 >> 4) & 3) ^ (((b2 >> 4) & 3) << 2)
    }
}
