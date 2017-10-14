//
//  Ed25519refTests.swift
//  Ed25519refTests
//
//  Created by pebble8888 on 2017/10/14.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import XCTest
import BigInt
@testable import Ed25519ref

class Ed25519refTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_b() {
        XCTAssert(ed25519.b >= 10)
    }
    
    func test_hash() {
        XCTAssertEqual(8 * ed25519.H("hash input".unhexlify()).count, 2 * ed25519.b)
    }
    
    func test_expmod_l() {
        XCTAssertEqual( ed25519.expmod(2, ed25519.q - 1, ed25519.q), 1)
    }
    
    func test_l_lbound() {
        XCTAssert( ed25519.L >= BigInt(2).power(ed25519.b-4))
    }
    
    func test_l_ubound() {
        XCTAssert( ed25519.L <= BigInt(2).power(ed25519.b-3))
    }
    
    func test_expmod_d() {
        XCTAssertEqual(ed25519.expmod(ed25519.d, (ed25519.q-1)/2, ed25519.q), ed25519.q-1)
    }
    
    func test_expmod_I() {
        XCTAssertEqual(ed25519.expmod(ed25519.I, 2, ed25519.q), ed25519.q-1)
    }
    
    func test_b_isoncurve() {
        XCTAssert(ed25519.isoncurve(ed25519.B))
    }
    
    func test0_ref_c() {
        // sk + pk
        let x0 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        // pk
        let x1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let x2 = ""
        let x3 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        let sk:[UInt8] = String(Array(x0.characters)[0..<64]).unhexlify()
        var sm:[UInt8] = [UInt8](repeating:0, count:64)
        var smc:UInt64 = 0
        let m:[UInt8] = x2.unhexlify()
        let skpk:[UInt8] = x0.unhexlify()
        let d = crypto_sign(&sm, &smc, m, UInt64(m.count), skpk)
        XCTAssertEqual(d, 0)
        XCTAssertEqual(smc, 64)
        
        var rm:[UInt8] = [UInt8](repeating:0, count:128)
        var rmc:UInt64 = 0
        let pk:[UInt8] = x1.unhexlify()
        let d1 = crypto_sign_open(&rm, &rmc, sm, smc, pk);
        XCTAssertEqual(d1, 0);
        
        let forgedm:[UInt8] = [0x78]
        let fd1 = crypto_sign_open(&rm, &rmc, forgedm, 1, pk);
        XCTAssertEqual(fd1, -1)
        
        XCTAssertEqual(x3, sm.hexDescription())
    }
    
    #if true
    // 100sec swift debug (You definitely can't wait.)
    // 3sec swift release
    // 1sec for python
    func test_scalarmul() {
        XCTAssert(ed25519.scalarmult(ed25519.B, ed25519.L) == [0,1])
    }
    #endif
    
    #if true
    // 1000sec swift debug (You definitely can't wait.)
    // 39sec swift release
    // 7sec for python
    func test0() {
        // sk + pk
        let x0 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        // pk
        let x1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let x2 = ""
        let x3 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        let sk = String(Array(x0.characters)[0..<64]).unhexlify()
        let pk = ed25519.publickey(sk)
        let m = x2.unhexlify()
        let s = ed25519.signature(m, sk, pk)
        XCTAssert(ed25519.checkvalid(s, m, pk))
        
        let forgedm:[UInt8] = [0x78]
        XCTAssert(!ed25519.checkvalid(s, forgedm, pk))
        
        XCTAssertEqual(x0, (sk + pk).hexDescription())
        XCTAssertEqual(x1, pk.hexDescription())
        XCTAssertEqual(x3, s.hexDescription())
    }
    #endif
    
    #if true
    // 1000sec swift debug (You definitely can't wait.)
    // 33sec swift release
    // 7sec for python
    func test1() {
        let x0 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
            let x1 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
            let x2 = "72"
            let x3 = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c0072"
            let sk = String(Array(x0.characters)[0..<64]).unhexlify()
            print("sk:\(sk.hexDescription())")
            let pk = ed25519.publickey(sk)
            print("pk:\(pk.hexDescription())")
            let m = x2.unhexlify()
            print("m:\(m.hexDescription())")
            let s = ed25519.signature(m, sk, pk)
            print("s:\(s.hexDescription())")
            XCTAssert(ed25519.checkvalid(s, m, pk))

            let forgedm:[UInt8] = m.enumerated().map({ $0.1 + (($0.0 == m.count - 1) ? UInt8(1) : UInt8(0)) })
            XCTAssert(!ed25519.checkvalid(s, forgedm, pk))

            XCTAssertEqual(x0, (sk + pk).hexDescription())
            XCTAssertEqual(x1, pk.hexDescription())
            XCTAssertEqual(x3, (s+m).hexDescription())
    }
    #endif

}
