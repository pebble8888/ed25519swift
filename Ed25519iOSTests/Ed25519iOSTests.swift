//
//  Ed25519iOSTests.swift
//  Ed25519iOSTests
//
//  Created by pebble8888 on 2017/05/13.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import XCTest
@testable import Ed25519iOS

class Ed25519iOSTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func test0() {
        let x0 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let x1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let x2 = ""
        let x3 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        let sk = String(Array(x0.characters)[0..<64]).unhexlify()
        print("sk:\(sk.hexDescription())")
        let pk = Ed25519.publickey(sk) 
        print("pk:\(pk.hexDescription())")
        let m = x2.unhexlify()
        print("m:\(m.hexDescription())")
        let s = Ed25519.signature(m, sk, pk)
        print("s:\(s.hexDescription())")
        let forgedm:[UInt8] = [0x78]
        XCTAssert(Ed25519.checkvalid(s, forgedm, pk))
        XCTAssertEqual(x0, (sk + pk).hexDescription())
        XCTAssertEqual(x1, pk.hexDescription())
        XCTAssertEqual(x3, s.hexDescription())
    }
    
    func test1() {
        let x0 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        let x1 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        let x2 = "72"
        let x3 = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c0072"
        let sk = String(Array(x0.characters)[0..<64]).unhexlify()
        print("sk:\(sk.hexDescription())")
        let pk = Ed25519.publickey(sk) 
        print("pk:\(pk.hexDescription())")
        let m = x2.unhexlify()
        print("m:\(m.hexDescription())")
        let s = Ed25519.signature(m, sk, pk)
        print("s:\(s.hexDescription())")
        
        let forgedm:[UInt8] = m.enumerated().map({ $0.1 + (($0.0 == m.count - 1) ? UInt8(1) : UInt8(0)) }) 
        XCTAssert(Ed25519.checkvalid(s, forgedm, pk))
        XCTAssertEqual(x0, (sk + pk).hexDescription())
        XCTAssertEqual(x1, pk.hexDescription())
        XCTAssertEqual(x3, s.hexDescription())
    }
    
}
