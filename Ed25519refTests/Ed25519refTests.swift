//
//  Ed25519refTests.swift
//  Ed25519refTests
//
//  Created by pebble8888 on 2017/10/14.
//  Copyright 2017 pebble8888. All rights reserved.
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

    func test0_ref_c() {
        // sk + pk
        let x0 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        // pk
        let x1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let x2 = ""
        let x3 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        //let sk:[UInt8] = String(Array(x0.characters)[0..<64]).unhexlify()
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
    
}
