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
    
    func testExample() {
        let x0 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        _ = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let x2 = ""
        let x3 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        let sk = x0.unhexlify()
        let pk = Ed25519.publickey(sk) 
        let m = x2.unhexlify()
        let s = Ed25519.signature(m, sk, pk)
        
        let ret = Ed25519.checkvalid(s, m, pk)
        XCTAssert(ret)
        
        XCTAssert(s == x3.unhexlify())
    }
    
}
