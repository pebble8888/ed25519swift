//
//  Ed25519macOSTests.swift
//
//  Created by pebble8888 on 2017/05/13.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import XCTest
import BigInt
@testable import Ed25519macOS

class Ed25519macOSTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func test0_fastlogic() {
        // sk + pk
        let x0 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        // pk
        let x1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let x2 = ""
        let x3 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        //let sk = String(Array(x0.characters)[0..<64]).unhexlify()
        let skpk:[UInt8] = x0.unhexlify()
        //let pk = Ed25519.publickey(sk)
        //let m = x2.unhexlify()
        var sm:[UInt8] = [UInt8](repeating:0, count:0)
        let d = ed25519.crypto_sign(&sm, x2.unhexlify(), skpk)
        XCTAssertEqual(d, 0)
        XCTAssertEqual(sm.count, 64)

        let pk:[UInt8] = x1.unhexlify()
        let result = ed25519.crypto_sign_open(sm, pk);
        XCTAssert(result)

        XCTAssertEqual(x3, sm.hexDescription())
    }
    
}
