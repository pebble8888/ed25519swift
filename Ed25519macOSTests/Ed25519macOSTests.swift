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
    
    func test0_count() {
        XCTAssertEqual( ge.ge25519_base_multiples_affine.count, 425)
    }
    
    func test0_fastlogic() {
        // sk + pk
        let x0 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        // pk
        let x1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let x2 = ""
        let x3 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        let sk = String(Array(x0.characters)[0..<64]).unhexlify()
        let skpk:[UInt8] = x0.unhexlify()
        //let pk = Ed25519.publickey(sk)
        let m = x2.unhexlify()
        var sm:[UInt8] = [UInt8](repeating:0, count:64)
        let d = crypto_sign(&sm, x2.unhexlify(), skpk)
        XCTAssertEqual(d, 0)
        XCTAssertEqual(sm.count, 64)

        let pk:[UInt8] = x1.unhexlify()
        do {
            let rm = try crypto_sign_open(sm, pk);
        } catch {
            XCTFail()
        }

        XCTAssertEqual(x3, sm.hexDescription())
    }
    
    /*
    func test_cmov() {
        var f:fe = fe()
        var a:fe = fe()
        for i in 0..<32 {
            a.v[i] = UInt32(i)
        }
        fe.fe25519_cmov(&f, a, 254);
        XCTAssertEqual(f.v[0], 0);
        XCTAssertEqual(f.v[1], 0);
        XCTAssertEqual(f.v[2], 2);
        XCTAssertEqual(f.v[3], 2);
        XCTAssertEqual(f.v[4], 0);
        XCTAssertEqual(f.v[5], 0);
        XCTAssertEqual(f.v[6], 2);
        XCTAssertEqual(f.v[7], 2);
        XCTAssertEqual(f.v[8], 0);
        XCTAssertEqual(f.v[9], 0);
        XCTAssertEqual(f.v[10], 2);
        XCTAssertEqual(f.v[11], 2);
        XCTAssertEqual(f.v[12], 0);
        XCTAssertEqual(f.v[13], 0);
        XCTAssertEqual(f.v[14], 2);
        XCTAssertEqual(f.v[15], 2);
        XCTAssertEqual(f.v[16], 0);
        XCTAssertEqual(f.v[17], 0);
        XCTAssertEqual(f.v[18], 2);
        XCTAssertEqual(f.v[19], 2);
        XCTAssertEqual(f.v[20], 0);
        XCTAssertEqual(f.v[21], 0);
        XCTAssertEqual(f.v[22], 2);
        XCTAssertEqual(f.v[23], 2);
        XCTAssertEqual(f.v[24], 0);
        XCTAssertEqual(f.v[25], 0);
        XCTAssertEqual(f.v[26], 2);
        XCTAssertEqual(f.v[27], 2);
        XCTAssertEqual(f.v[28], 0);
        XCTAssertEqual(f.v[29], 0);
        XCTAssertEqual(f.v[30], 2);
        XCTAssertEqual(f.v[31], 2);
    }
    
    func testWindow3() {
        var val:sc = sc()
        for i in 0..<32 {
            val.v[i] = UInt32(i);
        }
        var r:[Int8] = [Int8](repeating:0, count:85)
        sc.sc25519_window3(&r, val);
        
        XCTAssertEqual(r[0], 0);
        XCTAssertEqual(r[1], 0);
        XCTAssertEqual(r[2], Int8(bitPattern:0xfc))
        XCTAssertEqual(r[3], 0x01);
        XCTAssertEqual(r[4], 0);
        XCTAssertEqual(r[5], Int8(bitPattern:0xfc))
        XCTAssertEqual(r[6], 0x01);
        XCTAssertEqual(r[7], 0);
        XCTAssertEqual(r[8], 0x03);
        XCTAssertEqual(r[9], 0);
        XCTAssertEqual(r[10], 0);
        XCTAssertEqual(r[11], 0x02);
        XCTAssertEqual(r[12], 0);
        XCTAssertEqual(r[13], 0x02);
        XCTAssertEqual(r[14], 0x01);
        XCTAssertEqual(r[15], 0);
    }
     */
    

}
