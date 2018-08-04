//
//  Ed25519macOSTests.swift
//
//  Created by pebble8888 on 2017/05/13.
//  Copyright 2017 pebble8888. All rights reserved.
//

import XCTest
#if os(macOS)
@testable import Ed25519macOS
#elseif os(iOS)
@testable import Ed25519iOS
#endif

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
        let m = x2.unhexlify()
        var sm:[UInt8] = [UInt8](repeating:0, count:0)
        Ed25519.crypto_sign(&sm, x2.unhexlify(), skpk)
        XCTAssertEqual(sm.count, 64 + m.count)

        let pk:[UInt8] = x1.unhexlify()
        let result = Ed25519.crypto_sign_open(sm, pk)
        XCTAssert(result)

        XCTAssertEqual(x3, sm.hexDescription())
    }
    
    func test1_fastlogic() {
        // sk + pk
        let x0 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        // pk
        let x1 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        let x2 = "72"
        let x3 = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c0072"
        //let sk = String(Array(x0.characters)[0..<64]).unhexlify()
        let skpk:[UInt8] = x0.unhexlify()
        //let pk = Ed25519.publickey(sk)
        let m = x2.unhexlify()
        var sm:[UInt8] = [UInt8](repeating:0, count:0)
        Ed25519.crypto_sign(&sm, x2.unhexlify(), skpk)
        XCTAssertEqual(sm.count, 64 + m.count)
        
        let pk:[UInt8] = x1.unhexlify()
        let result = Ed25519.crypto_sign_open(sm, pk)
        XCTAssert(result)
        
        XCTAssertEqual(x3, sm.hexDescription())
    }
    
    // Debug: 558sec macOS
    // Release : 11sec macOS
    func test1024_fastlogic() {
        guard let url = Bundle(for: type(of:self)).resourceURL else { XCTFail(); return }
        do {
            let s = try String(contentsOf: url.appendingPathComponent("input.txt"))
            let lines = s.components(separatedBy: "\n")
            for line in lines {
				let ary: [String] = line.components(separatedBy: ":")
                if ary.count == 5 {
                    // sk + pk
                    let x0 = ary[0]
                    // pk
                    let x1 = ary[1]
                    let x2 = ary[2]
                    let x3 = ary[3]
                    let sk:[UInt8] = String(Array(x0.characters)[0..<64]).unhexlify()
                    XCTAssert(sk.count == 32)
                    let skpk:[UInt8] = x0.unhexlify()
                    //let pk = Ed25519.publickey(sk)
                    let m = x2.unhexlify()
                    var sm:[UInt8] = [UInt8](repeating:0, count:0)
                    Ed25519.crypto_sign(&sm, x2.unhexlify(), skpk)
                    XCTAssertEqual(sm.count, 64 + m.count)
                    
                    let pk:[UInt8] = x1.unhexlify()
                    let result = Ed25519.crypto_sign_open(sm, pk)
                    XCTAssert(result)
                    
                    XCTAssertEqual(x3, sm.hexDescription())
                    
                    let r2 = Ed25519.crypto_isvalid_keypair(pk, sk)
                    XCTAssert(r2)
                    
                    //print(".", terminator:"")
                }
            }
        } catch {
            XCTFail()
        }
    }
    
    // Release: 5 sec macOS
    // Debug: 248 sec macOS
    func test256_create_keypair() {
        for _ in 0..<1024 {
            let pair = Ed25519.crypto_sign_keypair()
            let result = Ed25519.crypto_isvalid_keypair(pair.pk, pair.sk)
            XCTAssert(result)
            print(">", terminator:"")
        }
    }
}
