//
//  BigInt+ExtensionTests.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/15.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import XCTest
import Ed25519iOS
import BigInt

class BigInt_ExtensionTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testModulo() {
        XCTAssertEqual(BigInt(7).modulo(3), BigInt(1))
        XCTAssertEqual(BigInt(7).modulo(-3), BigInt(-2))
        XCTAssertEqual(BigInt(-7).modulo(3), BigInt(2))
        XCTAssertEqual(BigInt(-7).modulo(-3), BigInt(-1))

        XCTAssertEqual(BigInt(6).modulo(3), BigInt(0))
        XCTAssertEqual(BigInt(6).modulo(-3), BigInt(0))
        XCTAssertEqual(BigInt(-6).modulo(3), BigInt(0))
        XCTAssertEqual(BigInt(-6).modulo(-3), BigInt(0))
    }
    
    func testDivide() {
        XCTAssertEqual(BigInt(7).divide(2), BigInt(3))
        XCTAssertEqual(BigInt(7).divide(-2), BigInt(-4))
        XCTAssertEqual(BigInt(-7).divide(2), BigInt(-4))
        XCTAssertEqual(BigInt(-7).divide(-2), BigInt(3))

        XCTAssertEqual(BigInt(6).divide(2), BigInt(3))
        XCTAssertEqual(BigInt(6).divide(-2), BigInt(-3))
        XCTAssertEqual(BigInt(-6).divide(2), BigInt(-3))
        XCTAssertEqual(BigInt(-6).divide(-2), BigInt(3))
    }
    
    func testOdd() {
        XCTAssertEqual(BigInt(3).odd(), 1)
        XCTAssertEqual(BigInt(2).odd(), 0)
        XCTAssertEqual(BigInt(1).odd(), 1)
        XCTAssertEqual(BigInt(0).odd(), 0)
        XCTAssertEqual(BigInt(-1).odd(), 1)
        XCTAssertEqual(BigInt(-2).odd(), 0)
        XCTAssertEqual(BigInt(-3).odd(), 1)
        XCTAssertEqual(BigInt("1000000000000000000000000000000").odd(), 0)
        XCTAssertEqual(BigInt(abs:BigUInt("1000000000000000000000000000001")!, negative:true).odd(), 1)
        XCTAssertEqual(BigInt("1000000000000000000000000000000").odd(), 0)
        XCTAssertEqual(BigInt(abs:BigUInt("1000000000000000000000000000001")!, negative:true).odd(), 1)
    }
}
