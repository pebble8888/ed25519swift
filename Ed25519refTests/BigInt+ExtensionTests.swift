//
//  BigInt+ExtensionTests.swift
//  Ed25519
//
//  Created by pebble8888 on 2017/05/15.
//  Copyright 2017 pebble8888. All rights reserved.
//

import XCTest
import Ed25519ref
import BigInt

class BigInt_ExtensionTests: XCTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testFundamental_0() {
        let x = BigInt(sign: .minus, magnitude: 1)
        let y = BigInt(sign: .plus, magnitude: 2)
        _ = x % y
    }

    func testFundamental_1() {
        let x = BigUInt(1)
        let y = BigUInt(2)
        _ = x % y
    }

    func testModulo() {
        XCTAssertEqual(BigUInt(1) % BigUInt(2), 1)
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
        XCTAssertEqual(BigInt(3).parity(), 1)
        XCTAssertEqual(BigInt(2).parity(), 0)
        XCTAssertEqual(BigInt(1).parity(), 1)
        XCTAssertEqual(BigInt(0).parity(), 0)
        XCTAssertEqual(BigInt(-1).parity(), 1)
        XCTAssertEqual(BigInt(-2).parity(), 0)
        XCTAssertEqual(BigInt(-3).parity(), 1)
        XCTAssertEqual(BigInt("1000000000000000000000000000000").parity(), 0)
        XCTAssertEqual(BigInt(sign: .minus, magnitude: BigUInt("1000000000000000000000000000001")!).parity(), 1)
        XCTAssertEqual(BigInt("1000000000000000000000000000000").parity(), 0)
        XCTAssertEqual(BigInt(sign: .minus, magnitude: BigUInt("1000000000000000000000000000001")!).parity(), 1)
    }
}
