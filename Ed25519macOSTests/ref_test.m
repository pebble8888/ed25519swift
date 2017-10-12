//
//  ref_test.m
//  Ed25519macOSTests
//
//  Created by pebble8888 on 2017/10/12.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <Ed25519macOS/Ed25519macOS-Swift.h>
#import <Ed25519macOS/fe25519.h>
#import <Ed25519macOS/sc25519.h>

@interface ref_test : XCTestCase

@end

@implementation ref_test

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample {
    
    const signed char a = 2;
    for (signed char b = -127; b <= 127; ++b){
        if (b == a){
            XCTAssertEqual(equal_i8(a, b), 1);
        } else {
            XCTAssertEqual(equal_i8(a, b), 0);
        }
    }
}

- (void)test111 {
    fe25519 f;
    for (int i = 0; i < 32; ++i){
        f.v[i] = 0;
    }
    fe25519 a;
    for (int i = 0; i < 32; ++i) {
        a.v[i] = i;
    }
    fe25519_cmov(&f, &a, 254);
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

- (void)testWindow3 {
    
    sc25519 sc;
    for (int i = 0; i < 32; ++i){
        sc.v[i] = i;
    }
    int8_t r[85];
    sc25519_window3(r, &sc);
    
    XCTAssertEqual(r[0], 0);
    XCTAssertEqual(r[1], 0);
    XCTAssertEqual(r[2], (int8_t)0xfc);
    XCTAssertEqual(r[3], 0x01);
    XCTAssertEqual(r[4], 0);
    XCTAssertEqual(r[5], (int8_t)0xfc);
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

@end
