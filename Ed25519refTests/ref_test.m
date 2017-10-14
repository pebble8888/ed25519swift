//
//  ref_test.m
//  Ed25519macOSTests
//
//  Created by pebble8888 on 2017/10/12.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <Ed25519ref/Ed25519ref-Swift.h>
#import <Ed25519ref/fe25519.h>
#import <Ed25519ref/sc25519.h>

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
