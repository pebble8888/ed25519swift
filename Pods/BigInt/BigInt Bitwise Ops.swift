//
//  BigInt Bitwise Ops.swift
//  Pods
//
//  Created by pebble8888 on 2017/05/13.
//
//

import Foundation

extension BigInt {
    public func odd() -> Int {
        let val:BigUInt = self.abs & 1
        if val == BigUInt(0) {
            return 0
        } else if self.negative {
            return -1
        } else {
            return 1
        }
    }
}

extension BigUInt {
    public func odd() -> Int {
        let val:BigUInt = self & 1
        if val == BigUInt(0) {
            return 0
        } else {
            return 1
        }
    }
}
