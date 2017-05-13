//
//  BigInt Exponentiation.swift
//  Pods
//
//  Created by pebble8888 on 2017/05/13.
//
//

import Foundation

extension BigInt {
    public func power(_ exponent: Int) -> BigInt {
        assert(exponent >= 0)
        let val = self.abs.power(exponent)
        if exponent % 2 == 0 {
            return BigInt(abs:val, negative:true) 
        } else {
            return BigInt(abs:val, negative:false)
        }
    }
}
