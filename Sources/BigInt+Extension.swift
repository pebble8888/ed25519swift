//
//  BigInt Exponentiation.swift
//
//  Created by pebble8888 on 2017/05/13.
//
//

import Foundation
import BigInt

extension BigInt {
    // 0 or 1
    public func odd() -> Int {
        return self.abs.odd()
    }
}

extension BigUInt {
    // return value: 0 or 1
    public func odd() -> Int {
        let a:UIntMax = self[0]
        let b:UIntMax = a & 1
        return Int(b)
    }
}

extension BigInt {
    public func power(_ exponent: Int) -> BigInt {
        assert(exponent >= 0)
        let val = self.abs.power(exponent)
        if exponent % 2 == 0 {
            return BigInt(abs:val) 
        } else {
            return BigInt(abs:val, negative:self.negative)
        }
    }
    
    /* python, ruby
    >>> 7 % 3
    1
    >>> 7 % -3
    -2
    >>> -7 % 3
    2
    >>> -7 % -3
    -1
     */
    public func modulo(_ divider:BigInt) -> BigInt {
        let v = self.abs % divider.abs
        if v == 0 {
            return 0
        }
        if !self.negative {
            if !divider.negative {
                return BigInt(abs:v)
            } else {
                return BigInt(abs:v) + divider
            }
        } else {
            if !divider.negative {
                return BigInt(abs:v, negative:true) + divider
            } else {
                return BigInt(abs:v, negative:true)
            }
        }
    }
    
    /** python, ruby
    >>> 7 / 2
    3
    >>> 7 / -2
    -4
    >>> -7 / 2
    -4
    >>> -7 / -2
    3
    */
    public func divide(_ divider:BigInt) -> BigInt {
        let v = self.abs / divider.abs
        if !self.negative {
            if !divider.negative {
                return BigInt(abs:v)
            } else {
                if (self.abs % divider.abs) == 0 {
                    return BigInt(abs:v, negative:true)
                } else {
                    return BigInt(abs:v+1, negative:true)
                }
            }
        } else {
            if !divider.negative {
                if (self.abs % divider.abs) == 0 {
                    return BigInt(abs:v, negative:true)
                } else {
                    return BigInt(abs:v+1, negative:true)
                }
            } else {
                return BigInt(abs:v)
            }
        }
    }
}
