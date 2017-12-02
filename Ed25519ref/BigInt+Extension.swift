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
    public func parity() -> Int {
        return self.magnitude.parity()
    }
    
    public init(word: Word) {
        let m = BigUInt(word)
        self.init(sign: word >= 0 ? .plus : .minus, magnitude: m)
    }
}

extension BigUInt {
    // return value: 0 or 1
    public func parity() -> Int {
        let a = self % BigUInt(2)
        let b = a & 1
        return Int(b)
    }
}

extension BigInt {
    
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
        let v = self.magnitude % divider.magnitude
        if v == 0 {
            return 0
        }
        if self.sign == .plus {
            if divider.sign == .plus {
                return BigInt(sign:.plus, magnitude:v)
            } else {
                return BigInt(sign:.plus, magnitude:v) + divider
            }
        } else {
            if divider.sign == .plus {
                return BigInt(sign:.minus, magnitude:v) + divider
            } else {
                return BigInt(sign:.minus, magnitude:v)
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
        let v = self.magnitude / divider.magnitude
        if self.sign == .plus {
            if divider.sign == .plus {
                return BigInt(sign:.plus, magnitude:v)
            } else {
                if (self.magnitude % divider.magnitude) == 0 {
                    return BigInt(sign:.minus, magnitude:v)
                } else {
                    return BigInt(sign:.minus, magnitude:v+1)
                }
            }
        } else {
            if divider.sign == .plus {
                if (self.magnitude % divider.magnitude) == 0 {
                    return BigInt(sign:.minus, magnitude:v)
                } else {
                    return BigInt(sign:.minus, magnitude:v+1)
                }
            } else {
                return BigInt(sign:.plus, magnitude:v)
            }
        }
    }
    
    // return val is less than q
    public static func expmod(_ b:BigInt, _ e:BigInt, _ q:BigInt) -> BigInt {
        if e == 0 { return 1 }
        var t = expmod(b, e.divide(2), q).power(2).modulo(q)
        if e.parity() != 0 {
            t = (t*b).modulo(q)
        }
        return t
    }
    
    // return val is less than q
    public static func inv(_ x:BigInt, _ q:BigInt) -> BigInt {
        return expmod(x,q-2,q)
    }
}
