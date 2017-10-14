//
//  Summable.swift
//  Ed25519ref
//
//  Created by pebble8888 on 2017/10/14.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation
import BigInt

protocol Summable {
    static var Zero: Self { get }
    static func +(lhs: Self, rhs: Self) -> Self
}

extension Sequence where Iterator.Element: Summable {
    func sum() -> Iterator.Element {
        return self.reduce(Iterator.Element.Zero, +)
    }
}

extension Int: Summable {
    static var Zero: Int { return 0 }
}

extension BigInt: Summable {
    static var Zero: BigInt { return BigInt(0) }
}
