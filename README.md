# Ed25519
Ed25519 by pure swift

[ed25519](https://ed25519.cr.yp.to)

## License
Ed25519 can be used, distributed and modified user the MIT license.

## Requirements
Ed25519 requires Swift 4.

## How to use

### Key pair creation

``` swift
import Ed25519macOS

static func crypto_sign_keypair() -> (pk:[UInt8], sk:[UInt8])
```

### Signing 
``` swift
static func crypto_sign(_ sm:inout [UInt8], _ m:[UInt8], _ skpk:[UInt8])
```

### Validation
``` swift
public static func crypto_sign_open(_ sm:[UInt8], _ pk:[UInt8]) -> Bool
```

## Implemantation

It is ported from [SUPERCOP](https://bench.cr.yp.to/supercop.html)  
  
You can check the algorithm in these papers and RFC.  
[Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang, High-speed high-security signatures. 2012](https://ed25519.cr.yp.to/ed25519-20110926.pdf)  
[Huseyin Hisl, Kenneth Koon-Ho Wong, Gary Carter, Ed Dawson, Twisted Edwards curves revisited. 2008](http://eprint.iacr.org/2008/522)  
[RFC8032 Edward-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)  

## Performance

On MacBook Pro 2017 2.3Ghz Intel Core i5

11 sec for 1024 message validation   
10 msec for a message validation
