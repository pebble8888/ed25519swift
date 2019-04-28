# Ed25519
Ed25519 by pure swift

[ed25519](https://ed25519.cr.yp.to)

## License
Ed25519 can be used, distributed and modified user the zlib license.

## Requirements
Ed25519 requires Swift5.

macOS, iOS

## Install

### CocoaPods

```
pod 'ed25519swift'
```
## Dependency

[CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift) for sha512

[BigInt](https://github.com/attaswift/BigInt) for reference implementation that is not included main Ed25519 library.

## How to use

### Key pair creation

``` swift
import Ed25519macOS // direct
or
import ed25519swift // pods

static func generateKeyPair() -> (pk: [UInt8], sk: [UInt8])
```

### Signing 
``` swift
static func sign(_ sig: inout [UInt8], _ m: [UInt8], _ sk: [UInt8])
```

### Validation
``` swift
static func verify(_ sig: [UInt8], _ m: [UInt8], _ pk: [UInt8]) -> Bool
```

### Calc public key from secret key
``` swift
static func calcPublicKey(_ sk: [UInt8]) -> [UInt8]
```

### Check valid keypair
``` swift
static func isValidKeypair(_ pk: [UInt8], _ sk: [UInt8]) -> Bool
```

## Implemantation

It is ported from [SUPERCOP](https://bench.cr.yp.to/supercop.html)  
  
You can check the algorithm in these papers and RFC.  
[Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang, High-speed high-security signatures. 2012](https://ed25519.cr.yp.to/ed25519-20110926.pdf)  
[Huseyin Hisl, Kenneth Koon-Ho Wong, Gary Carter, Ed Dawson, Twisted Edwards curves revisited. 2008](http://eprint.iacr.org/2008/522)  
[RFC8032 Edward-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)  

## Performance

### macOS  
  
  On MacBook Pro 2017 2.3Ghz Intel Core i5  
    
  message validation : 10.7 msec per message  
  keypair creation : 4.8 msec per message  
  
### iOS
  no measurement

