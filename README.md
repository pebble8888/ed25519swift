# Ed25519
Ed25519(EdDSA) by pure swift

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

### Swift Package Manager

The [Swift Package Manager](https://swift.org/package-manager/) is a tool for automating the distribution of Swift code and is integrated into the `swift` compiler.

Once you have your Swift package set up, adding Ed25519 as a dependency is as easy as adding it to the `dependencies` value of your `Package.swift`.

```swift
dependencies: [
    .package(url: "https://github.com/pebble8888/ed25519swift.git", from: "1.2.7")
]
```

## Dependency

[CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift) for sha512

[BigInt](https://github.com/attaswift/BigInt) for reference implementation that is not included main Ed25519 library.

## How to use

### Key pair creation

``` swift
import Ed25519macOS // direct
or
import ed25519swift // pods or Swift Package Manager

static func Ed25519.generateKeyPair() -> (publicKey: [UInt8], secretKey: [UInt8])
```

### Signing 
``` swift
static func Ed25519.sign(message: [UInt8], secretKey: [UInt8]) -> [UInt8]
```

### Validation
``` swift
static func Ed25519.verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool
```

### Calc public key from secret key
``` swift
static func Ed25519.calcPublicKey(secretKey: [UInt8]) -> [UInt8]
```

### Check valid keypair
``` swift
static func Ed25519.isValidKeyPair(publicKey: [UInt8], secretKey: [UInt8]) -> Bool
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
  keypair creation : 4.8 msec per keypair 
  
### iOS
  no measurement

