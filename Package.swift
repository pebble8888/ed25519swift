// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "ed25519swift",
    products: [
        .library(
            name: "ed25519swift",
            targets: ["ed25519swift"])
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "ed25519swift",
            dependencies: ["CryptoSwift"])
    ],
    swiftLanguageVersions: [.v5]
)
