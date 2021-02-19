// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "ed25519swift",
    platforms: [
        .macOS(.v10_12), .iOS("11.4")
    ],
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
