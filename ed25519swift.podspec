Pod::Spec.new do |s|
  s.name         = "ed25519swift"
  s.version      = "1.2.4"
  s.summary      = "ed25199 implementation by pure swift except sha512"
  s.homepage     = "https://github.com/pebble8888/ed25519swift"
  s.license      = "ZLIB"
  s.author             = { "pebble8888" => "pebble8888@gmail.com" }
  s.social_media_url   = "http://twitter.com/pebble8888"
  s.ios.deployment_target = "11.4"
  s.osx.deployment_target = "10.12"
  s.pod_target_xcconfig = { "SWIFT_VERSION" => "5.0" }
  s.source       = { :git => "https://github.com/pebble8888/ed25519swift.git", :tag => s.version.to_s }
  s.source_files  = "Sources/ed25519swift"
  s.dependency "CryptoSwift"
  s.swift_version = "5.0"
end
