Pod::Spec.new do |s|
  s.name         = "ed25519swift"
  #s.version      = "1.0.3"
  s.version      = "1.1.0pre"
  s.summary      = "ed25199 implementation by pure swift except sha512"
  s.homepage     = "https://github.com/pebble8888/ed25519swift"
  s.license      = "ZLIB"
  s.author             = { "pebble8888" => "pebble@gmail.com" }
  s.social_media_url   = "http://twitter.com/pebble8888"
  # s.ios.deployment_target = "8.0"
  s.osx.deployment_target = "10.9"
  s.pod_target_xcconfig = { "SWIFT_VERSION" => "4.0" }
  s.source       = { :git => "https://github.com/pebble8888/ed25519swift.git", :tag => s.version.to_s }
  s.source_files  = "Ed25519macOS"
  s.dependency "BigInt", '~> 3' 
  s.dependency "CryptoSwift"
end
