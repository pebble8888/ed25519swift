Pod::Spec.new do |s|
  s.name         = "ed25519swift"
  s.version      = "1.0.0"
  s.summary      = "ed25199 implementation by pure swift except sha512"
  s.homepage     = "https://github.com/pebble8888/ed25519swift"
  s.license      = "ZLIB"
  s.author             = { "pebble8888" => "pebble@gmail.com" }
  s.social_media_url   = "http://twitter.com/pebble8888"
  #
  # s.platform     = :ios
  # s.platform     = :ios, "5.0"

  #  When using multiple platforms
  # s.ios.deployment_target = "8.0"
  s.osx.deployment_target = "10.9"
  s.pod_target_xcconfig = { "SWIFT_VERSION" => "4.0" }

  s.source       = { :git => "https://github.com/pebble8888/ed25519swift.git", :tag => s.version.to_s }
  s.source_files  = "Ed25519macOS"
  s.dependency "BigInt", '~> 3.0' 
end
