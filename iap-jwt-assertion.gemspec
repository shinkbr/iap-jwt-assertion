Gem::Specification.new do |s|
  s.name        = 'iap-jwt-assertion'
  s.version     = '0.0.0'
  s.summary     = "A Ruby gem for handling Google Identity Aware Proxy's signed JWT header."
  s.authors     = ["shinkbr"]
  s.email       = 'shinkbr@gmail.com'
  s.files       = ["lib/iap_jwt_assertion.rb"]
  s.homepage    = 'https://rubygems.org/gems/iap-jwt-assertion'
  s.license     = 'MIT'

  s.add_runtime_dependency 'jwt', '~> 2.2'
end
