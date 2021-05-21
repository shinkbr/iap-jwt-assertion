# iap-jwt-assertion

A Ruby gem for parsing and verifying Google Identity Aware Proxy's [signed JWT header](https://cloud.google.com/iap/docs/signed-headers-howto).

## Installing
### Using Rubygems:
```
gem install iap-jwt-assertion
```

### Using Bundler:
Add the following to your Gemfile.
```
gem 'iap-jwt-assertion'
```

And run `bundle install`

## Usage
### Example usage for Ruby on Rails:
```ruby
class ApplicationController < ActionController::Base
  before_action :authenticate_iap_jwt_assertion

  def authenticate_iap_jwt_assertion
    unless IapJwtAssertion::authenticate? request.headers['x-goog-iap-jwt-assertion'], aud: '/projects/123456789012/global/backendServices/1234567890123456789'
      head 403
    end
  end
end
```

### Extracting payload from the JWT header
```ruby
payload, header = IapJwtAssertion::decode request.headers['x-goog-iap-jwt-assertion']
# => [{"aud"=>"/projects/123456789012/global/backendServices/1234567890123456789", "email"=>"username@example.com", "exp"=>1615284964, "hd"=>"example.com", "iat"=>1615284364, "iss"=>"https://cloud.google.com/iap", "sub"=>"accounts.google.com:123456789012345678901"}, {"kid"=>"0oeLcQ", "alg"=>"ES256"}]

payload['email']
# => "username@example.com"
```
