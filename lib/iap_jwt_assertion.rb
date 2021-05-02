require 'net/http'
require 'json'
require 'jwt'

module IapJwtAssertion
  ALGORITHM = 'ES256'
  ASSERTION_HEADER_NAME = 'x-goog-iap-jwt-assertion'
  PUBLIC_KEYS_URL = 'https://www.gstatic.com/iap/verify/public_key'

  module_function

  def authenticate token
    kid = get_kid(token)
    pubkey = get_key(kid)

    return JWT.decode(token, pubkey, true, {algorithm: ALGORITHM})
  end

  def decode token
    kid = get_kid(token)
    pubkey = get_key(kid)

    return JWT.decode(token, pubkey, false, {algorithm: ALGORITHM})
  end

  def get_kid token
    JWT.decode(token, nil, false).last['kid']
  end

  def get_key kid
    if @public_keys.nil? || !@public_keys.has_key?(kid)
      @public_keys = fetch_public_keys

      if !@public_keys.has_key?(kid)
        raise "kid was not found in the list of public keys."
      end
    end

    return @public_keys[kid]
  end

  def fetch_public_keys
    response = Net::HTTP.get(URI(PUBLIC_KEYS_URL))
    response_hash = JSON.parse(response)
    public_keys = response_hash.map {|kid, pubkey| [kid, OpenSSL::PKey::EC.new(pubkey)]}.to_h

    return public_keys
  end
end
