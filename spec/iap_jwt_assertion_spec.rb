require 'iap_jwt_assertion'

describe IapJwtAssertion do
  describe '.fetch_public_keys' do
    it 'returns hash' do
      expect(IapJwtAssertion::fetch_public_keys).to be_a(Hash)
    end

    it 'values are of type OpenSSL::PKey::EC' do
      expect(IapJwtAssertion::fetch_public_keys.values.first).to be_a(OpenSSL::PKey::EC)
    end
  end
end
