require 'iap_jwt_assertion'

describe IapJwtAssertion do
  # override fetch_public_keys so that we can test with our own keys
  def override_fetch_public_keys
    IapJwtAssertion.instance_eval do
      def fetch_public_keys
        response = File.read('spec/test-keys/public_key.json')
        response_hash = JSON.parse(response)
        public_keys = response_hash.map {|kid, pubkey| [kid, OpenSSL::PKey::EC.new(pubkey)]}.to_h

        return public_keys
      end
    end
  end

  describe '#fetch_public_keys' do
    it 'returns hash' do
      expect(IapJwtAssertion::fetch_public_keys).to be_a(Hash)
    end

    it 'values are of type OpenSSL::PKey::EC' do
      expect(IapJwtAssertion::fetch_public_keys.values.first).to be_a(OpenSSL::PKey::EC)
    end
  end

  describe '#get_key' do
    before :each do
      override_fetch_public_keys
    end

    it 'returns the correct public key' do
      expect(IapJwtAssertion::get_key('test1').to_text).to eq("Public-Key: (256 bit)\npub:\n    04:fd:24:72:43:de:57:00:db:38:0e:9a:a9:bf:ff:\n    78:3a:5b:ff:4b:a3:6f:e2:5d:bd:ca:9a:2d:b6:11:\n    a8:c0:a0:60:37:db:9b:8f:70:66:34:31:9f:20:30:\n    64:a0:6e:d7:39:8b:e0:f5:4a:06:a7:79:e3:e9:1b:\n    d7:17:99:99:19\nASN1 OID: prime256v1\nNIST CURVE: P-256\n")
      expect(IapJwtAssertion::get_key('test3').to_text).to eq("Public-Key: (256 bit)\npub:\n    04:ea:87:83:95:76:8e:52:43:42:b1:a7:32:d2:f9:\n    b3:62:10:87:df:d3:1b:df:51:80:5b:ba:ec:c1:c9:\n    ea:f0:ed:7c:4c:3d:5a:11:97:46:34:24:77:77:3d:\n    c5:9e:4d:d9:cb:97:6b:03:fd:e1:a0:11:a6:0c:71:\n    11:87:42:16:a1\nASN1 OID: prime256v1\nNIST CURVE: P-256\n")
    end
  end

  describe '#decode' do
    it 'decodes JWT' do
      kid = 'test1'
      file = File.read('spec/test-keys/private_key.json')
      file_hash = JSON.parse(file)
      private_keys = file_hash.map {|kid, pubkey| [kid, OpenSSL::PKey::EC.new(pubkey)]}.to_h

      payload = {
        'aud': '/projects/123456789012/global/backendServices/1234567890123456789',
        'email': 'username@example.com',
        'exp': (Time.now + 300).to_i,
        'hd': 'example.com',
        'iat': (Time.now - 10).to_i,
        'iss': 'https://cloud.google.com/iap',
        'sub': 'accounts.google.com:123456789012345678901'
      }

      token = JWT.encode payload, private_keys[kid], algorithm='ES256', header_fields={kid: kid}
      decoded_token = IapJwtAssertion::decode token

      expect(decoded_token.first['email']).to eq('username@example.com')
      expect(decoded_token.last['kid']).to eq(kid)
    end
  end

  describe '#get_kid' do
    it 'retrieves kid from JWT' do
      file = File.read('spec/test-keys/private_key.json')
      file_hash = JSON.parse(file)
      private_keys = file_hash.map {|kid, pubkey| [kid, OpenSSL::PKey::EC.new(pubkey)]}.to_h

      payload = {
        'aud': '/projects/123456789012/global/backendServices/1234567890123456789',
        'email': 'username@example.com',
        'exp': (Time.now + 300).to_i,
        'hd': 'example.com',
        'iat': (Time.now - 10).to_i,
        'iss': 'https://cloud.google.com/iap',
        'sub': 'accounts.google.com:123456789012345678901'
      }

      ['test1', 'test3'].each do |kid|
        token = JWT.encode payload, private_keys[kid], algorithm='ES256', header_fields={kid: kid}
        decoded_kid = IapJwtAssertion::get_kid token

        expect(decoded_kid).to eq(kid)
      end
    end
  end
end
