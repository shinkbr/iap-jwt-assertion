require 'iap_jwt_assertion'

describe IapJwtAssertion do
  describe '#fetch_public_keys' do
    it 'returns hash' do
      expect(IapJwtAssertion::fetch_public_keys).to be_a(Hash)
    end

    it 'values are of type OpenSSL::PKey::EC' do
      expect(IapJwtAssertion::fetch_public_keys.values.first).to be_a(OpenSSL::PKey::EC)
    end
  end

  describe '#get_key' do
    # override fetch_public_keys so that we can test with our own keys
    before :each do
      IapJwtAssertion.instance_eval do
        def fetch_public_keys
          response = File.read('spec/test-keys/public_key.json')
          response_hash = JSON.parse(response)
          public_keys = response_hash.map {|kid, pubkey| [kid, OpenSSL::PKey::EC.new(pubkey)]}.to_h

          return public_keys
        end
      end
    end

    it 'returns the correct public key' do
      expect(IapJwtAssertion::get_key('public1').to_text).to eq("Public-Key: (256 bit)\npub:\n    04:28:ee:e1:ec:61:93:99:09:7c:e6:ae:f2:90:4a:\n    fc:04:ba:ef:4f:55:21:fd:96:d5:ca:45:6a:3e:1a:\n    bf:61:8f:8d:d1:4b:72:2d:91:0f:e1:76:b0:c3:a0:\n    5b:8d:69:98:a0:2e:7a:d1:9b:f5:42:c3:e3:84:60:\n    83:9f:ad:cf:02\nASN1 OID: secp256k1\n")
      expect(IapJwtAssertion::get_key('public3').to_text).to eq("Public-Key: (256 bit)\npub:\n    04:75:0f:bb:62:c7:a6:ab:9b:c9:d1:dc:06:31:40:\n    b7:ba:60:f6:e1:80:49:26:b0:6f:f0:8c:74:77:11:\n    b4:8a:b2:6d:92:95:a7:90:55:ad:73:ad:7f:ea:61:\n    61:59:cd:89:be:52:48:1a:eb:ea:15:92:1b:8b:cf:\n    f5:f8:c0:43:42\nASN1 OID: secp256k1\n")
    end
  end
end
