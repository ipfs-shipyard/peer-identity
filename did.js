const UUID = require('uuid/v4');

class DID {

  constructor(peerId, person, id, jwk) {

    this.peerId = peerId;
    this.id = id || `did:ipfspeerstar:${UUID()}`;

    this.obj = Object.assign({
      '@context': ['https://w3id.org/did/v1', 'https://w3id.org/security/v1', 'https://schema.org'],
      '@type': 'Person',
      id: this.id
    }, person);

    if (jwk) {
      this.setPublicJWK(jwk);
    }
  }

  setId(id) {

    this.id = id;
    this.obj.id = id;
  }

  async sign() {

    return  await this.peerId.sign(JSON.stringify(this.obj));
  }

  setPublicJWK(jwk) {

    this.obj.publicKey = {
      id: this.id,
      type: 'RsaVerificationKey2018',
      owner: this.id,
      publicKeyJwk: jwk
    }
  }

}

module.exports = DID;
