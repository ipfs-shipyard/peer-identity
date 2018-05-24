'use strict';

const Base58 = require('bs58');
const isBrowser = new Function("try {return this===window;}catch(e){ return false;}")();
const UUID = require('uuid/v4');
const DID = require('./did.js');

const ALGO = { name: 'RSASSA-PKCS1-v1_5' };
const CAPS = ['sign', 'verify'];
const HASH = { name: 'SHA-512' };
const CONFIG_DEFAULTS = {
};

function toArrayBuffer(buf) {
  var ab = new ArrayBuffer(buf.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buf.length; ++i) {
	  view[i] = buf[i];
  }
  return ab;
}

class PeerIdentity {

  constructor(config) {

    this.peer = {
      sessions: {}
    };
    this.config = {...CONFIG_DEFAULTS, ...config};
    this.session = {
      privateKey: null,
      publicKey: null,
      id: null
    };
    this.state = {
      hasSession: false,
      inLocalStorage: false
    };
    this.save = this.saveToLocalStorage;
    this.load = this.loadFromLocalStorage;

    if (!isBrowser) {
      const Path = require('path');
      const LocalStorage = require('node-localstorage').LocalStorage;
      this.localStorage = new LocalStorage(this.config.localStoragePath || Path.join(__dirname, 'scratch'));
      const Crypto = require('node-webcrypto-ossl');
      this.subtle = new Crypto().subtle;
    } else {
      this.localStorage = window.localStorage;
      this.subtle = crypto.subtle;
    }
  }

  async loadFromLocalStorage() {

    const privKeyString = this.localStorage.getItem('sessionPrivateJWK');
    const pubKeyString = this.localStorage.getItem('sessionPublicJWK');
    //this.sessionProof = this.localStorage.getItem('sessionProof');
    this.session.id = this.localStorage.getItem('sessionId');
    if (privKeyString) {
      this.session.privateKey = await this.subtle.importKey('jwk', JSON.parse(privKeyString), {
        name: ALGO.name,
        hash: HASH
      }, true, ['sign']);
    }
    if (pubKeyString) {
      this.session.publicKey = await this.subtle.importKey('jwk', JSON.parse(pubKeyString), {
        name: ALGO.name,
        hash: HASH
      }, true, ['verify']);
    }
    if (!pubKeyString && !privKeyString) {
      return false;
    }
    this.state.inLocalStorage = true;
    this.state.hasSession = true;
    this.peer[this.session.id] = this.session;
    return true;
  }

  async addSession(id, jwk) {

    if (typeof jwk === 'string') {
      jwk = JSON.parse(jwk);
    }
    this.peer.sessions[id] = await this.subtle.importKey('jwk', jwk, {
      name: ALGO.name,
      hash: HASH
    }, true, ['verify']);
    return true;
  }

  async saveToLocalStorage() {

    if (this.state.hasSession) {

      const privExport = await this.subtle.exportKey('jwk', this.session.privateKey);
      const pubExport = await this.subtle.exportKey('jwk', this.session.publicKey);
      this.localStorage.setItem('sessionPrivateJWK', JSON.stringify(privExport));
      this.localStorage.setItem('sessionPublicJWK', JSON.stringify(pubExport));
      //window.localStorage.setItem('sessionProof', this.sessionProof);
      this.localStorage.setItem('sessionId', this.session.id);
      this.state.inLocalStorage = true;
      return true;
    }
    return false;
  }

  async loadPeerFromDID() {
  }

  async generateSessionKeys() {

    this.session.id = `did:ipfspeer*:${UUID()}`;
    const keyPair = await this.subtle.generateKey({
      name: ALGO.name,
      modulusLength: 1024,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: HASH
    }, true, CAPS);

    this.session.privateKey = keyPair.privateKey;
    this.session.publicKey = keyPair.publicKey;
    this.state.hasSession = true;
    this.peer[this.session.id] = this.session;

    return keyPair;
  }

  async exportProof() {

    const session = this.session;
    const jwk = await this.subtle.exportKey('jwk', session.publicKey);

    const did = new DID(this);
    did.setId(session.id);
    did.setPublicJWK(jwk);
    const { data58, sig } = await did.sign();
    const proof = `${data58}.${sig}`;
    return {
      did: did.obj,
      proof
    };
  }

  async importProof(proof) {

    const [ did58, sig58 ] = proof.split('.');
    const didJSON = Base58.decode(did58).toString('utf8');
    const didObj = JSON.parse(didJSON);
    const did = new DID(this);

    let jwk = null;
    if (Array.isArray(didObj.publicKey)) {
      jwk = didObj.publicKey[0];
    } else {
      jwk = didObj.publicKey;
    }
    jwk = jwk.publicKeyJwk;

    const publicKey = await this.subtle.importKey('jwk', jwk, {
      name: ALGO.name,
      hash: HASH
    }, true, ['verify']);

    const sigBuffer = Base58.decode(sig58);
    const sigArr = toArrayBuffer(sigBuffer);
    const dataBuffer = Buffer.from(did58);
    const dataArr = toArrayBuffer(dataBuffer);
    const verified = await this.subtle.verify(ALGO, publicKey, sigArr, dataArr);

    if(!verified) {
      return false;
    }

    if (!peer[didObj.id]) {
      this.peer[didObj.id] = {
        id: didObj.id,
        publicKey: publicKey
      };
    }
    return true;
  }

  async signObject(data) {

    return this.signBuffer(Buffer.from(JSON.stringify(data), 'utf8'));
  }

  async signString(data) {

    return this.signBuffer(Buffer.from(data, 'utf8'));
  }

  async signBuffer(data) {

    if (!this.state.hasSession) {
      await this.generateSessionKeys();
      await this.saveToLocalStorage();
    }
    const data58 = Base58.encode(data);
    const dataBuffer = Buffer.from(data58);
    const dataArr = toArrayBuffer(dataBuffer);
    const sigArr = await this.subtle.sign(ALGO, this.session.privateKey, dataArr, 'utf8');
    const sig = Base58.encode(Buffer.from(sigArr));

    return {
      data58,
      sig
    };
  }

  async verify(data58, id, sig) {

    if (!this.peer.hasOwnProperty(id)) {
      return {
        error: 'SESSION_NOT_FOUND'
      };
    }
    const publicKey = this.peer[id].publicKey;
    const sigBuffer = Base58.decode(sig);
    const sigArr = toArrayBuffer(sigBuffer);
    const dataBuffer = Buffer.from(data58);
    const dataArr = toArrayBuffer(dataBuffer);
    const verified = await this.subtle.verify(ALGO, publicKey, sigArr, dataArr);
    return {
      data58,
      id,
      sig,
      verified
    }
  }

  async verifyData(signedData) {

    const [data58, id58, sig] = signedData.split('.');
    const data = Base58.decode(data58);
    const id = Base58.decode(id58);

    if (!this.peer.sessions.hasOwnProperty(id)) {
      return {
        error: 'SESSION_NOT_FOUND'
      };
    }
    const publicKey = this.peer.sessions[id];
    const verified = await this.subtle.verify(ALGO, publicKey, sig, Buffer.from(data, 'utf8'));
    return {
      data,
      id,
      sig,
      verified
    }
  }

}

module.exports = PeerIdentity;
