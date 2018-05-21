'use strict';

const Base58 = require('base58');
const isBrowser = new Function("try {return this===window;}catch(e){ return false;}")();
const UUID = require('uuid/v4');

const ALGO = { name: 'RSASSA-PKCS1-v1_5' };
const CAPS = ['sign', 'verify'];
const HASH = { name: 'SHA-512' };
const CONFIG_DEFAULTS = {
};

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

    this.session.id = UUID();
    const keyPair = await this.subtle.generateKey({
      name: ALGO.name,
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: HASH
    }, true, CAPS);

    this.session.privateKey = keyPair.privateKey;
    this.session.publicKey = keyPair.publicKey;
    this.state.hasSession = true;

    return keyPair;
  }

  async exportDID() {
  }

  async signData(data) {

    if (!this.state.hasSession) {
      await this.generateSessionKeys();
      await this.saveToLocalStorage();
    }
    if (typeof data === 'object') {
      data = JSON.stringify(data);
    }
    data = Base58.encode(data);
    const sigArr = await this.subtle.sign(ALGO, this.session.privateKey, Buffer.from(data), 'utf8');
    //sig = Base58.encode(sigArr);
    const sig = btoa(
      new Uint8Array(sigArr).reduce((data, byte) => data + String.fromCharCode(byte), '')
    );
    return `${data}.${Base58.encode(this.session.id)}.${sig}`;
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
