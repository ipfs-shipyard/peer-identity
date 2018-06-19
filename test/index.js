const lab = exports.lab = require('lab').script();
const { expect } = require('code');
const { describe, it, before, after } = lab;

const PeerIdentity = require('../index.js');

describe('generate keys', () => {

  let peerIdentity;
  let proof;

  before(() => {

    peerIdentity = new PeerIdentity();
  });

  it('generates new keys', async () => {

    const keyPair = await peerIdentity.generateSessionKeys();
    expect(keyPair).to.include('publicKey');
    expect(keyPair).to.include('privateKey');
  });

  it('saves keys', async () => {

    const saved = await peerIdentity.save();
    expect(saved).to.be.true();
  });

  it('loads keys', async () => {

    let id = peerIdentity.session.id;
    peerIdentity = new PeerIdentity();
    expect(peerIdentity.state.hasSession).to.be.false();
    const loaded = await peerIdentity.load();
    expect(loaded).to.be.true();
    expect(peerIdentity.state.hasSession).to.be.true();
    expect(peerIdentity.state.inLocalStorage).to.be.true();
    expect(id).to.equal(peerIdentity.session.id);
  });

  it('create signature and verify', async () => {

    const data = 'How are you?';
    const { data58, sig } = await peerIdentity.sign(data);
    const { verified, error } = await peerIdentity.verify(data58, peerIdentity.session.id, sig);
    expect(verified).to.be.true();
  });

  it('export DID', async () => {

    const { did, proof } = await peerIdentity.exportProof(peerIdentity.session.id);
    const success = await peerIdentity.importProof(proof);
    expect(success).to.be.true();
  });

});
