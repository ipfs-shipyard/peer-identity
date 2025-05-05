# PeerIdentity
## Install

`npm install peer-identity`

## Usage

```js
const PeerIdentity = require('peer-identity');

const peerIdentity = new PeerIdentity();
```

## Webpack

Use the ignore plugin to ignore `node-localstorage` and `node-webcrypto-ossl` when building for the browser.

## API

### Initialize w/ Config

```js
new PeerIdentity({
  localStoragePath: '/tmp/myLocalStorage'
});
```

Config Options:

* localStoragePath: file to usage for `node-localstorage` if using node rather than browser

### function generateSessionKeys

Generates signing keys. Stores in `this.sesssion.publicKey` and `this.session.privateKey`

returns `Promise(keyPair)`

```js
const keyPair = await peerIdentity.generateSessionKeys();
```

### function loadFromLocalStorage / load

Loads signing keys from localStorage.

returns `Promise(bool)`

```js
const loaded = await peerIdentity.loadFromLocalStorage();
```

### function saveToLocalStorage / save

Saves current signing keys to localStorage.

returns `Promise(bool)`

```js
const saved = await peerIdentity.saveToLocalStorage();
```

### function addSession

Adds a peer session to be used by verify functions.

arguments:
* id string session/did id
* jwk json string or object

returns `Promise(bool)`

```js
const added = await peerIdentity.addSession('id:lkajdsflkjasdf', jwk);
```

### function signData

Signs data with the session signing keys.

arguments:
* data string or json object

returns `Promise(\`${Base58(data)}.${Base58(id)}.sig\`)`

### verifyData

Verifies signature and decodes data.

arguments:
* data and sig in form: `${Base58(data)}.${Base58(id)}.sig`

returns

```js
Promise({
  data, //decoded base58
  id, // decoded base58
  sig,
  error, // including `"SESSION_NOT_FOUND"`
})
```

### exportDID

TODO

### loadPeerFromDID

TODO
