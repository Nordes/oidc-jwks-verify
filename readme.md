# oidc-jwks-verify
Code inspired from express-oidc-jwks-verify. The reason why this project exists was for my project that needed to connect and validate the JWT token without using the express library.

## Installation [Not yet deployed as a npm package]
The installation is simple:

```bash
npm install oidc-jwks-verify
```

## Usage
```js
var verifier = require 'oidc-jwks-verify';

var oidcValidator = new verifier({ issuer: 'http://my-identity-server/.well-known/...' }); // to be completed

// Somewhere in your code
oidcValidator.verify(myToken)
```

# License
MIT (Enjoy)