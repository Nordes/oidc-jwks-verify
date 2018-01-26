# oidc-jwks-verify
![](https://api.travis-ci.org/Nordes/oidc-jwks-verify.svg?branch=master) 
[![Coverage Status](https://coveralls.io/repos/github/Nordes/oidc-jwks-verify/badge.svg?branch=master)](https://coveralls.io/github/Nordes/oidc-jwks-verify?branch=master) [![npm version](https://badge.fury.io/js/oidc-jwks-verify.svg)](https://badge.fury.io/js/oidc-jwks-verify)

Code inspired from [express-oidc-jwks-verify](https://github.com/Nordes/oidc-jwks-verify). The reason why this project exists was for my project that needed to connect and validate the JWT token without using the express library.

# Scenario
1. Server is having a Validation Key to validate the user tokens ([AddValidationKey](http://docs.identityserver.io/en/release/topics/startup.html#refstartupkeymaterial) in IdentityServer)
2. The client want to validate the token against the server (basically a key check)
3. We validate the id_token and then consider the user really authenticated

## Installation [Not yet deployed as a npm package]
The installation is simple:

```bash
npm install oidc-jwks-verify
```

## Usage
```js
import { VerifyOidc, VerifyStatusCode } from 'oidc-jwks-verify'
let oidcValidator = new VerifyOidc({ issuer: `http://localhost:5000` })

// Somewhere in your code
oidcValidator.verify(accessToken).then((result: VerifyStatusCode) => {
  // Result returns [Authorized|Unauthorized|Unknown] (Unknown should never happen)
  console.log(result)
})
```

## When building locally
```bash
$ npm install
$ npm run build
$ # Now a folder called lib will be available.
```

### Build Dependencies
Package: __x509__
- node-gyp (python... https://github.com/nodejs/node-gyp if not already installed)
- msbuild 14 (vs 2015?... https://www.microsoft.com/en-us/download/confirmation.aspx?id=48159 if not already installed)
- openSSL (Otherwise an error... `LINK : fatal error LNK1181: cannot open input file 'C:\OpenSSL-Win64\lib\libeay32.lib' [C:\...\oidc-jwks-verify\node_modules\x509\build\x509.vcxproj]
gyp ERR! build error` available at https://slproweb.com/products/Win32OpenSSL.html and https://github.com/ethereumjs/ethereumjs-util/issues/43 (see for the libeay32.lib link at the end))

## Running tests?
```bash
npm run test
```
> Some tests might fail since you need to update the token to be validated. The default max-age for the token is 30 minutes. If you want to create a new token, please create a certificate (pfx) add it to your identity server and then get the well known data and update the mock. I can't fake the x509 validation process. I would say, that at this moment I don't know how to mock it.

# License
MIT (Enjoy)