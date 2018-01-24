# oidc-jwks-verify
![](https://api.travis-ci.org/Nordes/oidc-jwks-verify.svg?branch=master)

Code inspired from [express-oidc-jwks-verify](https://github.com/Nordes/oidc-jwks-verify). The reason why this project exists was for my project that needed to connect and validate the JWT token without using the express library.

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
oidcValidator.verify(token).then((result: VerifyStatusCode) => {
  // Result returns [Authorized|Unauthorized|Unknown] (Unknown should never happen)
  console.log(result)
})
```

## When building locally
### Build Dependencies
Package: __x509__
- node-gyp (python... https://github.com/nodejs/node-gyp if not already installed)
- msbuild 14 (vs 2015?... https://www.microsoft.com/en-us/download/confirmation.aspx?id=48159 if not already installed)
- openSSL (Otherwise an error... `LINK : fatal error LNK1181: cannot open input file 'C:\OpenSSL-Win64\lib\libeay32.lib' [C:\...\oidc-jwks-verify\node_modules\x509\build\x509.vcxproj]
gyp ERR! build error` available at https://slproweb.com/products/Win32OpenSSL.html and https://github.com/ethereumjs/ethereumjs-util/issues/43 (see for the libeay32.lib link at the end))

# License
MIT (Enjoy)