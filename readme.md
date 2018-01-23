# oidc-jwks-verify
Code inspired from express-oidc-jwks-verify. The reason why this project exists was for my project that needed to connect and validate the JWT token without using the express library.

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

# License
MIT (Enjoy)