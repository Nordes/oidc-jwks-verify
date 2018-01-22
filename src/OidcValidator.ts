// ===============================================
// Inspiration from express-oidc-jwks-verify
// I couldn't use the express implementation within a WebSocket and I've decided to do a more generic implementation
// using the promises.
// ===============================================
const fs = require('fs')
const x509 = require('x509')
const NodeRSA = require('node-rsa')
import { VerifyOptions, VerifyStatusCode } from './Models'
import jwt = require('jsonwebtoken')
import * as path from 'path'
import request = require('request')
import urlJoin = require('url-join')

const OIDC_DISCOVERY_PATH = '/.well-known/openid-configuration'

const jwtVerify = async (token: string, publicKey: any): Promise<VerifyStatusCode> => {
  return new Promise<VerifyStatusCode>((resolve, reject) => {
    jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (errVerify: any) => { // format: 'PKCS8', <== the format does not exists
      if (errVerify) {
        return resolve(VerifyStatusCode.Unauthorized)
      }

      return resolve(VerifyStatusCode.Authorized)
    })
  })
}

export class OidcValidator {
  private _OidcDiscoveryUri: string
  private _publicKey: string

  constructor(options: VerifyOptions) {
    if (!options) {
      throw new Error('Options are missing.')
    }

    if (!options.issuer) {
      throw new Error('Issuer option is missing.')
    }

    this._OidcDiscoveryUri = urlJoin(options.issuer, OIDC_DISCOVERY_PATH)
  }

  get OidcDiscoveryUri(): string {
    return this._OidcDiscoveryUri;
  }

  public async verify(token: string): Promise<VerifyStatusCode> {
    if (!this._publicKey) {

      let thatPublicKey: string = this._publicKey
      let result = await (this.FetchDiscoveryJwkUris()
        .then((jwksUri: string) => this.FetchJwkFirstX5C(jwksUri))
        .then((x5c: any) => this.SaveCertificate(x5c, token))
        .catch(async (err: any): Promise<any> => {
          if (err) {
            console.log(`Not able to verify, error: ${err}`)
          }

          return jwtVerify(token, thatPublicKey)
        }))

      this._publicKey = thatPublicKey

      return result
    } else {
      // No pfx validation
      return jwtVerify(token, this._publicKey)
    }
  }

  private formatCertificate (cert: string) {
    cert = cert.replace(/\n|-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/mig, '')
  
    let result: string = ''
  
    while (cert.length > 0) {
      if (cert.length > 64) {
        result += `\n${cert.substring(0, 64)}`
        cert = cert.substring(64, cert.length)
      } else {
        result += `\n${cert}`
        cert = ''
      }
    }
  
    result = `-----BEGIN CERTIFICATE-----\n${result}\n-----END CERTIFICATE-----\n`
  
    return result
  }
  
  private FetchDiscoveryJwkUris (){
    return new Promise<string>((resolve, reject) => {
      request.get(this._OidcDiscoveryUri, (err: any, discoveryResponse: any) => {
        if (err) {
          return reject(err)
        }

        return resolve(JSON.parse(discoveryResponse.body).jwks_uri)
      })
    })
  }

  private FetchJwkFirstX5C(jwksUri: string) {
    return new Promise<any>((resolve, reject) => {
      request.get(jwksUri, (err: any, jwksResponse: any) => {
        if (err) {
          return reject(err)
        }

        return resolve(JSON.parse(jwksResponse.body).keys[0].x5c[0])
      })
    })
  }

  /**
   * Save the certificate and then validate the token against the certificate.
   * @param x5c Certificate
   * @param token OIDC Token
   */
  private SaveCertificate(x5c: any, token: string) {
    var that = this
    return new Promise<VerifyStatusCode>((resolve, reject) => {
      const x5cFormatted = that.formatCertificate(x5c)
      const certFilename = path.join(__dirname, 'tmp.crt')

      fs.writeFileSync(certFilename, x5cFormatted, { encoding: 'UTF-8' })
      const parsedKey = x509.parseCert(certFilename)
      const key = new NodeRSA()

      key.importKey({
        n: new Buffer(parsedKey.publicKey.n, 'hex'),
        e: parseInt(parsedKey.publicKey.e, 10)
      }, 'components-public')

      that._publicKey = key.exportKey('public')

      resolve(jwtVerify(token, that._publicKey))
    })
  }
}
