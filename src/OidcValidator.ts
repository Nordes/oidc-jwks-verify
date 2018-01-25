// ===============================================
// Inspiration from express-oidc-jwks-verify
// I couldn't use the express implementation within a WebSocket and I've decided to do a more generic implementation
// using the promises.
// ===============================================
import { disconnect } from "cluster";
import fs = require("fs");
import jwt = require("jsonwebtoken");
import NodeRSA = require("node-rsa");
import path = require("path");
import request = require("request");
import urlJoin = require("url-join"); // Should be removed. IMO, it's not worth havig that dependency
import { ValidatorResult, VerifyOptions, VerifyStatusCode } from "./Model/index";
import { OidcValidatorErrorMessage } from "./OidcValidatorErrorMessage";

// tslint:disable-next-line:no-var-requires
const x509 = require("x509");
const OidcDiscoveryPath = "/.well-known/openid-configuration";

/**
 * Class used to validate the OIDC JWT Token.
 */
export class OidcValidator {
  private oidcDiscoveryUri: string;
  private publicKey?: NodeRSA.Key;
  private hitCount: number = 0;
  private hitBeforeRefresh?: number = undefined;

  /**
   * Create an instance of the OIDC Validator
   * @param options Verify options containing the 'Issuer'
   */
  constructor(options: VerifyOptions) {
    if (!options) {
      throw new Error(OidcValidatorErrorMessage.OptionsMissing);
    }

    if (!options.issuer) {
      throw new Error(OidcValidatorErrorMessage.IssuerMissing);
    }

    if (!options.issuer.match(/^http:\/\/|^https:\/\/|^:\/\//)) { // Not sure for the "://"
      throw new Error(OidcValidatorErrorMessage.IssuerPrefixInvalid);
    }
    this.hitBeforeRefresh = options.hitBeforeRefresh;
    this.oidcDiscoveryUri = urlJoin(options.issuer, OidcDiscoveryPath);
  }

  /**
   * OidcDiscovery URI
   */
  get OidcDiscoveryUri(): string {
    return this.oidcDiscoveryUri;
  }

  /**
   * Verify the JWT against the OID issuer.
   * @param accessToken JWT Token coming from an Idenitty Server
   */
  public async verify(accessToken: string): Promise<ValidatorResult> {
    this.hitCount ++;

    if (!this.publicKey || (this.hitBeforeRefresh && this.hitCount >= this.hitBeforeRefresh)) {
      this.hitCount = 0;

      const result = await (this.FetchDiscoveryJwkUris()
        .then((jwksUri: string) => this.FetchJwkFirstX5C(jwksUri))
        .then((x5c: any) => this.SaveCertificateAndCheck(x5c, accessToken))
        .catch(async (err: any): Promise<any> => {
          // hack in order to force the check of the jwt when no x5c certificate. In fact it should be done differently.
          if (err) {
            return new ValidatorResult(VerifyStatusCode.Error, err);
          }
         }));

      return result;
    } else {
      // No pfx validation
      return this.jwtVerify(accessToken, this.publicKey);
    }
  }

  /**
   * Validate the JWT token.
   * @param token The JWT token
   * @param publicKey Public key used to certify the token
   */
  private async jwtVerify(token: string, publicKey?: NodeRSA.Key): Promise<ValidatorResult> {
    return new Promise<ValidatorResult>((resolve, reject) => {
      // format: 'PKCS8', <== the format does not exists
      jwt.verify(token, publicKey ? publicKey.toString() : "", { algorithms: ["RS256"] }, (errVerify: any) => {
        if (errVerify) { // Can also give an error like "TokenExpiredError"
          return resolve(new ValidatorResult(VerifyStatusCode.Unauthorized));
        }

        return resolve(new ValidatorResult(VerifyStatusCode.Authorized));
      });
    });
  }

  /**
   * Format the certificate
   * @param cert Certificate (public key)
   */
  private formatCertificate(cert: string): string {
    cert = cert.replace(/\n|-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/mig, "");
    let result: string = "";

    while (cert.length > 0) {
      if (cert.length > 64) {
        result += `\n${cert.substring(0, 64)}`;
        cert = cert.substring(64, cert.length);
      } else {
        result += `\n${cert}`;
        cert = "";
      }
    }

    return `-----BEGIN CERTIFICATE-----\n${result}\n-----END CERTIFICATE-----\n`;
  }

  /**
   * Fetch the discoery Jwk URI(s)
   */
  private FetchDiscoveryJwkUris() {
    return new Promise<string>((resolve, reject) => {
      request.get(this.oidcDiscoveryUri, (err: any, discoveryResponse: any) => {
        if (err) {
          return reject(err);
        }

        // Could add a check for body // json // jwks_uri
        return resolve(JSON.parse(discoveryResponse.body).jwks_uri);
      });
    });
  }

  /**
   * Fetch the JWK first X509 Certificate
   * @param jwksUri Uri where to get the certificates
   */
  private FetchJwkFirstX5C(jwksUri: string) {
    return new Promise<any>((resolve, reject) => {
      request.get(jwksUri, (error: any, jwksResponse: request.RequestResponse, body: any) => {
        if (error) {
          return reject(error);
        } else if (!jwksResponse || jwksResponse.statusCode !== 200) {
          return reject(OidcValidatorErrorMessage.OidJwkUnexpectedData);
        }
        try {
          const bodyObj = JSON.parse(body);

          if (!bodyObj || !bodyObj.keys || bodyObj.keys.length === 0) {
            // No key set on the server will generate the case of x5c not existing. Should we continue in the flow?
            return reject(OidcValidatorErrorMessage.OidJwkKeyNotFound);
          } else if (!bodyObj.keys[0].x5c || bodyObj.keys[0].x5c.length === 0) {
            // No x509 certificate, we still do have a RSA data, but it's not what we're looking for.
            return resolve(undefined);
          }

          return resolve(bodyObj.keys[0].x5c[0]); // Todo: We should instead return a list of x5c
        } catch (error) {
          return reject(OidcValidatorErrorMessage.OidJSONError + error);
        }
     });
    });
  }

  /**
   * Save the certificate and then validate the token against the certificate.
   * @param x5c Certificate
   * @param token OIDC Token
   */
  private SaveCertificateAndCheck(x5c: string, token: string): Promise<ValidatorResult> {
    const that = this;

    if (!x5c) {
      return this.jwtVerify(token, this.publicKey);
    }

    return new Promise<ValidatorResult>((resolve, reject) => {
      const x5cFormatted: string = that.formatCertificate(x5c);
      const certFilename: string = path.join(__dirname, "tmp.crt");

      // Library x509 only read from a file, not from anything else.
      // Here's how to do it, but we need a write access ¯\_(ツ)_/¯
      fs.writeFileSync(certFilename, x5cFormatted, { encoding: "UTF-8" });
      const parsedKey = x509.parseCert(certFilename); // Propose to x509 package to add a parse(bufer) or string.
      fs.unlinkSync(certFilename);

      const key = new NodeRSA();
      const nodeRSAKey: any = {
        e: parseInt(parsedKey.publicKey.e, 10),
        n: new Buffer(parsedKey.publicKey.n, "hex"),
      };

      key.importKey(nodeRSAKey, "components-public");

      that.publicKey = key.exportKey("public");

      return resolve(this.jwtVerify(token, that.publicKey));
    });
  }
}
