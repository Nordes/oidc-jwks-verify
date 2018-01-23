// ===============================================
// Inspiration from express-oidc-jwks-verify
// I couldn't use the express implementation within a WebSocket and I've decided to do a more generic implementation
// using the promises.
// ===============================================
import fs = require("fs");
import jwt = require("jsonwebtoken");
import NodeRSA = require("node-rsa");
import * as path from "path";
import request = require("request");
import urlJoin = require("url-join");
import { VerifyOptions, VerifyStatusCode } from "./Model";
// tslint:disable-next-line:no-var-requires
const x509 = require("x509");

const OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration";

/**
 * Validate the JWT token.
 * @param token The JWT token
 * @param publicKey Public key used to certify the token
 */
const jwtVerify = async (token: string, publicKey: NodeRSA.Key): Promise<VerifyStatusCode> => {
  return new Promise<VerifyStatusCode>((resolve, reject) => {
    // format: 'PKCS8', <== the format does not exists
    jwt.verify(token, publicKey.toString(), { algorithms: ["RS256"] }, (errVerify: any) => {
      if (errVerify) {
        return resolve(VerifyStatusCode.Unauthorized);
      }

      return resolve(VerifyStatusCode.Authorized);
    });
  });
};

/**
 * Class used to validate the OIDC JWT Token.
 */
export class OidcValidator {
  private oidcDiscoveryUri: string;
  private publicKey: NodeRSA.Key;

  /**
   * Create an instance of the OIDC Validator
   * @param options Verify options containing the 'Issuer'
   */
  constructor(options: VerifyOptions) {
    if (!options) {
      throw new Error("Options are missing.");
    }

    if (!options.issuer) {
      throw new Error("Issuer option is missing.");
    }

    this.oidcDiscoveryUri = urlJoin(options.issuer, OIDC_DISCOVERY_PATH);
  }

  /**
   * OidcDiscovery URI
   */
  get OidcDiscoveryUri(): string {
    return this.oidcDiscoveryUri;
  }

  /**
   * Verify the JWT against the OID issuer.
   * @param token JWT Token coming from an Idenitty Server
   */
  public async verify(token: string): Promise<VerifyStatusCode> {
    if (!this.publicKey) {

      // tslint:disable-next-line:prefer-const
      let thatPublicKey: NodeRSA.Key = this.publicKey;
      const result = await (this.FetchDiscoveryJwkUris()
        .then((jwksUri: string) => this.FetchJwkFirstX5C(jwksUri))
        .then((x5c: any) => this.SaveCertificate(x5c, token))
        .catch(async (err: any): Promise<any> => {
          if (err) {
            // tslint:disable-next-line:no-console
            throw new Error(`Not able to verify, error: ${err}`);
          }

          return jwtVerify(token, thatPublicKey);
        }));

      this.publicKey = thatPublicKey;

      return result;
    } else {
      // No pfx validation
      return jwtVerify(token, this.publicKey);
    }
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
      request.get(jwksUri, (err: any, jwksResponse: any) => {
        if (err) {
          return reject(err);
        }

        return resolve(JSON.parse(jwksResponse.body).keys[0].x5c[0]);
      });
    });
  }

  /**
   * Save the certificate and then validate the token against the certificate.
   * @param x5c Certificate
   * @param token OIDC Token
   */
  private SaveCertificate(x5c: string, token: string): Promise<VerifyStatusCode> {
    const that = this;

    return new Promise<VerifyStatusCode>((resolve, reject) => {
      const x5cFormatted: string = that.formatCertificate(x5c);
      const certFilename: string = path.join(__dirname, "tmp.crt");

      fs.writeFileSync(certFilename, x5cFormatted, { encoding: "UTF-8" });

      const parsedKey = x509.parseCert(certFilename);
      const key = new NodeRSA();
      const nodeRSAKey: any = {
        e: parseInt(parsedKey.publicKey.e, 10),
        n: new Buffer(parsedKey.publicKey.n, "hex"),
      };

      key.importKey(nodeRSAKey, "components-public");

      that.publicKey = key.exportKey("public");

      resolve(jwtVerify(token, that.publicKey));
    });
  }
}
