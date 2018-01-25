"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require("fs");
const jwt = require("jsonwebtoken");
const NodeRSA = require("node-rsa");
const path = require("path");
const request = require("request");
const urlJoin = require("url-join"); // Should be removed. IMO, it's not worth havig that dependency
const index_1 = require("./Model/index");
// tslint:disable-next-line:no-var-requires
const x509 = require("x509");
const OidcDiscoveryPath = "/.well-known/openid-configuration";
/**
 * Class used to validate the OIDC JWT Token.
 */
class OidcValidator {
    /**
     * Create an instance of the OIDC Validator
     * @param options Verify options containing the 'Issuer'
     */
    constructor(options) {
        if (!options) {
            throw new Error("Options are missing." /* OptionsMissing */);
        }
        if (!options.issuer) {
            throw new Error("Issuer option is missing." /* IssuerMissing */);
        }
        if (!options.issuer.match(/^http:\/\/|^https:\/\/|^:\/\//)) {
            throw new Error("Missing URI prefix within the 'issuer'." /* IssuerPrefixInvalid */);
        }
        this.oidcDiscoveryUri = urlJoin(options.issuer, OidcDiscoveryPath);
    }
    /**
     * OidcDiscovery URI
     */
    get OidcDiscoveryUri() {
        return this.oidcDiscoveryUri;
    }
    /**
     * Verify the JWT against the OID issuer.
     * @param token JWT Token coming from an Idenitty Server
     */
    verify(token) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.publicKey) {
                // tslint:disable-next-line:prefer-const
                let thatPublicKey = this.publicKey;
                const result = yield (this.FetchDiscoveryJwkUris()
                    .then((jwksUri) => this.FetchJwkFirstX5C(jwksUri))
                    .then((x5c) => this.SaveCertificateAndCheck(x5c, token))
                    .catch((err) => __awaiter(this, void 0, void 0, function* () {
                    // hack in order to force the check of the jwt when no x5c certificate. In fact it should be done differently.
                    if (err) {
                        return new index_1.ValidatorResult(index_1.VerifyStatusCode.Error, err);
                    }
                })));
                this.publicKey = thatPublicKey;
                return result;
            }
            else {
                // No pfx validation
                return this.jwtVerify(token, this.publicKey);
            }
        });
    }
    /**
     * Validate the JWT token.
     * @param token The JWT token
     * @param publicKey Public key used to certify the token
     */
    jwtVerify(token, publicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                // format: 'PKCS8', <== the format does not exists
                jwt.verify(token, publicKey ? publicKey.toString() : "", { algorithms: ["RS256"] }, (errVerify) => {
                    if (errVerify) {
                        return resolve(new index_1.ValidatorResult(index_1.VerifyStatusCode.Unauthorized));
                    }
                    return resolve(new index_1.ValidatorResult(index_1.VerifyStatusCode.Authorized));
                });
            });
        });
    }
    /**
     * Format the certificate
     * @param cert Certificate (public key)
     */
    formatCertificate(cert) {
        cert = cert.replace(/\n|-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/mig, "");
        let result = "";
        while (cert.length > 0) {
            if (cert.length > 64) {
                result += `\n${cert.substring(0, 64)}`;
                cert = cert.substring(64, cert.length);
            }
            else {
                result += `\n${cert}`;
                cert = "";
            }
        }
        return `-----BEGIN CERTIFICATE-----\n${result}\n-----END CERTIFICATE-----\n`;
    }
    /**
     * Fetch the discoery Jwk URI(s)
     */
    FetchDiscoveryJwkUris() {
        return new Promise((resolve, reject) => {
            request.get(this.oidcDiscoveryUri, (err, discoveryResponse) => {
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
    FetchJwkFirstX5C(jwksUri) {
        return new Promise((resolve, reject) => {
            request.get(jwksUri, (error, jwksResponse, body) => {
                if (error) {
                    return reject(error);
                }
                else if (!jwksResponse || jwksResponse.statusCode !== 200) {
                    return reject("Something went wrong in order to get the JWK x509 Certificate." /* OidJwkUnexpectedData */);
                }
                try {
                    const bodyObj = JSON.parse(body);
                    if (!bodyObj || !bodyObj.keys
                        || bodyObj.keys.length === 0) {
                        // No key set on the server will generate the case of x5c not existing. Should we continue in the flow?
                        return reject("Something went wrong. We are not able to find any x509 certificate from the response." /* OidJwkKeyNotFound */);
                    }
                    else if (!bodyObj.keys[0].x5c || bodyObj.keys[0].x5c.length === 0) {
                        return resolve(undefined);
                    }
                    return resolve(body.keys[0].x5c[0]); // Todo: We should instead return a list of x5c
                }
                catch (error) {
                    return reject("Something went wrong while parsing the JSON from the JWK: " /* OidJSONError */ + error);
                }
            });
        });
    }
    /**
     * Save the certificate and then validate the token against the certificate.
     * @param x5c Certificate
     * @param token OIDC Token
     */
    SaveCertificateAndCheck(x5c, token) {
        const that = this;
        if (!x5c) {
            return this.jwtVerify(token, that.publicKey);
        }
        return new Promise((resolve, reject) => {
            const x5cFormatted = that.formatCertificate(x5c);
            const certFilename = path.join(__dirname, "tmp.crt");
            fs.writeFileSync(certFilename, x5cFormatted, { encoding: "UTF-8" });
            const parsedKey = x509.parseCert(certFilename);
            const key = new NodeRSA();
            const nodeRSAKey = {
                e: parseInt(parsedKey.publicKey.e, 10),
                n: new Buffer(parsedKey.publicKey.n, "hex"),
            };
            key.importKey(nodeRSAKey, "components-public");
            that.publicKey = key.exportKey("public");
            return resolve(this.jwtVerify(token, that.publicKey));
        });
    }
}
exports.OidcValidator = OidcValidator;
//# sourceMappingURL=OidcValidator.js.map