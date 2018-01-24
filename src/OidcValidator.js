"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var fs = require("fs");
var jwt = require("jsonwebtoken");
var NodeRSA = require("node-rsa");
var path = require("path");
var request = require("request");
var urlJoin = require("url-join"); // Should be removed. IMO, it's not worth havig that dependency
var Model_1 = require("./Model");
// tslint:disable-next-line:no-var-requires
var x509 = require("x509");
var OidcDiscoveryPath = "/.well-known/openid-configuration";
/**
 * Class used to validate the OIDC JWT Token.
 */
var OidcValidator = /** @class */ (function () {
    /**
     * Create an instance of the OIDC Validator
     * @param options Verify options containing the 'Issuer'
     */
    function OidcValidator(options) {
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
    Object.defineProperty(OidcValidator.prototype, "OidcDiscoveryUri", {
        /**
         * OidcDiscovery URI
         */
        get: function () {
            return this.oidcDiscoveryUri;
        },
        enumerable: true,
        configurable: true
    });
    /**
     * Verify the JWT against the OID issuer.
     * @param token JWT Token coming from an Idenitty Server
     */
    OidcValidator.prototype.verify = function (token) {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            var thatPublicKey, result;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!!this.publicKey) return [3 /*break*/, 2];
                        thatPublicKey = this.publicKey;
                        return [4 /*yield*/, (this.FetchDiscoveryJwkUris()
                                .then(function (jwksUri) { return _this.FetchJwkFirstX5C(jwksUri); })
                                .then(function (x5c) { return _this.SaveCertificateAndCheck(x5c, token); })["catch"](function (err) { return __awaiter(_this, void 0, void 0, function () {
                                return __generator(this, function (_a) {
                                    // hack in order to force the check of the jwt when no x5c certificate. In fact it should be done differently.
                                    if (err) {
                                        return [2 /*return*/, new Model_1.ValidatorResult(Model_1.VerifyStatusCode.Error, err)];
                                    }
                                    return [2 /*return*/];
                                });
                            }); }))];
                    case 1:
                        result = _a.sent();
                        this.publicKey = thatPublicKey;
                        return [2 /*return*/, result];
                    case 2: 
                    // No pfx validation
                    return [2 /*return*/, this.jwtVerify(token, this.publicKey)];
                }
            });
        });
    };
    /**
     * Validate the JWT token.
     * @param token The JWT token
     * @param publicKey Public key used to certify the token
     */
    OidcValidator.prototype.jwtVerify = function (token, publicKey) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, new Promise(function (resolve, reject) {
                        // format: 'PKCS8', <== the format does not exists
                        jwt.verify(token, publicKey ? publicKey.toString() : "", { algorithms: ["RS256"] }, function (errVerify) {
                            if (errVerify) {
                                return resolve(new Model_1.ValidatorResult(Model_1.VerifyStatusCode.Unauthorized));
                            }
                            return resolve(new Model_1.ValidatorResult(Model_1.VerifyStatusCode.Authorized));
                        });
                    })];
            });
        });
    };
    /**
     * Format the certificate
     * @param cert Certificate (public key)
     */
    OidcValidator.prototype.formatCertificate = function (cert) {
        cert = cert.replace(/\n|-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/mig, "");
        var result = "";
        while (cert.length > 0) {
            if (cert.length > 64) {
                result += "\n" + cert.substring(0, 64);
                cert = cert.substring(64, cert.length);
            }
            else {
                result += "\n" + cert;
                cert = "";
            }
        }
        return "-----BEGIN CERTIFICATE-----\n" + result + "\n-----END CERTIFICATE-----\n";
    };
    /**
     * Fetch the discoery Jwk URI(s)
     */
    OidcValidator.prototype.FetchDiscoveryJwkUris = function () {
        var _this = this;
        return new Promise(function (resolve, reject) {
            request.get(_this.oidcDiscoveryUri, function (err, discoveryResponse) {
                if (err) {
                    return reject(err);
                }
                // Could add a check for body // json // jwks_uri
                return resolve(JSON.parse(discoveryResponse.body).jwks_uri);
            });
        });
    };
    /**
     * Fetch the JWK first X509 Certificate
     * @param jwksUri Uri where to get the certificates
     */
    OidcValidator.prototype.FetchJwkFirstX5C = function (jwksUri) {
        return new Promise(function (resolve, reject) {
            request.get(jwksUri, function (error, jwksResponse, body) {
                if (error) {
                    return reject(error);
                }
                else if (!jwksResponse || jwksResponse.statusCode !== 200) {
                    return reject("Something went wrong in order to get the JWK x509 Certificate." /* OidJwkUnexpectedData */);
                }
                try {
                    var bodyObj = JSON.parse(body);
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
    };
    /**
     * Save the certificate and then validate the token against the certificate.
     * @param x5c Certificate
     * @param token OIDC Token
     */
    OidcValidator.prototype.SaveCertificateAndCheck = function (x5c, token) {
        var _this = this;
        var that = this;
        if (!x5c) {
            return this.jwtVerify(token, that.publicKey);
        }
        return new Promise(function (resolve, reject) {
            var x5cFormatted = that.formatCertificate(x5c);
            var certFilename = path.join(__dirname, "tmp.crt");
            fs.writeFileSync(certFilename, x5cFormatted, { encoding: "UTF-8" });
            var parsedKey = x509.parseCert(certFilename);
            var key = new NodeRSA();
            var nodeRSAKey = {
                e: parseInt(parsedKey.publicKey.e, 10),
                n: new Buffer(parsedKey.publicKey.n, "hex")
            };
            key.importKey(nodeRSAKey, "components-public");
            that.publicKey = key.exportKey("public");
            return resolve(_this.jwtVerify(token, that.publicKey));
        });
    };
    return OidcValidator;
}());
exports.OidcValidator = OidcValidator;
