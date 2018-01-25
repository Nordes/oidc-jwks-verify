import { OidcValidator } from '../src/OidcValidator';
import { OidcValidatorErrorMessage } from '../src/OidcValidatorErrorMessage';
import { expect, should as shouldbe } from 'chai';
import nock = require('nock');
import fs = require('fs');
import { VerifyStatusCode } from '../src/Model/index';
import { Oidc, Profile } from './interface/oidc'

const fakeWellKnown = fs.readFileSync(__dirname + `/mockRequest/wellKnown.json`, null);
const fakeJwksNoX5C = fs.readFileSync(__dirname + `/mockRequest/jwksNoX5C.json`, null);
const fakeJwks = fs.readFileSync(__dirname + `/mockRequest/jwks.json`, null);
const oidcInfo: Oidc = JSON.parse(fs.readFileSync(__dirname + '/mockRequest/clientOidc.json', null).toString());
let scope: nock.Scope;

describe("OidcValidator", () => {
  describe("#constructor()", () => {
    context("Instantiate constructor with a valid [https] issuer", () => {
      it("Should not fail", () => {
        let oidcValidator = new OidcValidator({ issuer: "http://localhost:5000" });
        expect(oidcValidator).to.be.not.null;
      });
    })

    context("Instantiate constructor with a valid [http] issuer", () => {
      it("Should not fail", () => {
        let oidcValidator = new OidcValidator({ issuer: "http://openid.example.com" });
        expect(oidcValidator).to.be.not.null;
      });
    })

    context("Instantiate constructor with a valid [://] issuer", () => {
      it("Should not fail", () => {
        const oidcValidator = new OidcValidator({ issuer: "://openid.example.com" });
        expect(oidcValidator).to.be.not.null;
      });
    })

    context("Instantiate constructor having an invalid issuer URI", () => {
      it("Should throw when no http or https prefix", () => {
        const should = shouldbe();
        should.throw(() => { let oidcValidator = new OidcValidator({ issuer: "openid.example.com" }); }, OidcValidatorErrorMessage.IssuerPrefixInvalid, "Expecting the Constructor to throw an Error with missing URI prefix");
      });
    })

    context("Get the Discovery URI with no trailing slash", () => {
      it("Should return the well known URI without any extra slashes", () => {
        const oidcValidator = new OidcValidator({ issuer: "http://localhost:5000" });
        expect(oidcValidator.OidcDiscoveryUri).to.equal("http://localhost:5000/.well-known/openid-configuration");
      });
    })

    context("Get the Discovery URI with a trailing slash", () => {
      it("Should return the well known URI without any extra slashes", () => {
        const oidcValidator = new OidcValidator({ issuer: "http://localhost:5000/" });
        expect(oidcValidator.OidcDiscoveryUri).to.equal("http://localhost:5000/.well-known/openid-configuration");
      });
    })

    context("Undefined issuer", () => {
      it("Should fail with an error: Issuer option is missing.", () => {
        const should = shouldbe();
        should.throw(() => {
          let oidcValidator = new OidcValidator({ issuer: undefined });
        },
          OidcValidatorErrorMessage.IssuerMissing,
          "Expecting the Constructor to throw an Error with issuer option is missing.");
      });
    })

    context("Undefined options", () => {
      it("Should fail with an error: Options are missing.", () => {
        const should = shouldbe();
        should.throw(() => {
          let oidcValidator = new OidcValidator(undefined);
          console.log(oidcValidator.OidcDiscoveryUri);
        },
          OidcValidatorErrorMessage.OptionsMissing,
          "Expecting the Constructor to throw an Error with options are missing.");
      });
    })
  })

  describe("#verify()", () => {
    let oidcValidator: OidcValidator;

    before(function () {
      nock.cleanAll();
      scope = nock('http://localhost:5000', { allowUnmocked: false });
      oidcValidator = new OidcValidator({ issuer: "http://localhost:5000" })
    })

    context("Unable to contact the server [Not implemented]", () => {
      // Not implemented
    })

    context("Not found [Not implemented]", () => {
      // Not implemented
    })

    context("JwkUrl returns unexpected JSON in order to get the x509 certificate", () => {
      it("Should fail with a status code: Error", async () => {
        scope
          .get('/.well-known/openid-configuration')
          .reply(200, fakeWellKnown)
          .get('/.well-known/openid-configuration/jwks')
          .reply(200, "{}"); // Valid JSON, invalid content

        const token = 'fakeValidToken';
        const result = await oidcValidator.verify(token);
        expect(result.errorMessage).to.equal(OidcValidatorErrorMessage.OidJwkKeyNotFound);
        expect(result.statusCode).to.equal(VerifyStatusCode.Error);
      })
    })

    context("JwkUrl returns invalid JSON", () => {
      it("Should fail with a status code: Error", async () => {
        scope
          .get('/.well-known/openid-configuration')
          .reply(200, fakeWellKnown)
          .get('/.well-known/openid-configuration/jwks')
          .reply(200, "{a: 'abc'}"); // Invalid JSON

        const token = 'fakeValidToken';
        const result = await oidcValidator.verify(token);
        expect(result.errorMessage).to.match(/^Something went wrong while parsing the JSON from the JWK: .*/); // OidJSONError
        expect(result.statusCode).to.equal(VerifyStatusCode.Error);
      })
    })

    context("JwkUrl is not reachable (404)", () => {
      it("Should fail with a status code: Error", async () => {
        scope
          .get('/.well-known/openid-configuration')
          .reply(200, fakeWellKnown)
          .get('/.well-known/openid-configuration/jwks')
          .reply(404);

        const token = 'fakeValidToken';
        const result = await oidcValidator.verify(token);
        expect(result.errorMessage).to.equal(OidcValidatorErrorMessage.OidJwkUnexpectedData);
        expect(result.statusCode).to.equal(VerifyStatusCode.Error);
      });
    })

    context("Invalid token", () => {
      it("Should return a status of Unauthorized", async () => {
        // Prepare
        scope
          .get('/.well-known/openid-configuration')
          .reply(200, fakeWellKnown)
          .get('/.well-known/openid-configuration/jwks')
          .reply(200, fakeJwks);

        const token = 'fakeValidToken'; // Invalid token

        // Execute
        const result = await oidcValidator.verify(token);

        // Validate
        expect(result.statusCode).to.equal(VerifyStatusCode.Unauthorized);
      });
    });

    context("Valid token", () => {
      it("Should return a status of Authorized", async () => {
        nock.cleanAll();
        // Prepare
        scope
          .get('/.well-known/openid-configuration')
          .reply(200, fakeWellKnown)
          .get('/.well-known/openid-configuration/jwks')
          .reply(200, fakeJwks);

        // Execute
        const result = await oidcValidator.verify(oidcInfo.access_token);

        // Validate
        expect(result.statusCode).to.equal(VerifyStatusCode.Authorized);
      });
    });

    context("Valid token (2 times should use cached value)", () => {
      it("Should return a status of Authorized twice", async () => {
        nock.cleanAll();
        // Prepare
        scope
          .get('/.well-known/openid-configuration')
          .reply(200, fakeWellKnown)
          .get('/.well-known/openid-configuration/jwks')
          .reply(200, fakeJwks);

        // Execute
        const result = await oidcValidator.verify(oidcInfo.access_token);
        const result2 = await oidcValidator.verify(oidcInfo.access_token);

        // Validate
        expect(result.statusCode).to.equal(VerifyStatusCode.Authorized);
        expect(result2.statusCode).to.equal(VerifyStatusCode.Authorized);
      });
    });

    context("Valid token (2 times should without cache enabled)", () => {
      it("Should return a status of Authorized twice and two access to the URL", async () => {
        nock.cleanAll();
        // Prepare
        let oidcValidatorHitCounter: OidcValidator = new OidcValidator({ issuer: "http://localhost:5000", hitBeforeRefresh: 0});

        scope
          .get('/.well-known/openid-configuration')
          .times(2)
          .reply(200, fakeWellKnown)
          .get('/.well-known/openid-configuration/jwks')
          .times(2)
          .reply(200, fakeJwks);

        // Execute
        const result = await oidcValidator.verify(oidcInfo.access_token);
        const result2 = await oidcValidator.verify(oidcInfo.access_token);

        // Validate
        expect(result.statusCode).to.equal(VerifyStatusCode.Authorized);
        expect(result2.statusCode).to.equal(VerifyStatusCode.Authorized);
      });
    });
  })
});
