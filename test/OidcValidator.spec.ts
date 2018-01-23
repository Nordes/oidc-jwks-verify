import { OidcValidator } from '../src/OidcValidator'
import { OidcValidatorErrorMessage } from '../src/OidcValidatorErrorMessage'
import { expect, should as shouldbe } from 'chai';
import nock = require ('nock')
import fs = require('fs')
import { VerifyStatusCode } from '../src/Model/index';

var fakeWellKnown = fs.readFileSync(__dirname + `/mockRequest/wellKnown.json`, null)
var fakeJwks = fs.readFileSync(__dirname + `/mockRequest/jwks.json`, null)

describe("OidcValidator", () => {
  describe("#constructor()", () => {
    context("Instantiate constructor with a valid [https] issuer", () => {
      it("Should not fail", () => {
        let oidcValidator = new OidcValidator({ issuer: "https://openid.example.com" });
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
        const oidcValidator = new OidcValidator({ issuer: "https://openid.example.com" });
        expect(oidcValidator.OidcDiscoveryUri).to.equal("https://openid.example.com/.well-known/openid-configuration");
      });
    })
  
    context("Get the Discovery URI with a trailing slash", () => {
      it("Should return the well known URI without any extra slashes", () => {
        const oidcValidator = new OidcValidator({ issuer: "https://openid.example.com/" });
        expect(oidcValidator.OidcDiscoveryUri).to.equal("https://openid.example.com/.well-known/openid-configuration");
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
    let scope:nock.Scope;

    before(function () {
      nock.cleanAll();
      scope = nock('https://openid.example.com', { allowUnmocked: false });
      oidcValidator = new OidcValidator({ issuer: "https://openid.example.com" })
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

        const token = 'fakeValidToken'
        const result = await oidcValidator.verify(token)
        expect(result.errorMessage).to.equal("Something went wrong. We are not able to find any x509 certificate from the response.");
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

        const token = 'fakeValidToken'
        const result = await oidcValidator.verify(token)
        expect(result.errorMessage).to.match(/^Something went wrong while parsing the JSON from the JWK: .*/);
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

        const token = 'fakeValidToken'
        const result = await oidcValidator.verify(token)
        expect(result.errorMessage).to.equal("Something went wrong in order to get the JWK x509 Certificate.");
        expect(result.statusCode).to.equal(VerifyStatusCode.Error);
      });
    })
  })
});
