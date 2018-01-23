import { OidcValidator } from '../src/OidcValidator'
import { expect, should as shouldbe } from 'chai';
import nock = require ('nock')
import fs = require('fs')

var fakeWellKnown = fs.readFileSync(__dirname + `/mockRequest/wellKnown.data`, null)

// use nock in order to do all the tests.
var oidcProvider = nock('https://openid.example.com', { allowUnmocked: false })
  .get('/.well-known/openid-configuration')
  .reply(200, '');

describe("OidcValidator", () => {

  describe("Instantiate constructor with a valid [https] issuer", () => {
    it("Should not fail", () => {
      let oidcValidator = new OidcValidator({ issuer: "https://openid.example.com" });
      expect(oidcValidator).to.be.not.null;
      console.log(oidcValidator.OidcDiscoveryUri);
    });
  })

  describe("Instantiate constructor with a valid [http] issuer", () => {
    it("Should not fail", () => {
      let oidcValidator = new OidcValidator({ issuer: "http://openid.example.com" });
      expect(oidcValidator).to.be.not.null;
      console.log(oidcValidator.OidcDiscoveryUri);
    });
  })

  describe("Instantiate constructor with a valid [://] issuer", () => {
    it("Should not fail", () => {
      let oidcValidator = new OidcValidator({ issuer: "://openid.example.com" });
      expect(oidcValidator).to.be.not.null;
      console.log(oidcValidator.OidcDiscoveryUri);
    });
  })

  describe("Instantiate constructor having an invalid issuer URI", () => {
    it("Should throw when no http or https prefix", () => {
      var should = shouldbe();
      should.throw(() => { let oidcValidator = new OidcValidator({ issuer: "openid.example.com" }); }, "Missing URI prefix within the 'issuer'", "Expecting the Constructor to throw an Error with missing URI prefix");
    });
  })

  describe("Get the Discovery URI with no trailing slash", () => {
    it("Should return the well known URI without any extra slashes", () => {
      let oidcValidator = new OidcValidator({ issuer: "https://openid.example.com" });
      expect(oidcValidator.OidcDiscoveryUri).to.equal("https://openid.example.com/.well-known/openid-configuration");
    });
  })

  describe("Get the Discovery URI with a trailing slash", () => {
    it("Should return the well known URI without any extra slashes", () => {
      let oidcValidator = new OidcValidator({ issuer: "https://openid.example.com/" });
      expect(oidcValidator.OidcDiscoveryUri).to.equal("https://openid.example.com/.well-known/openid-configuration");
    });
  })
});
