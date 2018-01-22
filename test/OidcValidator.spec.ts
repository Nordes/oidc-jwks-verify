import { expect } from 'chai';
import * as base from '../src/OidcValidator'

describe("OidcValidator", () => {
  describe("Instantiate constructor", () => {
      it("Should not fail", () => {
          let oidcValidator = new base.OidcValidator({ issuer: "something" });
          expect(oidcValidator).to.be.not.null;
      });
  })
});
