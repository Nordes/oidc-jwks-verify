// https://expressjs.com/en/guide/using-middleware.html
import jwt = require("jsonwebtoken");
import { OidcValidator, VerifyOptions, VerifyStatusCode } from "../index";

export class ExpressMiddleware {
  private validator: OidcValidator;

  constructor(options: VerifyOptions) {
    this.validator = new OidcValidator(options);
  }

  /**
   * Middleware for Express.
   * @param req request
   * @param res result
   * @param next next middleware
   */
  public async middleware(req: any, res: any, next: any) {
    const bearerRegEx = /^(bearer\ )(.*)$/ig;
    const authorization = req.header("authorization");

    // Following recommendation from http://expressjs.com/ja/api.html (cref.: res.locals)
    res.locals.user = undefined;
    res.locals.authenticated = false;

    if (authorization) {
      const matches = bearerRegEx.exec(authorization);
      if (matches !== null && matches.length === 3 && matches[0].trimRight().toLowerCase() === "bearer") {
        // Start validating
        try {
          const status = await this.validator.verify(matches[2].trim());
          if (status.errorMessage || status.statusCode !== VerifyStatusCode.Authorized) {
            res.status(401);
          }

          res.locals.authenticated = true;
          res.locals.user = jwt.decode(matches[2].trim());

          next();
        } catch (error) {
          res.status(401);
        }
      } else {
        // Not a bearer token. So we should avoid doing any type of validation
        res.status(401);
      }
    } else {
      next();
    }
  }
}

const oidcMiddle = async (req: any, res: any, next: any) => {
  res.locals.currentUser = undefined;
  next();
};
