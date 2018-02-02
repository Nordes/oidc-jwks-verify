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
// Good ideas over there : https://github.com/techops-peopledata/oidc
// https://expressjs.com/en/guide/using-middleware.html
const jwt = require("jsonwebtoken");
const index_1 = require("../index");
class ExpressMiddleware {
    constructor(options) {
        this.validator = new index_1.OidcValidator(options);
    }
    /**
     * Middleware for Express.
     * @param req request
     * @param res result
     * @param next next middleware
     */
    middleware(req, res, next) {
        return __awaiter(this, void 0, void 0, function* () {
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
                        const status = yield this.validator.verify(matches[2].trim());
                        if (status.errorMessage || status.statusCode !== index_1.VerifyStatusCode.Authorized) {
                            res.status(401);
                        }
                        res.locals.authenticated = true;
                        res.locals.user = jwt.decode(matches[2].trim());
                        next();
                    }
                    catch (error) {
                        res.status(401);
                    }
                }
                else {
                    // Not a bearer token. So we should avoid doing any type of validation
                    res.status(401);
                }
            }
            else {
                next();
            }
        });
    }
}
exports.ExpressMiddleware = ExpressMiddleware;
const oidcMiddle = (req, res, next) => __awaiter(this, void 0, void 0, function* () {
    res.locals.currentUser = undefined;
    next();
});
//# sourceMappingURL=Express.js.map