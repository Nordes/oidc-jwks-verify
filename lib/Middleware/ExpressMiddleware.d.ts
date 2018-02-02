import { VerifyOptions } from "../index";
export declare class ExpressMiddleware {
    private validator;
    constructor(options: VerifyOptions);
    /**
     * Middleware for Express.
     * @param req request
     * @param res result
     * @param next next middleware
     */
    middleware(req: any, res: any, next: any): Promise<void>;
}
