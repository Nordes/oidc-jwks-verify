import { VerifyStatusCode } from "./verifyStatusCode";
export declare class ValidatorResult {
    statusCode: VerifyStatusCode;
    errorMessage?: string;
    constructor(status: VerifyStatusCode, errorMessage?: string);
}
