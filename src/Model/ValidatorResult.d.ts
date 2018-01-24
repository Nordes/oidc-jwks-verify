import { VerifyStatusCode } from "./VerifyStatusCode";
export declare class ValidatorResult {
    statusCode: VerifyStatusCode;
    errorMessage?: string;
    constructor(status: VerifyStatusCode, errorMessage?: string);
}
