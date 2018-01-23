import { VerifyStatusCode } from "./VerifyStatusCode";

export class ValidatorResult {
  public statusCode: VerifyStatusCode;
  public errorMessage?: string;

  constructor(status: VerifyStatusCode, errorMessage?: string) {
    this.statusCode = status;
    this.errorMessage = errorMessage;
  }
}
