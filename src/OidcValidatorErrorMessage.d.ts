export declare const enum OidcValidatorErrorMessage {
    OptionsMissing = "Options are missing.",
    IssuerMissing = "Issuer option is missing.",
    IssuerPrefixInvalid = "Missing URI prefix within the 'issuer'.",
    OidJwkUnexpectedData = "Something went wrong in order to get the JWK x509 Certificate.",
    OidJwkKeyNotFound = "Something went wrong. We are not able to find any x509 certificate from the response.",
    OidJSONError = "Something went wrong while parsing the JSON from the JWK: ",
}
