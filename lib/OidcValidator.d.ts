import { ValidatorResult, VerifyOptions } from "./Model/index";
/**
 * Class used to validate the OIDC JWT Token.
 */
export declare class OidcValidator {
    private oidcDiscoveryUri;
    private publicKey?;
    private hitCount;
    private hitBeforeRefresh?;
    /**
     * Create an instance of the OIDC Validator
     * @param options Verify options containing the 'Issuer'
     */
    constructor(options: VerifyOptions);
    /**
     * OidcDiscovery URI
     */
    readonly OidcDiscoveryUri: string;
    /**
     * Verify the JWT against the OID issuer.
     * @param accessToken JWT Token coming from an Idenitty Server
     */
    verify(accessToken: string): Promise<ValidatorResult>;
    /**
     * Validate the JWT token.
     * @param token The JWT token
     * @param publicKey Public key used to certify the token
     */
    private jwtVerify(token, publicKey?);
    /**
     * Format the certificate
     * @param cert Certificate (public key)
     */
    private formatCertificate(cert);
    /**
     * Fetch the discoery Jwk URI(s)
     */
    private FetchDiscoveryJwkUris();
    /**
     * Fetch the JWK first X509 Certificate
     * @param jwksUri Uri where to get the certificates
     */
    private FetchJwkFirstX5C(jwksUri);
    /**
     * Save the certificate and then validate the token against the certificate.
     * @param x5c Certificate
     * @param token OIDC Token
     */
    private SaveCertificateAndCheck(x5c, token);
}
