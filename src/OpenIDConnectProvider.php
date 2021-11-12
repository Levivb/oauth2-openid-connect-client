<?php

declare(strict_types=1);

namespace OpenIDConnectClient;

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use OpenIDConnectClient\Constraints\AuthorizedFor;
use OpenIDConnectClient\Constraints\HasClaim;
use OpenIDConnectClient\Exception\InvalidTokenException;
use Webmozart\Assert\Assert;

final class OpenIDConnectProvider extends GenericProvider
{
    private Configuration $jwtConfiguration;

    /** @var string|array<string> */
    protected $publicKey;
    protected string $idTokenIssuer;

    /**
     * @param array $options
     * @param array $collaborators
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        Assert::keyExists($collaborators, 'jwtConfiguration');
        Assert::isInstanceOf($collaborators['jwtConfiguration'], Configuration::class);
        Assert::keyExists($options, 'idTokenIssuer');
        Assert::stringNotEmpty($options['idTokenIssuer']);

        // Cast (optional) `scopes` parameter to array, add openid and deduplicate duplicates
        // and remove empty values just to be sure.
        $options['scopes'] = array_filter(array_unique(array_merge((array)($options['scopes'] ?? null), ['openid'])));

        parent::__construct($options, $collaborators);

        $this->jwtConfiguration = $collaborators['jwtConfiguration'];
    }

    /**
     * Returns all options that are required.
     *
     * @return array<string>
     */
    protected function getRequiredOptions(): array
    {
        $options = parent::getRequiredOptions();
        $options[] = 'publicKey';
        $options[] = 'idTokenIssuer';

        return $options;
    }

    /**
     * @return Key[]
     */
    public function getPublicKey(): array
    {
        if (is_array($this->publicKey)) {
            return array_map(
                static function (string $key): Key {
                    return new Key($key);
                },
                $this->publicKey,
            );
        }

        return [new Key($this->publicKey)];
    }

    /**
     * Requests an access token using a specified grant and option set.
     *
     * @param mixed $grant
     * @param array $options
     * @return AccessToken
     * @throws IdentityProviderException
     */
    public function getAccessToken($grant, array $options = [])
    {
        /** @var AccessToken $accessToken */
        $accessToken = parent::getAccessToken($grant, $options);
        $token = $accessToken->getIdToken();

        // id_token is empty.
        if ($token === null) {
            $message = 'Expected an id_token but did not receive one from the authorization server.';
            throw new InvalidTokenException($message);
        }

        /*
         * Proper validation scaffolding can only be applied to an instance of UnencryptedToken
         * When a different token type is used, the validation will be the responsibility of the implementing party.
         */
        if (!$token instanceof UnencryptedToken) {
            return $accessToken;
        }

        // If the ID Token is received via direct communication between the Client and the Token Endpoint
        // (which it is in this flow), the TLS server validation MAY be used to validate the issuer in place of checking
        // the token signature. The Client MUST validate the signature of all other ID Tokens according to JWS [JWS]
        // using the algorithm specified in the JWT alg Header Parameter. The Client MUST use the keys provided by
        // the Issuer.
        //
        // The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the
        // id_token_signed_response_alg parameter during Registration.
        $verified = false;
        foreach ($this->getPublicKey() as $key) {
            $isValid = $this->jwtConfiguration
                ->signer()
                ->verify($token->signature()->hash(), $token->payload(), $key);

            if ($isValid) {
                $verified = true;
                break;
            }
        }

        if (!$verified) {
            throw new InvalidTokenException('Received an invalid id_token from authorization server.');
        }

        $this->validateToken($token);

        return $accessToken;
    }

    /**
     * Overload parent as OpenID Connect specification states scopes shall be separated by spaces
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * Creates an access token from a response.
     *
     * The grant that was used to fetch the response can be used to provide
     * additional context.
     *
     * @param array<string, int|string> $response
     */
    protected function createAccessToken(array $response, AbstractGrant $grant): AccessToken
    {
        if (isset($response['id_token'])) {
            $response['id_token'] = $this->jwtConfiguration->parser()->parse($response['id_token']);
        }

        return new AccessToken($response);
    }

    private function validateToken(UnencryptedToken $token): void
    {
        $this->configureIdTokenValidation();

        $this->jwtConfiguration
            ->validator()
            ->assert($token, ...$this->jwtConfiguration->validationConstraints());
    }

    /**
     * @see http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     */
    private function configureIdTokenValidation(): void
    {
        if (count($this->jwtConfiguration->validationConstraints()) !== 0) {
            return;
        }

        $constraints = [
            // The nbf time should be in the future. An option of nbfToleranceSeconds can be sent and it will be
            // added to the currentTime in order to accept some difference in clocks
            new StrictValidAt(SystemClock::fromSystemTimezone()),
            // 'iat', 'exp', 'nbf'

            // The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
            // MUST exactly match the value of the iss (issuer) Claim.
            new IssuedBy($this->idTokenIssuer),

            // The Client MUST validate that the aud/audience Claim contains its client_id value registered
            // at the Issuer identified by the iss (issuer) Claim as an audience.
            // The aud (audience) Claim MAY contain an array with more than one element.
            new PermittedFor($this->clientId),

            new HasClaim(RegisteredClaims::SUBJECT),
            //new RelatedTo(), // sub

            //new IdentifiedBy(), // jti

            // azp
            new AuthorizedFor($this->clientId),

            new SignedWith($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey()),

            /**
             * @TODO
             */

            // NONCE
            // If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value
            // checked to verify that it is the same value as the one that was sent in the Authentication Request.
            // The Client SHOULD check the nonce value for replay attacks.
            // The precise method for detecting replay attacks is Client specific.

            // AUTH_TIME
            // If the auth_time Claim was requested, either through a specific request for this Claim or by using
            // the max_age parameter, the Client SHOULD check the auth_time Claim value and request re-authentication
            // if it determines too much time has elapsed since the last End-User authentication.

            // ACR
            // If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate.
            // The meaning and processing of acr Claim Values is out of scope for this specification.
        ];

        $this->jwtConfiguration->setValidationConstraints(...$constraints);
    }
}
