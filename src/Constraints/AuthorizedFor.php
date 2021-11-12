<?php

declare(strict_types=1);

namespace OpenIDConnectClient\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Webmozart\Assert\Assert;

/**
 * If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
 * If an azp (authorized party) Claim is present,
 * the Client SHOULD verify that its client_id is the Claim Value.
 */
final class AuthorizedFor implements Constraint
{
    private const AUTHORIZED_PARTY_CLAIM = 'azp';

    private string $id;

    public function __construct(string $id)
    {
        Assert::notEmpty(trim($id));

        $this->id = $id;
    }

    public function assert(Token $token): void
    {
        Assert::isInstanceOf(
            $token,
            UnencryptedToken::class,
            'This constraint only works for tokens which provide access to claims',
        );

        /** @var UnencryptedToken $token */
        $audience = $token->claims()->get(RegisteredClaims::AUDIENCE);

        if (!is_array($audience) || count($audience) === 1) {
            return;
        }

        $claim = $token->claims()->get(self::AUTHORIZED_PARTY_CLAIM);

        if (!$claim) {
            return;
        }

        if ($claim !== $this->id) {
            throw new ConstraintViolation('The token is not authorized for this party');
        }
    }
}
