<?php

declare(strict_types=1);

namespace OpenIDConnectClient\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Webmozart\Assert\Assert;

final class HasClaim implements Constraint
{
    private string $claimName;

    public function __construct(string $claimName)
    {
        Assert::notEmpty(trim($claimName));

        $this->claimName = $claimName;
    }

    public function assert(Token $token): void
    {
        Assert::isInstanceOf(
            $token,
            UnencryptedToken::class,
            'This constraint only works for tokens which provide access to claims',
        );

        /** @var UnencryptedToken $token */
        $claim = $token->claims()->get($this->claimName);
        if (!$claim) {
            throw new ConstraintViolation($this->claimName . ' is required and cannot be empty');
        }
    }
}
