<?php

declare(strict_types=1);

namespace OpenIDConnectClient;

use Lcobucci\JWT\Token;
use League\OAuth2\Client\Token\AccessToken as LeagueAccessToken;
use Webmozart\Assert\Assert;

final class AccessToken extends LeagueAccessToken
{
    private Token $idToken;

    public function __construct(array $options = [])
    {
        parent::__construct($options);

        if (isset($this->values['id_token'])) {
            Assert::isInstanceOf($this->values['id_token'], Token::class);
            $this->idToken = $this->values['id_token'];
            unset($this->values['id_token']);
        }
    }

    public function getIdToken(): ?Token
    {
        return $this->idToken ?? null;
    }

    public function jsonSerialize(): array
    {
        $parameters = parent::jsonSerialize();
        if (isset($this->idToken)) {
            $parameters['id_token'] = $this->idToken->toString();
        }

        return $parameters;
    }
}
