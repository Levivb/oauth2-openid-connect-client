<?php

declare(strict_types=1);

namespace OpenIDConnectClient\Tests\Unit;

use InvalidArgumentException;
use Lcobucci\JWT\Token as IdToken;
use OpenIDConnectClient\AccessToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use stdClass;

final class AccessTokenTest extends TestCase
{
    private const TEST_TIME = 1636070000;

    private const DEFAULT_ARGUMENTS = [
        'access_token' => 'some access token',
        'resource_owner_id' => 'some resource_owner_id',
        'refresh_token' => 'some refresh_token',
        'expires_in' => 123,
        'random_key_123' => 'some random value',
    ];

    /** @var IdToken&MockObject */
    private MockObject $idToken;

    private AccessToken $token;

    protected function setUp(): void
    {
        parent::setUp();

        AccessToken::setTimeNow(self::TEST_TIME);
        $this->idToken = $this->createMock(IdToken::class);

        $this->token = new AccessToken(self::DEFAULT_ARGUMENTS + ['id_token' => $this->idToken]);
    }

    public function testBareConstructor(): void
    {
        $token = new AccessToken(['access_token' => 'something']);
        self::assertSame('something', (string)$token);
        self::assertNull($token->getIdToken());
        self::assertSame(['access_token' => 'something'], $token->jsonSerialize());
    }

    public function testConstructorWithInvalidAccessTokenThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AccessToken([]);
    }

    public function testConstructorWithInvalidExpiresInThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AccessToken(['access_token' => 'something', 'expires_in' => 'invalid']);
    }

    public function testConstructorWithInvalidIdTokenThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AccessToken(['access_token' => 'something', 'id_token' => new stdClass()]);
    }

    public function testDefaultGettersWithValidValues(): void
    {
        self::assertSame(self::DEFAULT_ARGUMENTS['access_token'], $this->token->getToken());
        self::assertSame(self::DEFAULT_ARGUMENTS['access_token'], (string)$this->token);
        self::assertSame(self::DEFAULT_ARGUMENTS['resource_owner_id'], $this->token->getResourceOwnerId());
        self::assertSame(self::DEFAULT_ARGUMENTS['refresh_token'], $this->token->getRefreshToken());
        self::assertSame(self::TEST_TIME + self::DEFAULT_ARGUMENTS['expires_in'], $this->token->getExpires());
        self::assertSame(['random_key_123' => self::DEFAULT_ARGUMENTS['random_key_123']], $this->token->getValues());
        self::assertInstanceOf(IdToken::class, $this->token->getIdToken());
    }

    public function testJsonSerializeResponse(): void
    {
        $this->idToken
            ->expects(self::once())
            ->method('toString')
            ->willReturn('some-id-token');

        $expectedSerializedResponse = self::DEFAULT_ARGUMENTS + ['id_token' => 'some-id-token'];
        $expectedSerializedResponse['expires'] = self::TEST_TIME + self::DEFAULT_ARGUMENTS['expires_in'];
        unset($expectedSerializedResponse['expires_in']);
        $actualSerializedResponse = $this->token->jsonSerialize();
        ksort($expectedSerializedResponse);
        ksort($actualSerializedResponse);
        self::assertSame($expectedSerializedResponse, $actualSerializedResponse);
    }
}
