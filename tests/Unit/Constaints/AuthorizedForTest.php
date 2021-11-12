<?php

declare(strict_types=1);

namespace OpenIDConnectClient\Tests\Unit\Constraints;

use InvalidArgumentException;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\ConstraintViolation;
use OpenIDConnectClient\Constraints\AuthorizedFor;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class AuthorizedForTest extends TestCase
{
    private AuthorizedFor $constraint;

    /** @var MockObject&UnencryptedToken */
    private MockObject $token;

    protected function setUp(): void
    {
        parent::setUp();

        $this->token = $this->createMock(UnencryptedToken::class);
        $this->constraint = new AuthorizedFor('some-id');
    }

    public function testConstructorEnforcesValidId(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new AuthorizedFor(' ');
    }

    public function testAssertWithExactAudience(): void
    {
        $dataSet = $this->createMock(DataSet::class);

        $this->token
            ->expects(self::once())
            ->method('claims')
            ->willReturn($dataSet);

        $dataSet
            ->expects(self::once())
            ->method('get')
            ->with(self::identicalTo(RegisteredClaims::AUDIENCE))
            ->willReturn('some audience');

        $this->constraint->assert($this->token);
    }

    public function testAssertWithSingleAudience(): void
    {
        $dataSet = $this->createMock(DataSet::class);

        $this->token
            ->expects(self::once())
            ->method('claims')
            ->willReturn($dataSet);

        $dataSet
            ->expects(self::once())
            ->method('get')
            ->with(self::identicalTo(RegisteredClaims::AUDIENCE))
            ->willReturn(['some audience']);

        $this->constraint->assert($this->token);
    }

    public function testAssertWithMultipleAudienceChecksEmptyAzp(): void
    {
        $dataSet = $this->createMock(DataSet::class);

        $this->token
            ->expects(self::atLeastOnce())
            ->method('claims')
            ->willReturn($dataSet);

        $dataSet
            ->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(
                [self::identicalTo(RegisteredClaims::AUDIENCE)],
                [self::identicalTo('azp')],
            )
            ->willReturnOnConsecutiveCalls(['aud 1', 'aud 2'], null);

        $this->constraint->assert($this->token);
    }

    public function testAssertWithMultipleAudienceChecksValidAzp(): void
    {
        $dataSet = $this->createMock(DataSet::class);

        $this->token
            ->expects(self::atLeastOnce())
            ->method('claims')
            ->willReturn($dataSet);

        $dataSet
            ->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(
                [self::identicalTo(RegisteredClaims::AUDIENCE)],
                [self::identicalTo('azp')],
            )
            ->willReturnOnConsecutiveCalls(['aud 1', 'aud 2'], 'some-id');

        $this->constraint->assert($this->token);
    }

    public function testAssertWithMultipleAudienceChecksInvalidAzp(): void
    {
        $dataSet = $this->createMock(DataSet::class);

        $this->token
            ->expects(self::atLeastOnce())
            ->method('claims')
            ->willReturn($dataSet);

        $dataSet
            ->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(
                [self::identicalTo(RegisteredClaims::AUDIENCE)],
                [self::identicalTo('azp')],
            )
            ->willReturnOnConsecutiveCalls(['aud 1', 'aud 2'], 'some-other-id');

        $this->expectException(ConstraintViolation::class);

        $this->constraint->assert($this->token);
    }

    public function testAssertWithUnsupportedTokenThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->constraint->assert($this->createMock(Token::class));
    }
}
