<?php

declare(strict_types=1);

namespace OpenIDConnectClient\Tests\Unit\Constraints;

use InvalidArgumentException;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\ConstraintViolation;
use OpenIDConnectClient\Constraints\HasClaim;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class HasClaimTest extends TestCase
{
    private HasClaim $constraint;

    /** @var MockObject&UnencryptedToken */
    private MockObject $token;

    protected function setUp(): void
    {
        parent::setUp();

        $this->token = $this->createMock(UnencryptedToken::class);
        $this->constraint = new HasClaim('some-claim');
    }

    public function testConstructorEnforcesValidClaimName(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new HasClaim(' ');
    }

    public function testAssertWithValidClaim(): void
    {
        $dataSet = $this->createMock(DataSet::class);

        $this->token
            ->expects(self::once())
            ->method('claims')
            ->willReturn($dataSet);

        $dataSet
            ->expects(self::once())
            ->method('get')
            ->with(self::identicalTo('some-claim'))
            ->willReturn('some-claim-value');

        $this->constraint->assert($this->token);
    }

    public function testAssertWithInValidClaimThrowsException(): void
    {
        $dataSet = $this->createMock(DataSet::class);

        $this->token
            ->expects(self::once())
            ->method('claims')
            ->willReturn($dataSet);

        $dataSet
            ->expects(self::once())
            ->method('get')
            ->with(self::identicalTo('some-claim'))
            ->willReturn(null);

        $this->expectException(ConstraintViolation::class);

        $this->constraint->assert($this->token);
    }

    public function testAssertWithUnsupportedTokenThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->constraint->assert($this->createMock(Token::class));
    }
}
