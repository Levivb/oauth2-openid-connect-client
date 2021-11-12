<?php

declare(strict_types=1);

namespace OpenIDConnectClient\Exception;

use JetBrains\PhpStorm\Pure;
use RuntimeException;
use Throwable;

final class InvalidTokenException extends RuntimeException
{
    private array $validationErrors;

    public function __construct($message = '', $code = 0, ?Throwable $previous = null, ?array $validationErrors = [])
    {
        parent::__construct($message, $code, $previous);

        $this->validationErrors = $validationErrors;
    }

    #[Pure]
    public function getMessages(): array
    {
        return $this->validationErrors ?: [$this->getMessage()];
    }
}
