<?php

declare(strict_types=1);

namespace PSR7Sessions\Storageless\Http\ClientFingerprint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Psr\Http\Message\ServerRequestInterface;

use function assert;

/** @immutable */
final class SameOriginRequest implements Constraint
{
    public const CLAIM_FINGERPRINT = 'fp';

    /** @var non-empty-string */
    private readonly string $currentRequestFingerprint;

    public function __construct(
        private readonly Configuration $configuration,
        ServerRequestInterface $serverRequest,
    ) {
        if (! $this->configuration->enabled) {
            return;
        }

        $this->currentRequestFingerprint = self::getCurrentFingerprint($this->configuration, $serverRequest);
    }

    public function assert(Token $token): void
    {
        if (! $this->configuration->enabled) {
            return;
        }

        if (! $token instanceof UnencryptedToken) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        if (! $token->claims()->has(self::CLAIM_FINGERPRINT)) {
            throw ConstraintViolation::error('"Client Fingerprint" claim missing', $this);
        }

        if ($token->claims()->get(self::CLAIM_FINGERPRINT) !== $this->currentRequestFingerprint) {
            throw ConstraintViolation::error('"Client Fingerprint" does not match', $this);
        }
    }

    /** @return non-empty-string */
    private static function getCurrentFingerprint(Configuration $configuration, ServerRequestInterface $serverRequest): string
    {
        $sources = $configuration->sources;
        assert($sources !== []);

        $fingerprint = '';
        foreach ($sources as $source) {
            $fingerprint .= "\x00" . $source->extractFrom($serverRequest);
        }

        return $fingerprint;
    }
}
