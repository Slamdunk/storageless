<?php

declare(strict_types=1);

namespace PSR7Sessions\Storageless\Http\ClientFingerprint;

/** @immutable */
final class Configuration
{
    public readonly array $sources;

    public function __construct(
        public readonly bool $enabled,
        Source ...$sources,
    ) {
        $this->sources = $sources;
    }

    public static function default(): self
    {
        return self::disabled();
    }

    public static function enabled(): self
    {
        return new self(
            true,
            new RemoteAddr(),
            new UserAgent(),
        );
    }

    public static function disabled(): self
    {
        return new self(false);
    }
}
