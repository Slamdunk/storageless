<?php

declare(strict_types=1);

namespace PSR7Sessions\Storageless\Http\ClientFingerprint;

use Psr\Http\Message\ServerRequestInterface;

use function array_key_exists;
use function is_string;
use function sprintf;

/** @immutable */
final class RemoteAddr implements Source
{
    public const REQUEST_ATTRIBUTE_NAME = 'REMOTE_ADDR';

    public function extractFrom(ServerRequestInterface $request): string
    {
        $serverParams = $request->getServerParams();
        if (
            ! array_key_exists(self::REQUEST_ATTRIBUTE_NAME, $serverParams)
            || ! is_string($serverParams[self::REQUEST_ATTRIBUTE_NAME])
            || $serverParams[self::REQUEST_ATTRIBUTE_NAME] === ''
        ) {
            throw new RuntimeException(sprintf(
                'The request lacks a valid %s parameter',
                self::REQUEST_ATTRIBUTE_NAME,
            ));
        }

        return $serverParams[self::REQUEST_ATTRIBUTE_NAME];
    }
}
