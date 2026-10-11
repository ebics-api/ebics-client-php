<?php

namespace EbicsApi\Ebics\Services\Processor;

use EbicsApi\Ebics\Contracts\Processor\Base64EncoderInterface;
use RuntimeException;

/**
 * Base64 encode/decode pipe.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class Base64Encoder implements Base64EncoderInterface
{
    /** Max encoded length = 512 * 1024 * 1024 (512 MB) */
    private const MAX_ENCODED_LENGTH = 536870912;
    /** Max raw length = MAX_ENCODED_LENGTH * 3 / 4 (~384 MB) */
    private const MAX_RAW_LENGTH = 402653184;

    public function encode(string $data): string
    {
        $length = strlen($data);

        if ($length > self::MAX_RAW_LENGTH) {
            throw new RuntimeException(sprintf(
                'Data exceeds maximum length of %d bytes, got %d bytes. Use buffered analog.',
                self::MAX_RAW_LENGTH,
                $length
            ));
        }

        return base64_encode($data);
    }

    public function decode(string $data): string
    {
        $length = strlen($data);

        if ($length > self::MAX_ENCODED_LENGTH) {
            throw new RuntimeException(sprintf(
                'Encoded data exceeds maximum length of %d bytes, got %d bytes. Use buffered analog.',
                self::MAX_ENCODED_LENGTH,
                $length
            ));
        }

        return base64_decode($data);
    }
}
