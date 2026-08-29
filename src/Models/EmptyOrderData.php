<?php

namespace EbicsApi\Ebics\Models;

use EbicsApi\Ebics\Contracts\OrderDataInterface;

/**
 * Class EmptyOrderData.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class EmptyOrderData implements OrderDataInterface
{
    public const CONTENT = ' ';

    public function getContent(): string
    {
        return self::CONTENT;
    }

    public function getTrimmedContent(): string
    {
        return self::CONTENT;
    }

    public function getFormattedContent(): string
    {
        return self::CONTENT;
    }

    public function shouldChunk(): bool
    {
        return false;
    }

    /**
     * @return array<int, string>
     */
    public function getChunks(): array
    {
        return [self::CONTENT];
    }

    public function getChunksWithSize(int $chunkSize): array
    {
        return [self::CONTENT];
    }

    public function getNumChunks(): int
    {
        return 0;
    }

    public function getNumChunksWithSize(int $chunkSize): int
    {
        return 0;
    }
}
