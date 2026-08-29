<?php

namespace EbicsApi\Ebics\Models;

/**
 * Trait for data that can be chunked for EBICS upload.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
trait ChunkableData
{
    public const CHUNK_SIZE = 1048576; // 1MB

    public function shouldChunk(): bool
    {
        return true;
    }

    /**
     * @return array<int, string>
     */
    public function getChunks(): array
    {
        return $this->getChunksWithSize(self::CHUNK_SIZE);
    }

    /**
     * @return array<int, string>
     */
    public function getChunksWithSize(int $chunkSize): array
    {
        $content = $this->getTrimmedContent();
        $chunks = [];
        for ($i = 0; $i < strlen($content); $i += $chunkSize) {
            $chunks[] = substr($content, $i, $chunkSize);
        }

        return $chunks;
    }

    public function getNumChunks(): int
    {
        return $this->getNumChunksWithSize(self::CHUNK_SIZE);
    }

    public function getNumChunksWithSize(int $chunkSize): int
    {
        $content = $this->getTrimmedContent();
        if ($content === '') {
            return 0;
        }

        return (int)ceil(strlen($content) / $chunkSize);
    }
}
