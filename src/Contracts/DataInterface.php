<?php

namespace EbicsApi\Ebics\Contracts;

/**
 * Data interface.
 *
 * Represents a generic data container that provides both raw and
 * formatted content representations. This interface serves as the
 * base contract for various data types within the EBICS protocol,
 * including order data, documents, and signature data.
 *
 * EBICS Protocol Context:
 * Order data exchanged in EBICS transactions may be represented in
 * multiple formats (raw XML, human-readable, etc.). The DataInterface
 * allows consumers to access data in the most appropriate form for
 * their use case — raw content for programmatic processing or
 * formatted content for display/logging.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
interface DataInterface
{
    /**
     * Get the raw content as a string.
     *
     * Returns the unformatted data content, typically used for
     * programmatic processing or storage.
     *
     * @return string The raw data content
     */
    public function getContent(): string;

    /**
     * Get trimmed content
     *
     * @return string The raw data content
     */
    public function getTrimmedContent(): string;

    /**
     * Get a formatted (human-readable) representation of the content.
     *
     * Returns the data in a formatted form suitable for display,
     * logging, or debugging (e.g., pretty-printed XML).
     *
     * @return string The formatted data content
     */
    public function getFormattedContent(): string;

    /**
     * Check if the data should be chunked for upload.
     *
     * @return bool True if data should be split into chunks, false otherwise
     */
    public function shouldChunk(): bool;

    /**
     * Get data chunks for upload using default chunk size.
     *
     * @return array<int, string> Array of data chunks
     */
    public function getChunks(): array;

    /**
     * Get data chunks for upload with custom chunk size.
     *
     * @param int $chunkSize Maximum size of each chunk
     *
     * @return array<int, string> Array of data chunks
     */
    public function getChunksWithSize(int $chunkSize): array;

    /**
     * Get number of chunks for upload using default chunk size.
     *
     * @return int Number of chunks
     */
    public function getNumChunks(): int;

    /**
     * Get number of chunks for upload with custom chunk size.
     *
     * @param int $chunkSize Maximum size of each chunk
     *
     * @return int Number of chunks
     */
    public function getNumChunksWithSize(int $chunkSize): int;
}
