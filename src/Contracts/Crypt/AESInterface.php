<?php

namespace EbicsApi\Ebics\Contracts\Crypt;

/**
 * AES cipher operations for EBICS protocol encryption and decryption.
 *
 * Provides block-level AES encrypt/decrypt in CBC mode (backed by OpenSSL),
 * ANSI X.923 padding/unpadding, and block-size queries.
 *
 * Typical EBICS usage:
 *  1. Pad plaintext with {@see pad()} to make it block-aligned.
 *  2. Encrypt each block with {@see encryptBlock()} using a transaction key.
 *  3. On receipt, decrypt with {@see decryptBlock()} then strip padding with {@see unpad()}.
 *
 * @see \EbicsApi\Ebics\Services\Processor\AESEncryptor  Uses this interface for AES operations.
 * @see \App\Model\Ebics\BufferedAESEncryptor  Streaming variant.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
interface AESInterface
{
    /**
     * Returns the AES block size in bytes.
     *
     * AES uses a fixed 128-bit (16-byte) block size regardless of key length.
     *
     * @return int Block size in bytes (always 16).
     */
    public function getBlockSize(): int;

    /**
     * Apply ANSI X.923 padding to make the data a multiple of the block size.
     *
     * X.923 pads with zero bytes and stores the padding length in the final byte.
     * When the input is already block-aligned, a full 16-byte padding block is appended.
     *
     * Padding length is always between 1 and 16 (inclusive).
     *
     * @param string $text Plaintext to pad (any length, including empty).
     *
     * @return string Padded data whose length is a multiple of 16.
     */
    public function pad(string $text);

    /**
     * Strip ANSI X.923 padding from decrypted data.
     *
     * Reads the final byte as the padding length, then removes that many bytes
     * from the end of the string.
     *
     * @param string $text Decrypted data with X.923 padding at the end.
     *
     * @return string Original unpadded plaintext.
     *
     * @throws \LogicException If the padding length byte is 0 or exceeds the block size.
     */
    public function unpad(string $text);

    /**
     * Encrypt block-aligned data with AES in CBC mode (no internal padding).
     *
     * Delegates to {@see \openssl_encrypt()} with `OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING`.
     * The caller is responsible for padding the input before calling this method.
     *
     * @param string $data   Block-aligned plaintext (length must be a multiple of the block size).
     * @param string $key    Raw AES key (16 bytes for AES-128, 32 bytes for AES-256).
     * @param string $cipher OpenSSL cipher method (e.g. 'aes-128-cbc', 'aes-256-cbc').
     * @param string $iv     Initialization vector (must be $blockSize bytes).
     *
     * @return string Ciphertext block (same length as input).
     *
     * @throws \LogicException If OpenSSL encryption fails (bad key length, invalid cipher, etc.).
     */
    public function encryptBlock(string $data, string $key, string $cipher, string $iv);

    /**
     * Decrypt AES-CBC ciphertext without stripping padding.
     *
     * Delegates to {@see \openssl_decrypt()} with `OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING`.
     * The caller must call {@see unpad()} afterward to remove X.923 padding.
     *
     * @param string $data   Ciphertext block to decrypt.
     * @param string $key    Raw AES key (16 bytes for AES-128, 32 bytes for AES-256).
     * @param string $cipher OpenSSL cipher method (e.g. 'aes-128-cbc', 'aes-256-cbc').
     * @param string $iv     Initialization vector (must be $blockSize bytes).
     *
     * @return string Decrypted block (same length as input, may contain padding bytes).
     *
     * @throws \LogicException If OpenSSL decryption fails (bad key length, invalid cipher, etc.).
     */
    public function decryptBlock(string $data, string $key, string $cipher, string $iv);
}
