<?php

namespace EbicsApi\Ebics\Models\Crypt;

use EbicsApi\Ebics\Contracts\Crypt\AESInterface;
use LogicException;

/**
 * Pure-PHP implementation of AES cipher in CBC mode, backed by the OpenSSL extension.
 *
 * Supports 128-bit and 256-bit key lengths.
 * Padding scheme: ANSI X.923 (zero-padded bytes, final byte encodes the padding length).
 *
 * Requires the PHP `openssl` extension.
 */
final class AES implements AESInterface
{
    /**
     * AES block size in bytes. Fixed at 16 for AES.
     */
    protected int $blockSize = 16;

    /**
     * Returns the AES block size in bytes.
     */
    public function getBlockSize(): int
    {
        return $this->blockSize;
    }

    /**
     * Encrypt a single block without padding.
     *
     * @param string $data   Block-aligned plaintext.
     * @param string $key    Raw AES key.
     * @param string $cipher OpenSSL cipher method.
     * @param string $iv     Initialization vector.
     *
     * @return string Ciphertext block.
     */
    public function encryptBlock(string $data, string $key, string $cipher, string $iv): string
    {
        $this->assertValidCipher($cipher);
        $this->assertValidIv($cipher, $iv);

        $result = openssl_encrypt(
            $data,
            $cipher,
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );

        if (false === $result) {
            throw new LogicException('AES encryption failed.');
        }

        return $result;
    }

    /**
     * Decrypt a single block without unpadding.
     *
     * @param string $data   Ciphertext block.
     * @param string $key    Raw AES key.
     * @param string $cipher OpenSSL cipher method.
     * @param string $iv     Initialization vector.
     *
     * @return string Decrypted block (may contain padding bytes).
     */
    public function decryptBlock(string $data, string $key, string $cipher, string $iv): string
    {
        $this->assertValidCipher($cipher);
        $this->assertValidIv($cipher, $iv);

        $result = openssl_decrypt(
            $data,
            $cipher,
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );

        if (false === $result) {
            throw new LogicException('AES decryption failed.');
        }

        return $result;
    }

    /**
     * Applies ANSI X.923 padding to $text so its length is a multiple of the block size.
     *
     * @param string $text Plaintext to pad.
     *
     * @return string Padded plaintext.
     */
    public function pad(string $text): string
    {
        $paddingSize = $this->blockSize - (strlen($text) % $this->blockSize);

        return $text . str_repeat(chr(0), $paddingSize - 1) . chr($paddingSize & 0xFF);
    }

    /**
     * Strips ANSI X.923 padding from a decrypted block.
     *
     * @param string $text Decrypted, padded text.
     *
     * @return string Unpadded plaintext.
     */
    public function unpad(string $text): string
    {
        $length = ord($text[strlen($text) - 1]);

        if (!$length || $length > $this->blockSize) {
            throw new LogicException('Length incorrect.');
        }

        return substr($text, 0, -$length);
    }

    private function assertValidCipher(string $cipher): void
    {
        if (!in_array($cipher, openssl_get_cipher_methods(), true)) {
            throw new LogicException(sprintf('Unknown cipher: %s.', $cipher));
        }
    }

    private function assertValidIv(string $cipher, string $iv): void
    {
        $expectedLength = openssl_cipher_iv_length($cipher);

        if ($expectedLength > 0 && strlen($iv) !== $expectedLength) {
            throw new LogicException(sprintf(
                'IV length must be %d bytes, got %d.',
                $expectedLength,
                strlen($iv),
            ));
        }
    }
}
