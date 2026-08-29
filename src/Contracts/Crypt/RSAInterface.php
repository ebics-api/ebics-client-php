<?php

namespace EbicsApi\Ebics\Contracts\Crypt;

use EbicsApi\Ebics\Models\Crypt\KeyPair;
use EbicsApi\Ebics\Models\Crypt\RSA;

/**
 * Crypt RSA representation.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
interface RSAInterface
{
    /**
     * @return BigIntegerInterface
     */
    public function getExponent(): BigIntegerInterface;

    /**
     * @return BigIntegerInterface
     */
    public function getModulus(): BigIntegerInterface;

    /**
     * Defines the public key
     *
     * Some private key formats define the public exponent and some don't.
     * Those that don't define it are problematic when used in certain contexts.
     * For example, in SSH-2, RSA authentication works by sending the public key along with a
     * message signed by the private key to the server.  The SSH-2 server looks the public
     * key up in an index of public keys and if it's present then proceeds to verify the signature.
     * Problem is, if your private key doesn't include the public exponent this won't work unless
     * you manually add the public exponent. Lib tries to guess if the key being used is the public
     * key but in the event that it guesses incorrectly you might still want to explicitly set the
     * key as being public.
     *
     * Do note that when a new key is loaded the index will be cleared.
     *
     * Returns true on success, false on failure
     *
     * @param string|false $key optional
     *
     * @return bool
     */
    public function setPublicKey($key = false): bool;

    /**
     * Sets the password
     *
     * Private keys can be encrypted with a password. To unset the password, pass in the empty string or false.
     * Or rather, pass in $password such that empty($password) && !is_string($password) is true.
     *
     * @param string|null $password
     *
     * @return void
     */
    public function setPassword($password = null): void;

    /**
     * Loads a public or private key
     *
     * Returns true on success and false on failure (ie. an incorrect password was provided or the key was malformed)
     *
     * @param string|array<mixed> $key
     * @param false|int $type optional
     *
     * @return bool
     */
    public function loadKey($key, $type = false): bool;

    /**
     * Decryption
     *
     * @param string $ciphertext
     *
     * @return string
     */
    public function decrypt(string $ciphertext): string;

    /**
     * Encryption
     *
     * Both self::ENCRYPTION_OAEP and self::ENCRYPTION_PKCS1 both place limits on how long $plaintext can be.
     * If $plaintext exceeds those limits it will be broken up so that it does and the resultant ciphertext's will
     * be concatenated together.
     *
     * @param string $plaintext
     *
     * @return string
     */
    public function encrypt(string $plaintext): string;

    /**
     * Determines the public key format.
     *
     * @param int $format
     *
     * @return void
     */
    public function setPublicKeyFormat(int $format): void;

    /**
     * Determines the private key format.
     *
     * @param int $format
     *
     * @return void
     */
    public function setPrivateKeyFormat(int $format): void;

    /**
     * Determines which hashing function should be used.
     *
     * Used with signature production/verification and (if the encryption mode is self::ENCRYPTION_OAEP)
     * encryption and decryption.
     *
     * @param string $hash = 'sha256'
     *
     * @return void
     */
    public function setHash(string $hash): void;

    /**
     * Determines which hashing function should be used for the mask generation function
     *
     * The mask generation function is used by self::ENCRYPTION_OAEP and self::SIGNATURE_PSS and although it's
     * best if Hash and MGFHash are set to the same thing this is not a requirement.
     *
     * @param string $hash = 'sha256'
     *
     * @return void
     */
    public function setMGFHash($hash): void;

    /**
     * Create public / private key pair.
     *
     * @param int $bits
     * @param int|false $timeout
     * @param array<mixed> $partial
     *
     * @return KeyPair
     */
    public function createKey(int $bits = 1024, $timeout = false, array $partial = []): KeyPair;

    /**
     * Returns the public key
     *
     * The public key is only returned under two circumstances - if the private key
     * had the public key embedded within it or if the public key was set via setPublicKey().
     * If the currently loaded key is supposed to be the public key this function won't return
     * it since this library, for the most part, doesn't distinguish between public and private keys.
     *
     * @param int $type optional
     *
     * @return string|null
     */
    public function getPublicKey(int $type = RSA::PUBLIC_FORMAT_PKCS8): ?string;

    /**
     * Returns the private key
     *
     * The private key is only returned if the currently loaded key contains the constituent prime numbers.
     *
     * @param int $type optional
     *
     * @return string|null
     */
    public function getPrivateKey(int $type = RSA::PUBLIC_FORMAT_PKCS1): ?string;

    /**
     * Create a signature
     *
     * @param string $message
     *
     * @return string|null
     */
    public function sign(string $message): ?string;

    /**
     * Set Signature Mode
     *
     * Valid values include self::SIGNATURE_PSS and self::SIGNATURE_PKCS1
     *
     * @param int $mode
     *
     * @return void
     */
    public function setSignatureMode($mode): void;

    /**
     * EMSA-PKCS1-V1_5-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.2 RFC3447#section-9.2}.
     *
     * @param string $m
     * @param int|null $emLen
     *
     * @return string
     */
    public function emsaPkcs1V15Encode($m, $emLen = null): string;

    /**
     * EMSA-PSS-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.1 RFC3447#section-9.1.1}.
     *
     * @param string $m
     * @param int|null $emBits
     *
     * @return string
     */
    public function emsaPssEncode($m, $emBits = null): string;

    /**
     * EMSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.2 RFC3447#section-9.1.2}.
     *
     * @access private
     * @param string $m
     * @param string $em
     * @param int|null $emBits
     * @return bool
     */
    public function emsaPssVerify($m, $em, $emBits = null): bool;

    /**
     * Verify a signature over the message using the loaded public key.
     *
     * Delegates to RSASSA-PSS-VERIFY or RSASSA-PKCS1-V1_5-VERIFY depending
     * on the signature mode set via setSignatureMode().
     *
     * @param string $message The original message that was signed.
     * @param string $signature The raw binary signature to verify.
     *
     * @return bool True if the signature is valid, false otherwise.
     */
    public function verify(string $message, string $signature): bool;

    /**
     * Change password for private key.
     *
     * @param KeyPair $keyPair
     * @param string $oldPassword
     * @param string $newPassword
     *
     * @return KeyPair
     */
    public function changePassword($keyPair, $oldPassword, $newPassword): KeyPair;
}
