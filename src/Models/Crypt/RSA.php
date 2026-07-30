<?php

namespace EbicsApi\Ebics\Models\Crypt;

use EbicsApi\Ebics\Contracts\Crypt\BigIntegerInterface;
use EbicsApi\Ebics\Contracts\Crypt\HashInterface;
use EbicsApi\Ebics\Contracts\Crypt\RSAInterface;
use EbicsApi\Ebics\Contracts\Processor\AESEncryptorInterface;
use EbicsApi\Ebics\Exceptions\DecryptionException;
use LogicException;

/**
 * Pure-PHP PKCS#1 (v2.1) compliant implementation of RSA.
 * Uses encryption mode PKCS1.
 */
final class RSA implements RSAInterface
{
    /**
     * Use the Probabilistic Signature Scheme for signing
     *
     * Uses sha1 by default.
     *
     * @see self::setSaltLength()
     * @see self::setMGFHash()
     */
    const int SIGNATURE_PSS = 1;

    /**
     * Use the PKCS#1 scheme by default.
     *
     * Although self::SIGNATURE_PSS offers more security, including PKCS#1 signing is necessary for purposes of
     * backwards compatibility with protocols (like SSH-2) written before PSS's introduction.
     */
    const int SIGNATURE_PKCS1 = 2;

    /**
     * PKCS#1 formatted private key
     *
     * Used by OpenSSH
     */
    const int PRIVATE_FORMAT_PKCS1 = 0;

    /**
     * Raw public key
     *
     * An array containing two BigInteger objects.
     *
     * The exponent can be indexed with any of the following:
     *
     * 0, e, exponent, publicExponent
     *
     * The modulus can be indexed with any of the following:
     *
     * 1, n, modulo, modulus
     */
    const int PUBLIC_FORMAT_RAW = 3;

    /**
     * @see self::PUBLIC_FORMAT_PKCS1
     */
    const int PUBLIC_FORMAT_PKCS1 = 4;
    const int PUBLIC_FORMAT_PKCS1_RAW = 4;

    /**
     * @see self::PUBLIC_FORMAT_PKCS8
     */
    const int PUBLIC_FORMAT_PKCS8 = 7;

    /**
     * ASN1 Sequence (with the constucted bit set)
     *
     * @see self::ASN1_SEQUENCE
     */
    const int ASN1_SEQUENCE = 48;

    /**
     * ASN1 Integer
     */
    const int ASN1_INTEGER = 2;

    /**
     * ASN1 Bit String
     */
    const int ASN1_BITSTRING = 3;

    /**
     * ASN1 Object Identifier
     */
    const int ASN1_OBJECT = 6;

    /**
     * Modulus length
     */
    protected ?int $k;

    /**
     * Modulus (ie. n)
     */
    protected ?BigIntegerInterface $modulus;

    /**
     * Exponent (ie. e or d)
     */
    protected ?BigIntegerInterface $exponent;

    /**
     * Primes for Chinese Remainder Theorem (ie. p and q)
     * @var array<int, BigIntegerInterface>|null
     */
    protected ?array $primes;

    /**
     * Exponents for Chinese Remainder Theorem (ie. dP and dQ)
     * @var array<int, BigIntegerInterface>|null
     */
    protected ?array $exponents;

    /**
     * Coefficients for Chinese Remainder Theorem (ie. qInv)
     * @var array<int, BigIntegerInterface>|null
     */
    protected ?array $coefficients;

    /**
     * Signature mode
     */
    protected int $signatureMode = self::SIGNATURE_PSS;

    /**
     * Public Exponent
     *
     * @var mixed
     */
    protected $publicExponent = false;

    /**
     * Password.
     */
    protected ?string $password = null;

    /**
     * Public Key Format.
     */
    protected ?int $publicKeyFormat = null;

    /**
     * Private Key Format.
     */
    protected ?int $privateKeyFormat = null;

    /**
     * Hash name.
     */
    protected string $hashName;

    /**
     * Hash function
     */
    protected HashInterface $hash;

    /**
     * Length of hash function output
     */
    protected ?int $hLen = null;

    /**
     * Length of salt
     */
    protected ?int $sLen = null;

    /**
     * Hash function for the Mask Generation Function
     */
    protected HashInterface $mgfHash;

    /**
     * Length of MGF hash function output
     */
    protected int $mgfHLen;

    /**
     * Precomputed Zero
     */
    protected BigInteger $zero;

    /**
     * AES encryptor for symmetric operations.
     */
    protected AESEncryptorInterface $aesEncryptor;

    public function __construct()
    {
        $this->zero = new BigInteger();
    }

    public function setAesEncryptor(AESEncryptorInterface $aesEncryptor): void
    {
        $this->aesEncryptor = $aesEncryptor;
    }

    public function getExponent(): BigIntegerInterface
    {
        return $this->exponent;
    }

    public function getModulus(): BigIntegerInterface
    {
        return $this->modulus;
    }

    public function setPassword($password = null): void
    {
        $this->password = $password;
    }

    public function setPublicKeyFormat($format): void
    {
        $this->publicKeyFormat = $format;
    }

    public function setPrivateKeyFormat($format): void
    {
        $this->privateKeyFormat = $format;
    }

    public function setHash($hash): void
    {
        $this->hash = new Hash($hash);
        $this->hashName = $hash;
        $this->hLen = $this->hash->getLength();
    }

    public function createKey($bits = 1024, $timeout = false, array $partial = []): KeyPair
    {
        if (!defined('CRYPT_RSA_EXPONENT')) {
            // http://en.wikipedia.org/wiki/65537_%28number%29
            define('CRYPT_RSA_EXPONENT', 65537);
        }
        // per <http://cseweb.ucsd.edu/~hovav/dist/survey.pdf#page=5>, this number ought not result
        // in primes smaller than 256 bits. as a consequence if the key you're trying to create is
        // 1024 bits and you've set CRYPT_RSA_SMALLEST_PRIME to 384 bits then you're going to get a
        // 384 bit prime and a 640 bit prime (384 + 1024 % 384). at least if CRYPT_RSA_MODE is set to
        // self::MODE_INTERNAL. if CRYPT_RSA_MODE is set to self::MODE_OPENSSL then CRYPT_RSA_SMALLEST_PRIME
        // is ignored (ie. multi-prime RSA support is more intended as a way to speed up RSA key
        // generation when there's a chance neither gmp nor OpenSSL are installed)
        if (!defined('CRYPT_RSA_SMALLEST_PRIME')) {
            define('CRYPT_RSA_SMALLEST_PRIME', 4096);
        }

        // OpenSSL uses 65537 as the exponent and requires RSA keys be 384 bits minimum
        if ($bits < 384 || CRYPT_RSA_EXPONENT !== 65537) {
            throw new LogicException('Create key conditions are incorrect.');
        }
        if (!($rsa = openssl_pkey_new(['private_key_bits' => $bits]))) {
            throw new LogicException('Openssl pkey new error.');
        }
        openssl_pkey_export($rsa, $privatekey, null);
        if (!($publickey = openssl_pkey_get_details($rsa))) {
            throw new LogicException('Openssl pkey get details error.');
        }
        $publickey = $publickey['key'];

        $parsedKey = $this->parseKey($privatekey, self::PRIVATE_FORMAT_PKCS1);
        if (!is_array($parsedKey)) {
            throw new LogicException('Parse key error.');
        }
        $privatekey = $this->convertPrivateKey(
            $parsedKey['modulus'],
            $parsedKey['publicExponent'],
            $parsedKey['privateExponent'],
            $parsedKey['primes'],
            $parsedKey['exponents'],
            $parsedKey['coefficients']
        );

        $parsedKey = $this->parseKey($publickey, self::PUBLIC_FORMAT_PKCS1);
        if (!is_array($parsedKey)) {
            throw new LogicException('Parse key error.');
        }
        $publickey = $this->convertPublicKey(
            $parsedKey['modulus'],
            $parsedKey['publicExponent']
        );

        // clear the buffer of error strings stemming from a minimalistic openssl.cnf
        while (openssl_error_string() !== false) {
        }

        return new KeyPair(
            new Key($publickey, self::PUBLIC_FORMAT_PKCS1),
            new Key($privatekey, self::PRIVATE_FORMAT_PKCS1),
            $this->password
        );
    }

    /**
     * Break a public or private key down into its constituant components
     *
     * @param string|array<string|int, mixed> $key
     * @param int $type
     *
     * @return array<string, mixed>|bool
     */
    private function parseKey($key, int $type)
    {
        if ($type != self::PUBLIC_FORMAT_RAW && !is_string($key)) {
            return false;
        }

        switch ($type) {
            case self::PUBLIC_FORMAT_RAW:
                if (!is_array($key)) {
                    return false;
                }
                $components = [];
                switch (true) {
                    case isset($key['e']):
                        $components['publicExponent'] = $key['e']->copy();
                        break;
                    case isset($key['exponent']):
                        $components['publicExponent'] = $key['exponent']->copy();
                        break;
                    case isset($key['publicExponent']):
                        $components['publicExponent'] = $key['publicExponent']->copy();
                        break;
                    case isset($key[0]):
                        $components['publicExponent'] = $key[0]->copy();
                }
                switch (true) {
                    case isset($key['n']):
                        $components['modulus'] = $key['n']->copy();
                        break;
                    case isset($key['modulo']):
                        $components['modulus'] = $key['modulo']->copy();
                        break;
                    case isset($key['modulus']):
                        $components['modulus'] = $key['modulus']->copy();
                        break;
                    case isset($key[1]):
                        $components['modulus'] = $key[1]->copy();
                }

                return isset($components['modulus']) && isset($components['publicExponent']) ? $components : false;
            case self::PRIVATE_FORMAT_PKCS1:
            case self::PUBLIC_FORMAT_PKCS1:
                /* Although PKCS#1 proposes a format that public and private keys can use, encrypting
                   them is "outside the scope" of PKCS#1.  PKCS#1 then refers you to PKCS#12 and PKCS#15
                   if you're wanting to protect private keys, however, that's not what OpenSSL* does.
                   OpenSSL protects private keys by adding two new "fields" to the key - DEK-Info and
                   Proc-Type.  These fields are discussed here:

                   http://tools.ietf.org/html/rfc1421#section-4.6.1.1
                   http://tools.ietf.org/html/rfc1421#section-4.6.1.3

                   DES-EDE3-CBC as an algorithm, however, is not discussed anywhere, near as I can tell.
                   DES-CBC and DES-EDE are discussed in RFC1423, however, DES-EDE3-CBC isn't, nor is its
                   key derivation function.  As is, the definitive authority on this encoding scheme isn't
                   the IETF but rather OpenSSL's own implementation.  ie. the implementation *is* the
                   standard and any bugs that may exist in that implementation are part of the standard, as well.

                   * OpenSSL is the de facto standard.  It's utilized by OpenSSH and other projects */
                if (preg_match('#DEK-Info: (.+),(.+)#', $key, $matches)) {
                    $iv = pack('H*', trim($matches[2]));

                    $symkey = pack('H*', md5($this->password . substr($iv, 0, 8))); // symkey is short for symmetric key
                    $symkey .= pack('H*', md5($symkey . $this->password . substr($iv, 0, 8)));

                    // remove the Proc-Type / DEK-Info sections as they're no longer needed
                    $key = preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $key);
                    $ciphertext = $this->extractBER($key);
                    switch ($matches[1]) {
                        case 'AES-256-CBC':
                            $decoded = $this->aesEncryptor->decrypt($ciphertext, [
                                'key' => $symkey,
                                'iv' => $iv,
                                'cipher' => 'aes-256-cbc',
                            ]);
                            break;
                        case 'DES-EDE3-CBC':
                            $symkey = substr($symkey, 0, 24);
                            $crypto = new TripleDES();
                            $crypto->setKey($symkey);
                            $crypto->setIV($iv);
                            $decoded = $crypto->decrypt($ciphertext);
                            break;
                        default:
                            throw new LogicException('Wrong crypto.');
                    }
                } else {
                    $decoded = $this->extractBER($key);
                }

                $key = $decoded;

                $components = [];

                if (ord($this->stringShift($key)) != self::ASN1_SEQUENCE) {
                    return false;
                }
                if ($this->decodeLength($key) != strlen($key)) {
                    return false;
                }

                $tag = ord($this->stringShift($key));
                /* intended for keys for which OpenSSL's asn1parse returns the following:

                    0:d=0  hl=4 l= 631 cons: SEQUENCE
                    4:d=1  hl=2 l=   1 prim:  INTEGER           :00
                    7:d=1  hl=2 l=  13 cons:  SEQUENCE
                    9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
                   20:d=2  hl=2 l=   0 prim:   NULL
                   22:d=1  hl=4 l= 609 prim:  OCTET STRING

                   ie. PKCS8 keys*/

                if ($tag == self::ASN1_INTEGER && str_starts_with($key, "\x01\x00\x30")) {
                    $this->stringShift($key, 3);
                    $tag = self::ASN1_SEQUENCE;
                }

                if ($tag == self::ASN1_SEQUENCE) {
                    $temp = $this->stringShift($key, $this->decodeLength($key));
                    if (ord($this->stringShift($temp)) != self::ASN1_OBJECT) {
                        return false;
                    }
                    $length = $this->decodeLength($temp);
                    switch ($this->stringShift($temp, $length)) {
                        case "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01": // rsaEncryption
                            break;
                        default:
                            throw new LogicException('Wrong _string_shift');
                    }
                    /* intended for keys for which OpenSSL's asn1parse returns the following:

                        0:d=0  hl=4 l= 290 cons: SEQUENCE
                        4:d=1  hl=2 l=  13 cons:  SEQUENCE
                        6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
                       17:d=2  hl=2 l=   0 prim:   NULL
                       19:d=1  hl=4 l= 271 prim:  BIT STRING */
                    $tag = ord($this->stringShift($key)); // skip over the BIT STRING / OCTET STRING tag
                    $this->decodeLength($key); // skip over the BIT STRING / OCTET STRING length
                    // "The initial octet shall encode, as an unsigned binary integer wtih bit 1 as the least
                    // significant bit, the number of unused bits in the final subsequent octet. The number
                    // shall be in the range zero to seven."
                    //  -- http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf (section 8.6.2.2)
                    if ($tag == self::ASN1_BITSTRING) {
                        $this->stringShift($key);
                    }
                    if (ord($this->stringShift($key)) != self::ASN1_SEQUENCE) {
                        return false;
                    }
                    if ($this->decodeLength($key) != strlen($key)) {
                        return false;
                    }
                    $tag = ord($this->stringShift($key));
                }
                if ($tag != self::ASN1_INTEGER) {
                    return false;
                }

                $length = $this->decodeLength($key);
                $temp = $this->stringShift($key, $length);
                if (strlen($temp) != 1 || ord($temp) > 2) {
                    $components['modulus'] = new BigInteger($temp, 256);
                    $this->stringShift($key); // skip over self::ASN1_INTEGER
                    $length = $this->decodeLength($key);
                    $components[$type == self::PUBLIC_FORMAT_PKCS1 ? 'publicExponent' : 'privateExponent']
                        = new BigInteger($this->stringShift($key, $length), 256);

                    return $components;
                }
                if (ord($this->stringShift($key)) != self::ASN1_INTEGER) {
                    return false;
                }
                $length = $this->decodeLength($key);
                $components['modulus'] = new BigInteger($this->stringShift($key, $length), 256);
                $this->stringShift($key);
                $length = $this->decodeLength($key);
                $components['publicExponent'] = new BigInteger($this->stringShift($key, $length), 256);
                $this->stringShift($key);
                $length = $this->decodeLength($key);
                $components['privateExponent'] = new BigInteger($this->stringShift($key, $length), 256);
                $this->stringShift($key);
                $length = $this->decodeLength($key);
                $components['primes'] = [1 => new BigInteger($this->stringShift($key, $length), 256)];
                $this->stringShift($key);
                $length = $this->decodeLength($key);
                $components['primes'][] = new BigInteger($this->stringShift($key, $length), 256);
                $this->stringShift($key);
                $length = $this->decodeLength($key);
                $components['exponents'] = [1 => new BigInteger($this->stringShift($key, $length), 256)];
                $this->stringShift($key);
                $length = $this->decodeLength($key);
                $components['exponents'][] = new BigInteger($this->stringShift($key, $length), 256);
                $this->stringShift($key);
                $length = $this->decodeLength($key);
                $components['coefficients'] = [2 => new BigInteger($this->stringShift($key, $length), 256)];

                if (!empty($key)) {
                    return false;
                }

                return $components;

            default:
                throw new LogicException('Wrong type');
        }
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param string $string
     * @param int $index
     *
     * @return string
     */
    private function stringShift(string &$string, int $index = 1): string
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);

        return $substr;
    }

    /**
     * DER-decode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3}
     * for more information.
     *
     * @param string $string
     *
     * @return int
     */
    private function decodeLength(string &$string): int
    {
        $length = ord($this->stringShift($string));
        if ($length & 0x80) { // definite length, long form
            $length &= 0x7F;
            $temp = $this->stringShift($string, $length);
            $array = unpack('N', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4));
            if (!is_array($array)) {
                throw new LogicException('Unpack failed');
            }
            [, $length] = $array;
        }

        return $length;
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3}
     * for more information.
     *
     * @param int $length
     *
     * @return string
     */
    private function encodeLength(int $length): string
    {
        if ($length <= 0x7F) {
            return chr($length & 0xFF);
        }

        $temp = ltrim(pack('N', $length), chr(0));

        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     * Extract raw BER from Base64 encoding
     *
     * @param string $str
     *
     * @return string
     */
    private function extractBER(string $str): string
    {
        /* X.509 certs are assumed to be base64 encoded but sometimes they'll have additional things in them
         * above and beyond the ceritificate.
         * ie. some may have the following preceding the -----BEGIN CERTIFICATE----- line:
         *
         * Bag Attributes
         *     localKeyID: 01 00 00 00
         * subject=/O=organization/OU=org unit/CN=common name
         * issuer=/O=organization/CN=common name
         */
        $temp = preg_replace('#.*?^-+[^-]+-+[\r\n ]*$#ms', '', $str, 1);
        // remove the -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- stuff
        $temp = preg_replace('#-+[^-]+-+#', '', $temp);
        // remove new lines
        $temp = str_replace(["\r", "\n", ' '], '', $temp);
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? base64_decode($temp) : false;

        return $temp != false ? $temp : $str;
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @param BigIntegerInterface $n
     * @param BigIntegerInterface $e
     * @param BigIntegerInterface $d
     * @param BigIntegerInterface[] $primes
     * @param BigIntegerInterface[] $exponents
     * @param BigIntegerInterface[] $coefficients
     *
     * @return string
     */
    private function convertPrivateKey(
        BigIntegerInterface $n,
        BigIntegerInterface $e,
        BigIntegerInterface $d,
        array $primes,
        array $exponents,
        array $coefficients
    ): string {
        $signed = true;
        $numPrimes = count($primes);
        $raw = [
            'version' => $numPrimes == 2 ? chr(0) : chr(1), // two-prime vs. multi
            'modulus' => $n->toBytes($signed),
            'publicExponent' => $e->toBytes($signed),
            'privateExponent' => $d->toBytes($signed),
            'prime1' => $primes[1]->toBytes($signed),
            'prime2' => $primes[2]->toBytes($signed),
            'exponent1' => $exponents[1]->toBytes($signed),
            'exponent2' => $exponents[2]->toBytes($signed),
            'coefficient' => $coefficients[2]->toBytes($signed),
        ];

        // if the format in question does not support multi-prime rsa and multi-prime rsa was used,
        // call _convertPublicKey() instead.
        switch ($this->privateKeyFormat) {
            default: // eg. self::PRIVATE_FORMAT_PKCS1
                $components = [];
                foreach ($raw as $name => $value) {
                    $components[$name] = pack(
                        'Ca*a*',
                        self::ASN1_INTEGER,
                        $this->encodeLength(strlen($value)),
                        $value
                    );
                }

                $RSAPrivateKey = implode('', $components);

                if ($numPrimes > 2) {
                    throw new LogicException('Should not be more than 2 primes.');
                }

                $RSAPrivateKey = pack(
                    'Ca*a*',
                    self::ASN1_SEQUENCE,
                    $this->encodeLength(strlen($RSAPrivateKey)),
                    $RSAPrivateKey
                );

                if (!empty($this->password) || is_string($this->password)) {
                    $method = 'DES-EDE3-CBC';
                    if (!($ivLen = openssl_cipher_iv_length($method))) {
                        throw new LogicException('Can no determinate cipher length.');
                    }
                    $iv = openssl_random_pseudo_bytes($ivLen);

                    $symkey = pack('H*', md5($this->password . $iv)); // symkey is short for symmetric key
                    $symkey .= substr(pack('H*', md5($symkey . $this->password . $iv)), 0, 8);

                    $crypt = new TripleDES();
                    $crypt->setKey($symkey);
                    $crypt->setIV($iv);

                    $RSAPrivateKeyEncrypted = $crypt->encrypt($RSAPrivateKey);

                    $iv = strtoupper(bin2hex($iv));
                    $method = strtoupper($method);
                    $RSAPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n" .
                        "Proc-Type: 4,ENCRYPTED\r\n" .
                        "DEK-Info: $method,$iv\r\n" .
                        "\r\n" .
                        chunk_split(base64_encode($RSAPrivateKeyEncrypted), 64) .
                        '-----END RSA PRIVATE KEY-----';
                } else {
                    $RSAPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n" .
                        chunk_split(base64_encode($RSAPrivateKey), 64) .
                        '-----END RSA PRIVATE KEY-----';
                }

                return $RSAPrivateKey;
        }
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @param BigIntegerInterface $n
     * @param BigIntegerInterface $e
     *
     * @return string
     */
    private function convertPublicKey(BigIntegerInterface $n, BigIntegerInterface $e): string
    {
        $signed = true;

        $modulus = $n->toBytes($signed);
        $publicExponent = $e->toBytes($signed);

        switch ($this->publicKeyFormat) {
            default: // eg. self::PUBLIC_FORMAT_PKCS1_RAW or self::PUBLIC_FORMAT_PKCS1
                // from <http://tools.ietf.org/html/rfc3447#appendix-A.1.1>:
                // RSAPublicKey ::= SEQUENCE {
                //     modulus           INTEGER,  -- n
                //     publicExponent    INTEGER   -- e
                // }
                $components = [
                    'modulus' => pack('Ca*a*', self::ASN1_INTEGER, $this->encodeLength(strlen($modulus)), $modulus),
                    'publicExponent' => pack(
                        'Ca*a*',
                        self::ASN1_INTEGER,
                        $this->encodeLength(strlen($publicExponent)),
                        $publicExponent
                    ),
                ];

                $RSAPublicKey = pack(
                    'Ca*a*a*',
                    self::ASN1_SEQUENCE,
                    $this->encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
                    $components['modulus'],
                    $components['publicExponent']
                );

                if ($this->publicKeyFormat == self::PUBLIC_FORMAT_PKCS1_RAW) {
                    $RSAPublicKey = "-----BEGIN RSA PUBLIC KEY-----\r\n" .
                        chunk_split(base64_encode($RSAPublicKey), 64) .
                        '-----END RSA PUBLIC KEY-----';
                } else {
                    // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
                    $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
                    $RSAPublicKey = chr(0) . $RSAPublicKey;
                    $RSAPublicKey = chr(3) . $this->encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

                    $RSAPublicKey = pack(
                        'Ca*a*',
                        self::ASN1_SEQUENCE,
                        $this->encodeLength(strlen($rsaOID . $RSAPublicKey)),
                        $rsaOID . $RSAPublicKey
                    );

                    $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
                        chunk_split(base64_encode($RSAPublicKey), 64) .
                        '-----END PUBLIC KEY-----';
                }

                return $RSAPublicKey;
        }
    }

    public function setPublicKey($key = false): bool
    {
        // if a public key has already been loaded return false
        if (!empty($this->publicExponent)) {
            return false;
        }

        if ($key === false && !empty($this->modulus)) {
            $this->publicExponent = $this->exponent;

            return true;
        }

        if (!is_string($key)) {
            throw new LogicException('Key must be a string.');
        }
        $components = $this->parseKey($key, self::PUBLIC_FORMAT_PKCS1);

        if ($components === false) {
            return false;
        }

        if (!is_array($components)) {
            throw new LogicException('Components must be an array.');
        }

        if (empty($this->modulus) || !$this->modulus->equals($components['modulus'])) {
            $this->modulus = $components['modulus'];
            $this->exponent = $this->publicExponent = $components['publicExponent'];

            return true;
        }

        $this->publicExponent = $components['publicExponent'];

        return true;
    }

    public function loadKey($key, $type = false): bool
    {
        $components = false;
        if ($type === false) {
            $types = [
                self::PUBLIC_FORMAT_RAW,
                self::PRIVATE_FORMAT_PKCS1,
            ];
            foreach ($types as $type) {
                $components = $this->parseKey($key, $type);
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $components = $this->parseKey($key, $type);
        }

        if ($components === false) {
            $this->modulus = null;
            $this->k = null;
            $this->exponent = null;
            $this->primes = null;
            $this->exponents = null;
            $this->coefficients = null;
            $this->publicExponent = null;

            return false;
        }

        if (!is_array($components)) {
            throw new LogicException('Components must be an array.');
        }

        // If key was formed with switched Modulus and Exponent, then change the place of key parts.
        // It can happens for Bank.
        if (isset($components['privateExponent']) && isset($components['modulus'])
            && strlen($components['privateExponent']) > strlen($components['modulus'])
        ) {
            $buffer = $components['privateExponent'];
            $components['privateExponent'] = $components['modulus'];
            $components['modulus'] = $buffer;
        }

        $this->modulus = $components['modulus'];
        $this->k = strlen($this->modulus->toBytes());
        $this->exponent = isset($components['privateExponent']) ?
            $components['privateExponent'] : $components['publicExponent'];
        if (isset($components['primes'])) {
            $this->primes = $components['primes'];
            $this->exponents = $components['exponents'];
            $this->coefficients = $components['coefficients'];
            $this->publicExponent = $components['publicExponent'];
        } else {
            $this->primes = [];
            $this->exponents = [];
            $this->coefficients = [];
            $this->publicExponent = false;
        }

        switch ($type) {
            case self::PUBLIC_FORMAT_RAW:
                $this->setPublicKey();
                break;
            case self::PRIVATE_FORMAT_PKCS1:
                if (!is_string($key)) {
                    throw new LogicException('Key must be a string.');
                }
                switch (true) {
                    case str_contains($key, '-BEGIN PUBLIC KEY-'):
                    case str_contains($key, '-BEGIN RSA PUBLIC KEY-'):
                        $this->setPublicKey();
                }
                break;
            default:
                throw new LogicException('Wrong type.');
        }

        return true;
    }

    public function decrypt($ciphertext): string
    {
        if ($this->k <= 0) {
            throw new DecryptionException('K can not be less than 0.');
        }

        /** @var list<string> */
        $ciphertext = str_split($ciphertext, $this->k);
        if (empty($ciphertext)) {
            throw new DecryptionException('Ciphertext was not split.');
        }
        $ciphertext[count($ciphertext) - 1] = str_pad(
            $ciphertext[count($ciphertext) - 1],
            $this->k,
            chr(0),
            STR_PAD_LEFT
        );

        $plaintext = '';

        foreach ($ciphertext as $c) {
            $temp = $this->rsaesPkcs1V15Decrypt($c);

            $plaintext .= $temp;
        }

        return $plaintext;
    }

    public function encrypt($plaintext): string
    {
        // see the comments of _rsaes_pkcs1_v1_5_decrypt() to understand why this is being done
        if (!defined('CRYPT_RSA_PKCS15_COMPAT')) {
            define('CRYPT_RSA_PKCS15_COMPAT', true);
        }

        $length = $this->k - 11;
        if ($length <= 0) {
            throw new LogicException('Length must be more 0.');
        }

        $plaintext = str_split($plaintext, $length);
        $ciphertext = '';
        foreach ($plaintext as $m) {
            $ciphertext .= $this->rsaesPkcs1V15Encrypt($m);
        }

        return $ciphertext;
    }

    public function getPublicKey($type = RSA::PUBLIC_FORMAT_PKCS8): ?string
    {
        if (empty($this->modulus) || empty($this->publicExponent)) {
            return null;
        }

        $oldFormat = $this->publicKeyFormat;
        $this->publicKeyFormat = $type;
        $temp = $this->convertPublicKey($this->modulus, $this->publicExponent);
        $this->publicKeyFormat = $oldFormat;

        return $temp;
    }

    public function getPrivateKey($type = RSA::PUBLIC_FORMAT_PKCS1): ?string
    {
        if (empty($this->primes)) {
            return null;
        }

        $oldFormat = $this->privateKeyFormat;
        $this->privateKeyFormat = $type;
        $temp = $this->convertPrivateKey(
            $this->modulus,
            $this->publicExponent,
            $this->exponent,
            $this->primes,
            $this->exponents,
            $this->coefficients
        );
        $this->privateKeyFormat = $oldFormat;

        return $temp;
    }

    public function sign($message): ?string
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return null;
        }

        switch ($this->signatureMode) {
            case self::SIGNATURE_PKCS1:
                return $this->rsassaPkcs1V15Sign($message);
            //case self::SIGNATURE_PSS:
            default:
                return $this->rsassaPssSign($message);
        }
    }

    /**
     * Verifies a signature against a message using the loaded public key.
     *
     * Delegates to RSASSA-PSS-VERIFY or RSASSA-PKCS1-V1_5-VERIFY depending
     * on the current signature mode set via setSignatureMode().
     *
     * @param string $message The original message that was signed.
     * @param string $signature The raw binary signature to verify.
     *
     * @return bool True if the signature is valid, false otherwise.
     */
    public function verify(string $message, string $signature): bool
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        switch ($this->signatureMode) {
            case self::SIGNATURE_PKCS1:
                return $this->rsassaPkcs1V15Verify($message, $signature);
            default:
                return $this->rsassaPssVerify($message, $signature);
        }
    }

    /**
     * RSASSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.2 RFC3447#section-8.1.2}.
     *
     * @param string $m The message.
     * @param string $s The signature.
     *
     * @return bool
     */
    private function rsassaPssVerify(string $m, string $s): bool
    {
        if (strlen($s) != $this->k) {
            return false;
        }

        $s2 = $this->os2ip($s);
        $m2 = $this->exponentiate($s2);
        $em = $this->i2osp($m2, $this->k);

        return $this->emsaPssVerify($m, $em, 8 * $this->k - 1);
    }

    /**
     * RSASSA-PKCS1-V1_5-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.2 RFC3447#section-8.2.2}.
     *
     * @param string $m The message.
     * @param string $s The signature.
     *
     * @return bool
     */
    private function rsassaPkcs1V15Verify(string $m, string $s): bool
    {
        if (strlen($s) != $this->k) {
            return false;
        }

        $s2 = $this->os2ip($s);
        $m2 = $this->exponentiate($s2);
        $em = $this->i2osp($m2, $this->k);
        $em2 = $this->emsaPkcs1V15Encode($m, $this->k);

        return $this->equals($em, $em2);
    }

    /**
     * RSASSA-PKCS1-V1_5-SIGN
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.1 RFC3447#section-8.2.1}.
     *
     * @access private
     *
     * @param string $m
     *
     * @return string
     */
    private function rsassaPkcs1V15Sign(string $m): string
    {
        // EMSA-PKCS1-v1_5 encoding
        $em = $this->emsaPkcs1V15Encode($m, $this->k);

        // RSA signature
        $m = $this->os2ip($em);
        $s = $this->rsasp1($m);
        $s = $this->i2osp($s, $this->k);

        // Output the signature S
        return $s;
    }

    public function emsaPkcs1V15Encode($m, $emLen = null): string
    {
        if (null === $emLen) {
            $emLen = $this->k;
        }

        $h = $this->hash->hash($m);

        // see http://tools.ietf.org/html/rfc3447#page-43
        switch ($this->hashName) {
            case 'sha256':
                $t = pack('H*', '3031300d060960864801650304020105000420');
                break;
            default:
                throw new LogicException('Hash algorithm not supported.');
        }
        $t .= $h;
        $tLen = strlen($t);

        if ($emLen < $tLen + 11) {
            throw new LogicException('Intended encoded message length too short');
        }

        $ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

        $em = "\0\1$ps\0$t";

        return $em;
    }

    /**
     * Octet-String-to-Integer primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.2 RFC3447#section-4.2}.
     *
     * @param int|string $x
     *
     * @return BigIntegerInterface
     */
    private function os2ip(int|string $x): BigIntegerInterface
    {
        return new BigInteger($x, 256);
    }

    /**
     * RSASP1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.2.1 RFC3447#section-5.2.1}.
     *
     * @param BigIntegerInterface $m
     *
     * @return BigIntegerInterface
     */
    private function rsasp1(BigIntegerInterface $m): BigIntegerInterface
    {
        if ($m->compare($this->zero) < 0 || $m->compare($this->modulus) > 0) {
            throw new LogicException('Message representative out of range');
        }

        return $this->exponentiate($m);
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.2}.
     *
     * @param BigIntegerInterface $x
     *
     * @return BigIntegerInterface
     */
    private function exponentiate(BigIntegerInterface $x): BigIntegerInterface
    {
        switch (true) {
            case empty($this->primes):
            case $this->primes[1]->equals($this->zero):
            case empty($this->coefficients):
            case $this->coefficients[2]->equals($this->zero):
            case empty($this->exponents):
            case $this->exponents[1]->equals($this->zero):
                return $x->modPow($this->exponent, $this->modulus);
        }

        $numPrimes = count($this->primes);

        $smallest = $this->primes[1];
        for ($i = 2; $i <= $numPrimes; $i++) {
            if ($smallest->compare($this->primes[$i]) > 0) {
                $smallest = $this->primes[$i];
            }
        }

        $one = new BigInteger(1);

        $r = $one->random($one, $smallest->subtract($one));

        $mI = [
            1 => $this->blind($x, $r, 1),
            2 => $this->blind($x, $r, 2),
        ];
        $h = $mI[1]->subtract($mI[2]);
        $h = $h->multiply($this->coefficients[2]);
        [, $h] = $h->divide($this->primes[1]);
        $m = $mI[2]->add($h->multiply($this->primes[2]));

        $r = $this->primes[1];
        for ($i = 3; $i <= $numPrimes; $i++) {
            $mI = $this->blind($x, $r, $i);

            $r = $r->multiply($this->primes[$i - 1]);

            $h = $mI->subtract($m);
            $h = $h->multiply($this->coefficients[$i]);
            [, $h] = $h->divide($this->primes[$i]);

            $m = $m->add($r->multiply($h));
        }

        return $m;
    }

    /**
     * Performs RSA Blinding
     *
     * Protects against timing attacks by employing RSA Blinding.
     * Returns $x->modPow($this->exponents[$i], $this->primes[$i])
     *
     * @param BigIntegerInterface $x
     * @param BigIntegerInterface $r
     * @param int $i
     *
     * @return BigIntegerInterface
     */
    private function blind(BigIntegerInterface $x, BigIntegerInterface $r, int $i): BigIntegerInterface
    {
        $x = $x->multiply($r->modPow($this->publicExponent, $this->primes[$i]));
        $x = $x->modPow($this->exponents[$i], $this->primes[$i]);

        $r = $r->modInverse($this->primes[$i]);
        $x = $x->multiply($r);
        [, $x] = $x->divide($this->primes[$i]);

        return $x;
    }

    /**
     * Integer-to-Octet-String primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.1 RFC3447#section-4.1}.
     *
     * @param BigIntegerInterface $x
     * @param int $xLen
     *
     * @return string
     */
    private function i2osp(BigIntegerInterface $x, int $xLen): string
    {
        $x = $x->toBytes();
        if (strlen($x) > $xLen) {
            throw new LogicException('Integer too large');
        }

        return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * RSAES-PKCS1-V1_5-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.1 RFC3447#section-7.2.1}.
     *
     * @param string $m
     *
     * @return string
     */
    private function rsaesPkcs1V15Encrypt(string $m): string
    {
        $mLen = strlen($m);

        // Length checking
        if ($mLen > $this->k - 11) {
            throw new LogicException('Message too long');
        }

        // EME-PKCS1-v1_5 encoding
        $psLen = $this->k - $mLen - 3;
        $ps = '';
        while (strlen($ps) != $psLen) {
            $length = $psLen - strlen($ps);
            $temp = openssl_random_pseudo_bytes($length);
            $temp = str_replace("\x00", '', $temp);
            $ps .= $temp;
        }
        $type = 2;
        // see the comments of _rsaes_pkcs1_v1_5_decrypt() to understand why this is being done
        if (defined('CRYPT_RSA_PKCS15_COMPAT')
            && (!isset($this->publicExponent) || $this->exponent !== $this->publicExponent)
        ) {
            $type = 1;
            // "The padding string PS shall consist of k-3-||D|| octets. ...
            // for block type 01, they shall have value FF"
            $ps = str_repeat("\xFF", $psLen);
        }
        $em = chr(0) . chr($type) . $ps . chr(0) . $m;

        // RSA encryption
        $m = $this->os2ip($em);
        $c = $this->rsaep($m);
        $c = $this->i2osp($c, $this->k);

        // Output the ciphertext C
        return $c;
    }

    /**
     * RSAEP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.1}.
     *
     * @param BigIntegerInterface $m
     *
     * @return BigIntegerInterface
     */
    private function rsaep(BigIntegerInterface $m): BigIntegerInterface
    {
        if ($m->compare($this->zero) < 0 || $m->compare($this->modulus) > 0) {
            throw new LogicException('Message representative out of range');
        }

        return $this->exponentiate($m);
    }

    /**
     * RSAES-PKCS1-V1_5-DECRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.2 RFC3447#section-7.2.2}.
     *
     * For compatibility purposes, this function departs slightly from the description given in RFC3447.
     * The reason being that RFC2313#section-8.1 (PKCS#1 v1.5) states that ciphertext's encrypted by the
     * private key should have the second byte set to either 0 or 1 and that ciphertext's encrypted by the
     * public key should have the second byte set to 2.  In RFC3447 (PKCS#1 v2.1), the second byte is supposed
     * to be 2 regardless of which key is used.  For compatibility purposes, we'll just check to make sure the
     * second byte is 2 or less.  If it is, we'll accept the decrypted string as valid.
     *
     * As a consequence of this, a private key encrypted ciphertext produced with RSA may not decrypt
     * with a strictly PKCS#1 v1.5 compliant RSA implementation.  Public key encrypted ciphertext's should but
     * not private key encrypted ciphertext's.
     *
     * @param string $c
     *
     * @return string
     */
    private function rsaesPkcs1V15Decrypt(string $c): string
    {
        // Length checking

        if (strlen($c) != $this->k) { // or if k < 11
            throw new DecryptionException('Decryption error');
        }

        // RSA decryption

        $c = $this->os2ip($c);
        $m = $this->rsadp($c);

        $em = $this->i2osp($m, $this->k);

        // EME-PKCS1-v1_5 decoding

        if (ord($em[0]) != 0 || ord($em[1]) > 2) {
            throw new DecryptionException('Decryption error');
        }

        $ps = substr($em, 2, strpos($em, chr(0), 2) - 2);
        $m = substr($em, strlen($ps) + 3);

        if (strlen($ps) < 8) {
            throw new DecryptionException('Decryption error');
        }

        // Output M

        return $m;
    }

    /**
     * RSADP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.2 RFC3447#section-5.1.2}.
     *
     * @param BigIntegerInterface $c
     *
     * @return BigIntegerInterface
     */
    private function rsadp(BigIntegerInterface $c): BigIntegerInterface
    {
        if ($c->compare($this->zero) < 0 || $c->compare($this->modulus) > 0) {
            throw new DecryptionException('Ciphertext representative out of range');
        }

        return $this->exponentiate($c);
    }

    /**
     * RSASSA-PSS-SIGN
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.1 RFC3447#section-8.1.1}.
     *
     * @param string $m
     *
     * @return string
     */
    private function rsassaPssSign(string $m): string
    {
        // EMSA-PSS encoding

        $em = $this->emsaPssEncode($m, 8 * $this->k - 1);

        // RSA signature

        $m = $this->os2ip($em);
        $s = $this->rsasp1($m);
        $s = $this->i2osp($s, $this->k);

        // Output the signature S

        return $s;
    }

    public function emsaPssEncode($m, $emBits = null): string
    {
        if (null === $emBits) {
            $emBits = 8 * $this->k - 1;
        }
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 1) >> 3; // ie. ceil($emBits / 8)
        $sLen = $this->sLen !== null ? $this->sLen : $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            throw new LogicException('Encoding error');
        }

        $salt = openssl_random_pseudo_bytes($sLen);
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h = $this->hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $this->hLen - 2);
        $db = $ps . chr(1) . $salt;
        $dbMask = $this->mgf1($h, $emLen - $this->hLen - 1);
        $maskedDB = $db ^ $dbMask;
        if (empty($maskedDB)) {
            throw new LogicException('maskedDB can not be empty');
        }
        $maskedDB[0] = chr(~(0xFF << ($emBits & 7)) & ord($maskedDB[0]) & 0xFF);
        $em = $maskedDB . $h . chr(0xBC);

        return $em;
    }

    public function emsaPssVerify($m, $em, $emBits = null): bool
    {
        if (null === $emBits) {
            $emBits = 8 * $this->k - 1;
        }
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 7) >> 3; // ie. ceil($emBits / 8);
        $sLen = $this->sLen !== null ? $this->sLen : $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            return false;
        }

        if ($em[strlen($em) - 1] != chr(0xBC)) {
            return false;
        }

        $maskedDB = substr($em, 0, -$this->hLen - 1);
        $h = substr($em, -$this->hLen - 1, $this->hLen);
        $temp = chr((0xFF << ($emBits & 7)) & 0xFF);
        if ((chr(~ord($maskedDB[0]) & 0xFF) & $temp) != $temp) {
            return false;
        }
        $dbMask = $this->mgf1($h, $emLen - $this->hLen - 1);
        $db = $maskedDB ^ $dbMask;
        $db[0] = chr(~(0xFF << ($emBits & 7)) & ord($db[0]) & 0xFF);
        $temp = $emLen - $this->hLen - $sLen - 2;
        if (substr($db, 0, $temp) != str_repeat(chr(0), $temp) || ord($db[$temp]) != 1) {
            return false;
        }
        $salt = substr($db, $temp + 1); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h2 = $this->hash->hash($m2);

        return $this->equals($h, $h2);
    }

    /**
     * MGF1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#appendix-B.2.1 RFC3447#appendix-B.2.1}.
     *
     * @param string $mgfSeed
     * @param int $maskLen
     *
     * @return string
     */
    private function mgf1(string $mgfSeed, int $maskLen): string
    {
        // if $maskLen would yield strings larger than 4GB, PKCS#1 suggests a "Mask too long" error be output.

        $t = '';
        $count = ceil($maskLen / $this->mgfHLen);
        for ($i = 0; $i < $count; $i++) {
            $c = pack('N', $i);
            $t .= $this->mgfHash->hash($mgfSeed . $c);
        }

        return substr($t, 0, $maskLen);
    }

    public function setMGFHash($hash): void
    {
        // Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        $this->mgfHash = new Hash($hash);
        $this->mgfHLen = $this->mgfHash->getLength();
    }

    public function setSignatureMode($mode): void
    {
        $this->signatureMode = $mode;
    }

    /**
     * Performs blinded RSA equality testing
     *
     * Protects against a particular type of timing attack described.
     *
     * See {@link http://codahale.com/a-lesson-in-timing-attacks/ A Lesson In Timing Attacks (or,
     * Don't use MessageDigest.isEquals)}
     *
     * Thanks for the heads up singpolyma!
     *
     * @access private
     *
     * @param string $x
     * @param string $y
     *
     * @return bool
     */
    private function equals(string $x, string $y): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($x, $y);
        }

        if (strlen($x) != strlen($y)) {
            return false;
        }

        $result = "\0";
        $x ^= $y;
        for ($i = 0; $i < strlen($x); $i++) {
            $result |= $x[$i];
        }

        return $result === "\0";
    }

    /**
     * @inheritDoc
     */
    public function changePassword($keyPair, $oldPassword, $newPassword): KeyPair
    {
        $oldPrivatekey = $keyPair->getPrivateKey()->getKey();

        if (!defined('CRYPT_RSA_EXPONENT')) {
            // http://en.wikipedia.org/wiki/65537_%28number%29
            define('CRYPT_RSA_EXPONENT', 65537);
        }
        // per <http://cseweb.ucsd.edu/~hovav/dist/survey.pdf#page=5>, this number ought not result
        // in primes smaller than 256 bits. as a consequence if the key you're trying to create is
        // 1024 bits and you've set CRYPT_RSA_SMALLEST_PRIME to 384 bits then you're going to get a
        // 384 bit prime and a 640 bit prime (384 + 1024 % 384). at least if CRYPT_RSA_MODE is set to
        // self::MODE_INTERNAL. if CRYPT_RSA_MODE is set to self::MODE_OPENSSL then CRYPT_RSA_SMALLEST_PRIME
        // is ignored (ie. multi-prime RSA support is more intended as a way to speed up RSA key
        // generation when there's a chance neither gmp nor OpenSSL are installed)
        if (!defined('CRYPT_RSA_SMALLEST_PRIME')) {
            define('CRYPT_RSA_SMALLEST_PRIME', 4096);
        }

        $rsa = openssl_pkey_get_private($oldPrivatekey, $oldPassword);

        if ($rsa === false) {
            throw new LogicException('Openssl pkey loading error.');
        }

        if (openssl_pkey_export($rsa, $privatekey, null) === false) {
            throw new LogicException('Openssl pkey get details error.');
        }

        if (!($publickey = openssl_pkey_get_details($rsa))) {
            throw new LogicException('Openssl pkey get details error.');
        }

        $publickey = $publickey['key'];

        $this->setPassword($newPassword);

        $parsedKey = $this->parseKey($privatekey, self::PRIVATE_FORMAT_PKCS1);
        if (!is_array($parsedKey)) {
            throw new LogicException('Parse key error.');
        }
        $privatekey = $this->convertPrivateKey(
            $parsedKey['modulus'],
            $parsedKey['publicExponent'],
            $parsedKey['privateExponent'],
            $parsedKey['primes'],
            $parsedKey['exponents'],
            $parsedKey['coefficients']
        );

        $parsedKey = $this->parseKey($publickey, self::PUBLIC_FORMAT_PKCS1);
        if (!is_array($parsedKey)) {
            throw new LogicException('Parse key error.');
        }
        $publickey = $this->convertPublicKey(
            $parsedKey['modulus'],
            $parsedKey['publicExponent']
        );

        // clear the buffer of error strings stemming from a minimalistic openssl.cnf
        while (openssl_error_string() !== false) {
        }

        return new KeyPair(
            new Key($publickey, self::PUBLIC_FORMAT_PKCS1),
            new Key($privatekey, self::PRIVATE_FORMAT_PKCS1),
            $newPassword
        );
    }
}
