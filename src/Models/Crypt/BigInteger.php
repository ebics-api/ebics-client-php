<?php

namespace EbicsApi\Ebics\Models\Crypt;

use EbicsApi\Ebics\Contracts\Crypt\BigIntegerInterface;
use LogicException;

/**
 * Pure-PHP arbitrary precision integer arithmetic library.
 *
 * Supports base-10 and base-256 numbers.  Uses the BCMath extension.
 */
final class BigInteger implements BigIntegerInterface
{
    /**
     * Holds the BigInteger's value.
     *
     * @var mixed
     */
    protected mixed $value;

    /**
     * Holds the BigInteger's magnitude.
     */
    protected bool $isNegative = false;

    /**
     * Precision
     */
    protected int $precision = -1;

    /**
     * Precision Bitmask
     *
     * @var BigIntegerInterface|false
     */
    protected BigIntegerInterface|false $bitmask = false;

    /**
     * Converts base-10, and binary strings (base-256) to BigIntegers.
     *
     * If the second parameter - $base - is negative, then it will be assumed that the number's are encoded using
     * two's compliment.  The sole exception to this is -10, which is treated the same as 10 is.
     *
     * @param int|string $x base-10 number or base-$base number if $base set.
     * @param int $base
     */
    public function __construct(int|string $x = 0, int $base = 10)
    {
        if (!defined('PHP_INT_SIZE')) {
            define('PHP_INT_SIZE', 4);
        }

        $this->value = '0';

        // '0' counts as empty() but when the base is 256 '0' is equal to ord('0') or 48
        // '0' is the only value like this per http://php.net/empty
        if (empty($x) && (abs($base) != 256 || $x !== '0')) {
            return;
        }

        switch ($base) {
            case -256:
                if (ord(((string)$x)[0]) & 0x80) {
                    $x = ~$x;
                    $this->isNegative = true;
                }
            // no break
            case 256:
                // round $len to the nearest 4 (thanks, DavidMJ!)
                $len = (strlen((string)$x) + 3) & 0xFFFFFFFC;

                $x = str_pad((string)$x, $len, chr(0), STR_PAD_LEFT);

                for ($i = 0; $i < $len; $i += 4) {
                    $this->value = bcmul($this->value, '4294967296', 0); // 4294967296 == 2**32
                    $this->value = bcadd(
                        $this->value,
                        (string)(0x1000000 * ord($x[$i]) +
                            ((ord($x[$i + 1]) << 16) | (ord($x[$i + 2]) << 8) | ord($x[$i + 3]))),
                        0
                    );
                }

                if ($this->isNegative) {
                    $this->value = '-' . $this->value;
                }


                if ($this->isNegative) {
                    $this->isNegative = false;

                    $temp = $this->add(new self('-1'));
                    $this->value = $temp->getValue();
                }
                break;
            case 10:
            case -10:
                // (?<!^)(?:-).*: find any -'s that aren't at the beginning and then any characters that follow that
                // (?<=^|-)0*: find any 0's that are preceded by the start of the string or by a - (ie. octals)
                // [^-0-9].*: find any non-numeric characters and then any characters that follow that
                $x = preg_replace('#(?<!^)(?:-).*|(?<=^|-)0*|[^-0-9].*#', '', (string)$x);
                if (!strlen($x) || $x == '-') {
                    $x = '0';
                }

                $this->value = $x === '-' ? '0' : (string)$x;
                break;
            default:
                throw new LogicException('Base is not supported');
        }
    }

    public function toBytes($twosCompliment = false)
    {
        if ($twosCompliment) {
            $comparison = $this->compare(new self());
            if ($comparison == 0) {
                return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
            }

            $temp = $comparison < 0 ? $this->add(new self(1)) : $this->copy();
            $bytes = $temp->toBytes();

            if (!strlen($bytes)) { // eg. if the number we're trying to convert is -1
                $bytes = chr(0);
            }

            if ($this->precision <= 0 && (ord($bytes[0]) & 0x80)) {
                $bytes = chr(0) . $bytes;
            }

            return $comparison < 0 ? ~$bytes : $bytes;
        }

        if ($this->value === '0') {
            return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
        }

        $value = '';
        $current = $this->value;

        if ($current[0] == '-') {
            $current = substr($current, 1);
        }

        while (bccomp($current, '0', 0) > 0) {
            $temp = bcmod($current, '16777216');
            $value = chr(($temp >> 16) & 0xFF) . chr(($temp >> 8) & 0xFF) . chr($temp & 0xFF) . $value;
            $current = bcdiv($current, '16777216', 0);
        }

        return $this->precision > 0 ?
            substr(str_pad($value, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
            ltrim($value, chr(0));
    }

    public function toHex($twosCompliment = false): string
    {
        return bin2hex($this->toBytes($twosCompliment));
    }

    public function toString(): string
    {
        if ($this->value === '0') {
            return '0';
        }

        return ltrim($this->value, '0');
    }

    /**
     *  __toString() magic method
     *
     * Will be called, automatically, if you're supporting just PHP5.  If you're supporting PHP4, you'll need to call
     * toString().
     */
    public function __toString()
    {
        return $this->toString();
    }

    public function equals($x): bool
    {
        return $this->value === $x->getValue() && $this->isNegative == $x->isNegative();
    }

    public function copy(): BigInteger
    {
        $temp = new self();
        $temp->value = $this->value;
        $temp->isNegative = $this->isNegative;
        $temp->precision = $this->precision;
        $temp->bitmask = $this->bitmask;
        return $temp;
    }

    public function compare($y): int
    {
        return bccomp($this->value, $y->getValue(), 0);
    }

    public function modPow($e, $n): BigIntegerInterface
    {
        $n = $this->bitmask !== false && $this->bitmask->compare($n) < 0 ? $this->bitmask : $n->abs();

        if ($e->compare(new self()) < 0) {
            $e = $e->abs();

            $temp = $this->modInverse($n);

            return $this->normalize($temp->modPow($e, $n));
        }

        if ($this->compare(new self()) < 0 || $this->compare($n) > 0) {
            [, $temp] = $this->divide($n);
            return $temp->modPow($e, $n);
        }

        $components = [
            'modulus' => $n->toBytes(true),
            'publicExponent' => $e->toBytes(true)
        ];

        $components = [
            'modulus' => pack(
                'Ca*a*',
                2,
                $this->encodeASN1Length(strlen($components['modulus'])),
                $components['modulus']
            ),
            'publicExponent' => pack(
                'Ca*a*',
                2,
                $this->encodeASN1Length(strlen($components['publicExponent'])),
                $components['publicExponent']
            )
        ];

        $RSAPublicKey = pack(
            'Ca*a*a*',
            48,
            $this->encodeASN1Length(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );

        $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . $this->encodeASN1Length(strlen($RSAPublicKey)) . $RSAPublicKey;

        $encapsulated = pack(
            'Ca*a*',
            48,
            $this->encodeASN1Length(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );

        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($encapsulated)) .
            '-----END PUBLIC KEY-----';

        $plaintext = str_pad($this->toBytes(), strlen($n->toBytes(true)) - 1, "\0", STR_PAD_LEFT);

        if (!openssl_public_encrypt($plaintext, $result, $RSAPublicKey, OPENSSL_NO_PADDING)) {
            throw new LogicException('Public encrypt failed.');
        }

        return new self($result, 256);
    }

    public function multiply($x): BigIntegerInterface
    {
        $temp = new self();
        $temp->setValue(bcmul($this->value, $x->getValue(), 0));

        return $this->normalize($temp);
    }

    public function modInverse($n): BigIntegerInterface
    {
        static $zero, $one;
        if (!isset($zero)) {
            $zero = new self();
            $one = new self(1);
        }

        // $x mod -$n == $x mod $n.
        $n = $n->abs();

        if ($this->compare($zero) < 0) {
            $temp = $this->abs();
            $temp = $temp->modInverse($n);
            return $this->normalize($n->subtract($temp));
        }

        $extendedGcd = $this->extendedGCD($n);

        if (!$extendedGcd['gcd']->equals($one)) {
            throw new LogicException('Values are not equals');
        }

        $x = $extendedGcd['x']->compare($zero) < 0 ? $extendedGcd['x']->add($n) : $extendedGcd['x'];

        return $this->normalize($x);
    }

    /**
     * Divides two BigIntegers.
     *
     * @param BigIntegerInterface $y
     *
     * @return array{0: BigIntegerInterface, 1: BigIntegerInterface}
     */
    public function divide($y): array
    {
        $quotient = new self();
        $remainder = new self();

        $quotient->setValue(bcdiv($this->value, $y->getValue(), 0));
        $remainder->setValue(bcmod($this->value, $y->getValue()));

        if ($remainder->value[0] == '-') {
            $remainder->setValue(
                bcadd(
                    $remainder->value,
                    $y->getValue()[0] == '-' ? substr($y->getValue(), 1) : $y->getValue(),
                    0
                )
            );
        }

        return [$this->normalize($quotient), $this->normalize($remainder)];
    }

    public function subtract($y): BigIntegerInterface
    {
        $temp = new self();
        $temp->setValue(bcsub($this->value, $y->getValue(), 0));

        return $this->normalize($temp);
    }

    public function add($y): BigIntegerInterface
    {
        $temp = new self();
        $temp->setValue(bcadd($this->value, $y->getValue(), 0));

        return $this->normalize($temp);
    }

    public function random($arg1, $arg2 = false): BigIntegerInterface
    {
        if ($arg2 === false) {
            $max = $arg1;
            $min = $this;
        } else {
            $min = $arg1;
            $max = $arg2;
        }

        $compare = $max->compare($min);

        if (!$compare) {
            return $this->normalize($min);
        } elseif ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        static $one;
        if (!isset($one)) {
            $one = new self(1);
        }

        $max = $max->subtract($min->subtract($one));
        $size = strlen(ltrim($max->toBytes(), chr(0)));

        /*
            doing $random % $max doesn't work because some numbers will be more likely to occur than others.
            eg. if $max is 140 and $random's max is 255 then that'd mean both $random = 5 and $random = 145
            would produce 5 whereas the only value of random that could produce 139 would be 139. ie.
            not all numbers would be equally likely. some would be more likely than others.

            creating a whole new random number until you find one that is within the range doesn't work
            because, for sufficiently small ranges, the likelihood that you'd get a number within that range
            would be pretty small. eg. with $random's max being 255 and if your $max being 1 the probability
            would be pretty high that $random would be greater than $max.
        */
        $randomMax = new self(chr(1) . str_repeat("\0", $size), 256);
        $random = $this->randomNumberHelper($size);

        [$maxMultiple] = $randomMax->divide($max);
        $maxMultiple = $maxMultiple->multiply($max);

        while ($random->compare($maxMultiple) >= 0) {
            $random = $random->subtract($maxMultiple);
            $randomMax = $randomMax->subtract($maxMultiple);
            $random = $random->bitwiseLeftShift(8);
            $random = $random->add($this->randomNumberHelper(1));
            $randomMax = $randomMax->bitwiseLeftShift(8);
            [$maxMultiple] = $randomMax->divide($max);
            $maxMultiple = $maxMultiple->multiply($max);
        }
        [, $random] = $random->divide($max);

        return $this->normalize($random->add($min));
    }

    public function abs(): BigInteger
    {
        $temp = new self();

        $temp->value = (bccomp($this->value, '0', 0) < 0) ? substr($this->value, 1) : $this->value;

        return $temp;
    }

    /**
     * Normalize
     *
     * Removes leading zeros and truncates (if necessary) to maintain the appropriate precision
     *
     * @param BigIntegerInterface $result
     *
     * @return BigIntegerInterface
     */
    private function normalize(BigIntegerInterface $result): BigIntegerInterface
    {
        $result->setPrecision($this->precision);
        $result->setBitmask($this->bitmask);

        if (!empty($result->bitmask) && !empty($result->bitmask->getValue())) {
            $result->setValue(bcmod($result->getValue(), $result->bitmask->getValue()));
        }

        return $result;
    }

    /**
     * DER-encode an integer
     *
     * The ability to DER-encode integers is needed to create RSA public keys for use with OpenSSL
     *
     * @param int<0, max> $length
     *
     * @return string
     */
    private function encodeASN1Length(int $length): string
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     * Generates a random BigInteger
     *
     * Byte length is equal to $length.
     *
     * @param int $size
     *
     * @return BigIntegerInterface
     */
    private function randomNumberHelper(int $size): BigIntegerInterface
    {
        $random = '';

        if ($size & 1) {
            $random .= chr(mt_rand(0, 255));
        }

        $blocks = $size >> 1;
        for ($i = 0; $i < $blocks; ++$i) {
            // mt_rand(-2147483648, 0x7FFFFFFF) always produces -2147483648 on some systems
            $random .= pack('n', mt_rand(0, 0xFFFF));
        }

        return new self($random, 256);
    }

    /**
     * Calculates the greatest common divisor and Bezout's identity.
     *
     * Say you have 693 and 609.  The GCD is 21.  Bezout's identity states that there exist integers x and y such that
     * 693*x + 609*y == 21.  In point of fact, there are actually an infinite number of x and y combinations and which
     * combination is returned is dependent upon which mode is in use.  See
     * {@link http://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity Bezout's identity - Wikipedia} for more information.
     *
     * @param BigIntegerInterface $n
     *
     * @return array = [
     *     'gcd' => '<BigIntegerInterface>',
     *     'x' => '<BigIntegerInterface>',
     *     'y' => '<BigIntegerInterface>',
     * ]
     */
    /**
     * Extended GCD calculation.
     *
     * @param BigIntegerInterface $n
     *
     * @return array{gcd: BigIntegerInterface, x: BigIntegerInterface, y: BigIntegerInterface}
     */
    private function extendedGCD(BigIntegerInterface $n): array
    {
        // it might be faster to use the binary xGCD algorithim here, as well, but (1) that algorithim works
        // best when the base is a power of 2 and (2) i don't think it'd make much difference, anyway.  as is,
        // the basic extended euclidean algorithim is what we're using.

        $u = $this->value;
        $v = $n->getValue();

        $a = '1';
        $b = '0';
        $c = '0';
        $d = '1';

        while (bccomp($v, '0', 0) != 0) {
            $q = bcdiv($u, $v, 0);

            $temp = $u;
            $u = $v;
            $v = bcsub($temp, bcmul($v, $q, 0), 0);

            $temp = $a;
            $a = $c;
            $c = bcsub($temp, bcmul($a, $q, 0), 0);

            $temp = $b;
            $b = $d;
            $d = bcsub($temp, bcmul($b, $q, 0), 0);
        }

        return [
            'gcd' => $this->normalize(new self($u)),
            'x' => $this->normalize(new self($a)),
            'y' => $this->normalize(new self($b))
        ];
    }

    public function bitwiseLeftShift($shift): BigIntegerInterface
    {
        $temp = new self();

        $temp->setValue(bcmul($this->value, bcpow('2', (string)$shift, 0), 0));

        return $this->normalize($temp);
    }

    public function bitwiseOr($x): BigIntegerInterface
    {
        $left = $this->toBytes();
        $right = $x->toBytes();

        $length = max(strlen($left), strlen($right));

        $left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
        $right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

        return $this->normalize(new self($left | $right, 256));
    }

    public function bitwiseAnd($x): BigIntegerInterface
    {
        $left = $this->toBytes();
        $right = $x->toBytes();

        $length = max(strlen($left), strlen($right));

        $left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
        $right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

        return $this->normalize(new self($left & $right, 256));
    }

    public function setupPrecision($bits): void
    {
        $this->precision = $bits;

        $this->bitmask = new self(bcpow('2', (string)$bits, 0));

        $temp = $this->normalize($this);
        $this->value = $temp->getValue();
    }

    public function bitwiseRightShift($shift): BigIntegerInterface
    {
        $temp = new self();

        $temp->value = bcdiv($this->value, bcpow('2', (string)$shift, 0), 0);

        return $this->normalize($temp);
    }

    public function getValue()
    {
        return $this->value;
    }

    public function setValue($value): void
    {
        $this->value = $value;
    }

    public function setBitmask($bitmask): void
    {
        $this->bitmask = $bitmask;
    }

    public function setPrecision($precision): void
    {
        $this->precision = $precision;
    }

    public function isNegative(): bool
    {
        return $this->isNegative;
    }
}
