<?php

namespace EbicsApi\Ebics\Contracts\Crypt;

/**
 * Crypt BigInteger representation.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
interface BigIntegerInterface
{

    /**
     * Converts a BigInteger to a byte string (eg. base-256).
     *
     * @param bool $twosCompliment
     *
     * @return string
     * @internal Converts a base-2**26 number to base-2**8
     */
    public function toBytes($twosCompliment = false);

    /**
     * Converts a BigInteger to a hex string (eg. base-16)).
     *
     * Negative numbers are saved as positive numbers, unless $twosCompliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * @param bool $twosCompliment
     *
     * @return string
     * @internal Converts a base-2**26 number to base-2**8
     */
    public function toHex(bool $twosCompliment = false);

    /**
     * Converts a BigInteger to a base-10 number.
     *
     * @return string
     *
     * @internal Converts a base-2**26 number to base-10**7 (which is pretty much base-10)
     */
    public function toString();

    /**
     * Tests the equality of two numbers.
     *
     * If you need to see if one number is greater than or less than another number, use BigInteger::compare()
     *
     * @param BigIntegerInterface $x
     *
     * @return bool
     */
    public function equals($x);

    /**
     * Copy an object
     *
     * PHP5 passes objects by reference while PHP4 passes by value.  As such, we need a function to guarantee
     * that all objects are passed by value, when appropriate.  More information can be found here:
     *
     * {@link http://php.net/language.oop5.basic#51624}
     *
     * @return BigIntegerInterface
     */
    public function copy();

    /**
     * Compares two numbers.
     *
     * Although one might think !$x->compare($y) means $x != $y, it, in fact, means the opposite.
     * The reason for this is demonstrated thusly:
     *
     * $x  > $y: $x->compare($y)  > 0
     * $x  < $y: $x->compare($y)  < 0
     * $x == $y: $x->compare($y) == 0
     *
     * Note how the same comparison operator is used.  If you want to test for equality, use $x->equals($y).
     *
     * @param BigIntegerInterface $y
     *
     * @return int that is < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal.
     * @internal Could return $this->subtract($x), but that's not as fast as what we do do.
     */
    public function compare(BigIntegerInterface $y);

    /**
     * Performs modular exponentiation.
     *
     * @param BigIntegerInterface $e
     * @param BigIntegerInterface $n
     *
     * @return BigIntegerInterface
     *
     * @internal The most naive approach to modular exponentiation has very unreasonable requirements, and
     *    and although the approach involving repeated squaring does vastly better, it, too, is impractical
     *    for our purposes.  The reason being that division - by far the most complicated and time-consuming
     *    of the basic operations (eg. +,-,*,/) - occurs multiple times within it.
     *
     *    Modular reductions resolve this issue.  Although an individual modular reduction takes more time
     *    then an individual division, when performed in succession (with the same modulo), they're a lot faster.
     *
     *    The two most commonly used modular reductions are Barrett and Montgomery reduction.  Montgomery reduction,
     *    although faster, only works when the gcd of the modulo and of the base being used is 1.  In RSA, when the
     *    base is a power of two, the modulo - a product of two primes - is always going to have a gcd of 1 (because
     *    the product of two odd numbers is odd), but what about when RSA isn't used?
     *
     *    In contrast, Barrett reduction has no such constraint.  As such, some bigint implementations perform a
     *    Barrett reduction after every operation in the modpow function.  Others perform Barrett reductions when the
     *    modulo is even and Montgomery reductions when the modulo is odd.  BigInteger.java's modPow method, however,
     *    uses a trick involving the Chinese Remainder Theorem to factor the even modulo into two numbers - one odd and
     *    the other, a power of two - and recombine them, later.  This is the method that this modPow function uses.
     *    {@link http://islab.oregonstate.edu/papers/j34monex.pdf Montgomery Reduction with Even Modulus} elaborates.
     */
    public function modPow(BigIntegerInterface $e, BigIntegerInterface $n);

    /**
     * Multiplies two BigIntegers
     *
     * @param BigIntegerInterface $x
     *
     * @return BigIntegerInterface
     */
    public function multiply(BigIntegerInterface $x);

    /**
     * Calculates modular inverses.
     *
     * Say you have (30 mod 17 * x mod 17) mod 17 == 1.  x can be found using modular inverses.
     *
     * @param BigIntegerInterface $n
     *
     * @return BigIntegerInterface
     * @internal See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=21 HAC 14.64}
     *    for more information.
     */
    public function modInverse(BigIntegerInterface $n);

    /**
     * Divides two BigIntegers.
     *
     * Returns an array whose first element contains the quotient and whose second element contains the
     * "common residue".  If the remainder would be positive, the "common residue" and the remainder are the
     * same.  If the remainder would be negative, the "common residue" is equal to the sum of the remainder
     * and the divisor (basically, the "common residue" is the first positive modulo).
     *
     * @param BigIntegerInterface $y
     *
     * @return array{0: BigIntegerInterface, 1: BigIntegerInterface}
     * @internal This function is based off of
     *    {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=9 HAC 14.20}.
     */
    public function divide(BigIntegerInterface $y);

    /**
     * Subtracts two BigIntegers.
     *
     * @param BigIntegerInterface $y
     *
     * @return BigIntegerInterface
     * @internal Performs base-2**52 subtraction
     */
    public function subtract(BigIntegerInterface $y);

    /**
     * Adds two BigIntegers.
     *
     * @param BigIntegerInterface $y
     *
     * @return BigIntegerInterface
     * @internal Performs base-2**52 addition
     */
    public function add(BigIntegerInterface $y);

    /**
     * Generate a random number
     *
     * Returns a random number between $min and $max where $min and $max
     * can be defined using one of the two methods:
     *
     * @param BigIntegerInterface $arg1
     * @param BigIntegerInterface|false $arg2
     *
     * @return BigIntegerInterface
     * @internal The API for creating random numbers used to be $a->random($min, $max),
     *   where $a was a BigInteger object. That method is still supported for BC purposes.
     */
    public function random(BigIntegerInterface $arg1, $arg2 = false);

    /**
     * Absolute value.
     *
     * @return BigIntegerInterface
     */
    public function abs();

    /**
     * Logical Left Shift
     *
     * Shifts BigInteger's by $shift bits, effectively multiplying by 2**$shift.
     *
     * @param int $shift
     *
     * @return BigIntegerInterface
     * @internal The only version that yields any speed increases is the internal version.
     */
    public function bitwiseLeftShift(int $shift);

    /**
     * Logical Right Shift
     *
     * Shifts BigInteger's by $shift bits, effectively dividing by 2**$shift.
     *
     * @param int $shift
     *
     * @return BigIntegerInterface
     * @internal The only version that yields any speed increases is the internal version.
     */
    public function bitwiseRightShift(int $shift);

    /**
     * Logical Or
     *
     * @param BigIntegerInterface $x
     *
     * @return BigIntegerInterface
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     */
    public function bitwiseOr(BigIntegerInterface $x);

    /**
     * Logical And
     *
     * @param BigIntegerInterface $x
     *
     * @return BigIntegerInterface
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     */
    public function bitwiseAnd(BigIntegerInterface $x);

    /**
     * Setup Precision
     *
     * Some bitwise operations give different results depending on the precision being used.  Examples include left
     * shift, not, and rotates.
     *
     * @param int $bits
     *
     * @return void
     */
    public function setupPrecision(int $bits);

    /**
     * Get Value.
     *
     * @return mixed
     */
    public function getValue();

    /**
     * Set Value.
     *
     * @param mixed $value
     *
     * @return void
     */
    public function setValue($value);

    /**
     * Set Bitmask.
     *
     * @param BigIntegerInterface|false $bitmask
     *
     * @return void
     */
    public function setBitmask($bitmask);

    /**
     * Set Precision.
     *
     * @param int $precision
     *
     * @return void
     */
    public function setPrecision(int $precision);

    /**
     * Is negative?
     *
     * @return bool
     */
    public function isNegative();
}
