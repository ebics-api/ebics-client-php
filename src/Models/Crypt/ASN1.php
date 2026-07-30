<?php

namespace EbicsApi\Ebics\Models\Crypt;

use DateTime;
use DateTimeInterface;
use DateTimeZone;
use EbicsApi\Ebics\Contracts\Crypt\ASN1Interface;
use EbicsApi\Ebics\Contracts\Crypt\BigIntegerInterface;
use LogicException;

/**
 * Pure-PHP ASN.1 Parser
 */
final class ASN1 implements ASN1Interface
{
    /**
     * Tag Classes
     *
     * @link http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=12
     */
    const int CLASS_UNIVERSAL = 0;
    const int CLASS_APPLICATION = 1;
    const int CLASS_CONTEXT_SPECIFIC = 2;
    const int CLASS_PRIVATE = 3;

    /**
     * Universal Tag Numbers
     *
     * @link http://www.obj-sys.com/asn1tutorial/node124.html
     */
    const int TYPE_BOOLEAN = 1;
    const int TYPE_INTEGER = 2;
    const int TYPE_BIT_STRING = 3;
    const int TYPE_OCTET_STRING = 4;
    const int TYPE_NULL = 5;
    const int TYPE_OBJECT_IDENTIFIER = 6;
    const int TYPE_REAL = 9;
    const int TYPE_ENUMERATED = 10;
    const int TYPE_UTF8_STRING = 12;
    const int TYPE_SEQUENCE = 16; // SEQUENCE OF
    const int TYPE_SET = 17; // SET OF

    /**
     * Additional Universal String Type Numbers
     *
     * @link http://www.obj-sys.com/asn1tutorial/node10.html
     */
    const int TYPE_NUMERIC_STRING = 18;
    const int TYPE_PRINTABLE_STRING = 19;
    const int TYPE_TELETEX_STRING = 20; // T61String
    const int TYPE_VIDEOTEX_STRING = 21;
    const int TYPE_IA5_STRING = 22;
    const int TYPE_UTC_TIME = 23;
    const int TYPE_GENERALIZED_TIME = 24;
    const int TYPE_GRAPHIC_STRING = 25;
    const int TYPE_VISIBLE_STRING = 26; // ISO646String
    const int TYPE_GENERAL_STRING = 27;
    const int TYPE_UNIVERSAL_STRING = 28;
    const int TYPE_BMP_STRING = 30;

    /**
     * Tag Aliases
     *
     * These tags are kinda placeholders for other tags.
     */
    const int TYPE_CHOICE = -1;
    const int TYPE_ANY = -2;

    /**
     * ASN.1 object identifier
     *
     * @link http://en.wikipedia.org/wiki/Object_identifier
     * @var array<string, string>
     */
    protected array $oids = [];

    /**
     * Default date format
     *
     * @link http://php.net/class.datetime
     */
    protected string $format = 'D, d M Y H:i:s O';

    /**
     * Filters
     *
     * If the mapping type is self::TYPE_ANY what do we actually encode it as?
     * @var array<string, mixed>
     */
    protected array $filters;

    /**
     * Type mapping table for the ANY type.
     *
     * Unambiguous types get the direct mapping (int/real/bool).
     * Others are mapped as a choice, with an extra indexing level.
     * @var array<int, bool|string>
     */
    protected array $ANYmap = [
        self::TYPE_BOOLEAN => true,
        self::TYPE_INTEGER => true,
        self::TYPE_BIT_STRING => 'bitString',
        self::TYPE_OCTET_STRING => 'octetString',
        self::TYPE_NULL => 'null',
        self::TYPE_OBJECT_IDENTIFIER => 'objectIdentifier',
        self::TYPE_REAL => true,
        self::TYPE_ENUMERATED => 'enumerated',
        self::TYPE_UTF8_STRING => 'utf8String',
        self::TYPE_NUMERIC_STRING => 'numericString',
        self::TYPE_PRINTABLE_STRING => 'printableString',
        self::TYPE_TELETEX_STRING => 'teletexString',
        self::TYPE_VIDEOTEX_STRING => 'videotexString',
        self::TYPE_IA5_STRING => 'ia5String',
        self::TYPE_UTC_TIME => 'utcTime',
        self::TYPE_GENERALIZED_TIME => 'generalTime',
        self::TYPE_GRAPHIC_STRING => 'graphicString',
        self::TYPE_VISIBLE_STRING => 'visibleString',
        self::TYPE_GENERAL_STRING => 'generalString',
        self::TYPE_UNIVERSAL_STRING => 'universalString',
        self::TYPE_BMP_STRING => 'bmpString'
    ];

    /**
     * String type to character size mapping table.
     *
     * Non-convertable types are absent from this table.
     * size == 0 indicates variable length encoding.
     * @var array<int, int>
     */
    protected array $stringTypeSize = [
        self::TYPE_UTF8_STRING => 0,
        self::TYPE_BMP_STRING => 2,
        self::TYPE_UNIVERSAL_STRING => 4,
        self::TYPE_PRINTABLE_STRING => 1,
        self::TYPE_TELETEX_STRING => 1,
        self::TYPE_IA5_STRING => 1,
        self::TYPE_VISIBLE_STRING => 1,
    ];

    /**
     * Current location in the ASN.1 document.
     * @var array<int, string>
     */
    protected array $location;

    public function loadOIDs($oids): void
    {
        $this->oids = $oids;
    }

    public function decodeBER($encoded): array
    {
        // Wrap in an array for BC with the old decodeBER return format.
        return [$this->decodeBERInternal($encoded)];
    }

    /**
     * Parse BER-encoding (internal recursive implementation).
     *
     * Decodes a single TLV (Tag-Length-Value) element starting at $encodedPos
     * within $encoded. $start tracks the absolute byte offset within the original
     * input, which is used to compute the 'start' and 'length' fields of each
     * returned element. Recursive calls are made for constructed types
     * (SEQUENCE, SET, BIT STRING, OCTET STRING) and for non-UNIVERSAL classes.
     *
     * @param string $encoded Raw BER-encoded bytes.
     * @param int $start Absolute byte offset of the current element in the original input.
     * @param int $encodedPos Read position within $encoded for the current call.
     *
     * @return array<string, mixed>|false Decoded element array, or false if the data is truncated or invalid.
     */
    private function decodeBERInternal(string $encoded, int $start = 0, int $encodedPos = 0): array|false
    {
        $current = ['start' => $start];

        $type = ord($encoded[$encodedPos++]);
        $start++;

        $constructed = ($type >> 5) & 1;

        $tag = $type & 0x1F;
        if ($tag == 0x1F) {
            $tag = 0;
            // process septets (since the eighth bit is ignored, it's not an octet)
            do {
                 $temp = ord($encoded[$encodedPos++]);
                $loop = $temp >> 7;
                $tag <<= 7;
                $tag |= $temp & 0x7F;
                $start++;
            } while ($loop);
        }

        // Length, as discussed in paragraph 8.1.3 of X.690-0207.pdf#page=13
        $length = ord($encoded[$encodedPos++]);
        $start++;
        if ($length == 0x80) { // indefinite length
            // "[A sender shall] use the indefinite form (see 8.1.3.6) if the encoding is constructed and is not all
            //  immediately available." -- paragraph 8.1.3.2.c
            $length = strlen($encoded) - $encodedPos;
        } elseif ($length & 0x80) { // definite length, long form
            // technically, the long form of the length can be represented by up to 126 octets (bytes), but we'll only
            // support it up to four.
            $length &= 0x7F;
            $temp = substr($encoded, $encodedPos, $length);
            $encodedPos += $length;
            // For long-form definite length, the header length covers the tag byte plus all length octets.
            $current += ['headerlength' => $length + 2];
            $start += $length;

            if (!($unpacked = unpack('Nlength', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4)))) {
                throw new LogicException('Unpack failed.');
            }
            extract($unpacked);
        } else {
            $current += ['headerlength' => 2];
        }

        if ($length > (strlen($encoded) - $encodedPos)) {
            return false;
        }

        $content = substr($encoded, $encodedPos, $length);
        $contentPos = 0;

        // From this point $length reflects only the definite-length value and is not accurate for indefinite forms.

        /* Class is UNIVERSAL, APPLICATION, PRIVATE, or CONTEXT-SPECIFIC. The UNIVERSAL class is restricted to the ASN.1
           built-in types. It defines an application-independent data type that must be distinguishable from all other
           data types. The other three classes are user defined. The APPLICATION class distinguishes data types that
           have a wide, scattered use within a particular presentation context. PRIVATE distinguishes data types within
           a particular organization or country. CONTEXT-SPECIFIC distinguishes members of a sequence or set, the
           alternatives of a CHOICE, or universally tagged set members. Only the class number appears in braces for this
           data type; the term CONTEXT-SPECIFIC does not appear.

             -- http://www.obj-sys.com/asn1tutorial/node12.html */
        $class = ($type >> 6) & 3;
        switch ($class) {
            case self::CLASS_APPLICATION:
            case self::CLASS_PRIVATE:
            case self::CLASS_CONTEXT_SPECIFIC:
                if (!$constructed) {
                    return [
                        'type' => $class,
                        'constant' => $tag,
                        'content' => $content,
                        'length' => $length + $start - $current['start']
                    ];
                }

                $newcontent = [];
                $remainingLength = $length;
                while ($remainingLength > 0) {
                    $temp = $this->decodeBERInternal($content, $start, $contentPos);
                    if ($temp === false) {
                        break;
                    }
                    $length = $temp['length'];
                    // end-of-content octets - see paragraph 8.1.5
                    if (substr($content, $contentPos + $length, 2) == "\0\0") {
                        $length += 2;
                        $start += $length;
                        $newcontent[] = $temp;
                        break;
                    }
                    $start += $length;
                    $remainingLength -= $length;
                    $newcontent[] = $temp;
                    $contentPos += $length;
                }

                return [
                        'type' => $class,
                        'constant' => $tag,
                        // the array encapsulation is for BC with the old format
                        'content' => $newcontent,
                        // the only time when $content['headerlength'] isn't defined is when
                        // the length is indefinite. the absence of $content['headerlength'] is
                        // how we know if something is indefinite or not. technically, it could
                        // be defined to be 2 and then another indicator could be used but whatever.
                        'length' => $start - $current['start']
                    ] + $current;
        }

        $current += ['type' => $tag];

        // decode UNIVERSAL tags
        switch ($tag) {
            case self::TYPE_BOOLEAN:
                // "The contents octets shall consist of a single octet." -- paragraph 8.2.1
                //if (strlen($content) != 1) {
                //    return false;
                //}
                $current['content'] = (bool)ord($content[$contentPos]);
                break;
            case self::TYPE_INTEGER:
            case self::TYPE_ENUMERATED:
                $current['content'] = new BigInteger(substr($content, $contentPos), -256);
                break;
            case self::TYPE_REAL: // not currently supported
                return false;
            case self::TYPE_BIT_STRING:
                // The initial octet shall encode, as an unsigned binary integer with bit 1
                // as the least significant bit, the number of unused bits in the final subsequent octet.
                // The number shall be in the range zero to seven.
                if (!$constructed) {
                    $current['content'] = substr($content, $contentPos);
                } else {
                    $temp = $this->decodeBERInternal($content, $start, $contentPos);
                    if ($temp === false) {
                        return false;
                    }
                    $length -= (strlen($content) - $contentPos);
                }
                break;
            case self::TYPE_OCTET_STRING:
                if (!$constructed) {
                    $current['content'] = substr($content, $contentPos);
                } else {
                    $current['content'] = '';
                    $length = 0;
                    while (substr($content, $contentPos, 2) != "\0\0") {
                        $temp = $this->decodeBERInternal($content, $length + $start, $contentPos);
                        if ($temp === false) {
                            return false;
                        }
                        $contentPos += $temp['length'];
                        // all subtags should be octet strings
                        //if ($temp['type'] != self::TYPE_OCTET_STRING) {
                        //    return false;
                        //}
                        $current['content'] .= $temp['content'];
                        $length += $temp['length'];
                    }
                    if (substr($content, $contentPos, 2) == "\0\0") {
                        $length += 2; // +2 for the EOC
                    }
                }
                break;
            case self::TYPE_NULL:
                // "The contents octets shall not contain any octets." -- paragraph 8.8.2
                //if (strlen($content)) {
                //    return false;
                //}
                break;
            case self::TYPE_SEQUENCE:
            case self::TYPE_SET:
                $offset = 0;
                $current['content'] = [];
                $contentLen = strlen($content);
                while ($contentPos < $contentLen) {
                    // if indefinite length construction was used, and we have an end-of-content string next
                    // see paragraphs 8.1.1.3, 8.1.3.2, 8.1.3.6, 8.1.5, and (for an example) 8.6.4.2
                    if (!isset($current['headerlength']) && substr($content, $contentPos, 2) == "\0\0") {
                        $length = $offset + 2; // +2 for the EOC
                        break 2;
                    }
                    $temp = $this->decodeBERInternal($content, $start + $offset, $contentPos);
                    if ($temp === false) {
                        return false;
                    }
                    $contentPos += $temp['length'];
                    $current['content'][] = $temp;
                    $offset += $temp['length'];
                }
                break;
            case self::TYPE_OBJECT_IDENTIFIER:
                $current['content'] = $this->decodeOID(substr($content, $contentPos));
                break;
            /* Each character string type shall be encoded as if it had been declared:
               [UNIVERSAL x] IMPLICIT OCTET STRING

                 -- X.690-0207.pdf#page=23 (paragraph 8.21.3)

               Per that, we're not going to do any validation.  If there are any illegal characters in the string,
               we don't really care */
            case self::TYPE_NUMERIC_STRING:
                // 0,1,2,3,4,5,6,7,8,9, and space
            case self::TYPE_PRINTABLE_STRING:
                // Upper and lower case letters, digits, space, apostrophe, left/right parenthesis, plus sign, comma,
                // hyphen, full stop, solidus, colon, equal sign, question mark
            case self::TYPE_TELETEX_STRING:
                // The Teletex character set in CCITT's T61, space, and delete
                // see http://en.wikipedia.org/wiki/Teletex#Character_sets
            case self::TYPE_VIDEOTEX_STRING:
                // The Videotex character set in CCITT's T.100 and T.101, space, and delete
            case self::TYPE_VISIBLE_STRING:
                // Printing character sets of international ASCII, and space
            case self::TYPE_IA5_STRING:
                // International Alphabet 5 (International ASCII)
            case self::TYPE_GRAPHIC_STRING:
                // All registered G sets, and space
            case self::TYPE_GENERAL_STRING:
                // All registered C and G sets, space and delete
            case self::TYPE_UTF8_STRING:
                // Unicode encoded as UTF-8
            case self::TYPE_BMP_STRING:
                $current['content'] = substr($content, $contentPos);
                break;
            case self::TYPE_UTC_TIME:
            case self::TYPE_GENERALIZED_TIME:
                $current['content'] = $this->decodeTime(substr($content, $contentPos), $tag);
        }

        $start += $length;

        // The returned 'length' is the total TLV length (tag + length octets + value), not just the value length.
        return $current + ['length' => $start - $current['start']];
    }

    /**
     * BER-decode an OID value.
     *
     * Called by decodeBERInternal(). Reverses the base-128 septet encoding
     * and reconstructs the dotted-decimal OID string, including splitting
     * the first combined octet back into the first two arc components per
     * X.690 §8.19.
     *
     * @param string $content Raw OID value bytes (without tag or length).
     *
     * @return string Dotted-decimal OID string (e.g. '1.2.840.113549').
     */
    private function decodeOID(string $content): string
    {
        static $eighty;
        if (!$eighty) {
            $eighty = new BigInteger(80);
        }

        $oid = [];
        $pos = 0;
        $len = strlen($content);
        $n = new BigInteger();
        while ($pos < $len) {
            $temp = ord($content[$pos++]);
            $n = $n->bitwiseLeftShift(7);
            $n = $n->bitwiseOr(new BigInteger($temp & 0x7F));
            if (~$temp & 0x80) {
                $oid[] = $n;
                $n = new BigInteger();
            }
        }
        $part1 = array_shift($oid);
        $first = floor(ord($content[0]) / 40);
        /*
          "This packing of the first two object identifier components recognizes that only
           three values are allocated from the root node, and at most 39 subsequent values
           from nodes reached by X = 0 and X = 1."

          -- https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=22
        */
        if ($first <= 2) { // ie. 0 <= ord($content[0]) < 120 (0x78)
            array_unshift($oid, ord($content[0]) % 40);
            array_unshift($oid, $first);
        } else {
            array_unshift($oid, $part1->subtract($eighty));
            array_unshift($oid, 2);
        }

        $oid = array_map(static function ($v): string {
            if ($v instanceof BigIntegerInterface) {
                return $v->toString();
            }
            return (string)$v;
        }, $oid);

        return implode('.', $oid);
    }

    /**
     * BER-decode a UTCTime or GeneralizedTime value into a DateTime.
     *
     * Called by decodeBERInternal() and, for implicitly tagged time fields, by asn1map().
     * Handles the two-digit year prefix ambiguity in UTCTime (years >= 50 are mapped to
     * the 1900s, years < 50 to the 2000s), fractional seconds in GeneralizedTime,
     * and both 'Z' (UTC) and explicit ±HHMM timezone suffixes.
     *
     * @param string $content Raw time string from the encoded content bytes.
     * @param int $tag Either self::TYPE_UTC_TIME or self::TYPE_GENERALIZED_TIME.
     *
     * @return DateTime|false Parsed DateTime object, or false if parsing fails.
     */
    private function decodeTime(string $content, int $tag): DateTime|false
    {
        /* UTCTime:
           http://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
           http://www.obj-sys.com/asn1tutorial/node15.html

           GeneralizedTime:
           http://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
           http://www.obj-sys.com/asn1tutorial/node14.html */

        $format = 'YmdHis';

        if ($tag == self::TYPE_UTC_TIME) {
            // https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=28 says "the seconds
            // element shall always be present" but none-the-less I've seen X509 certs where it isn't and if the
            // browsers parse it lib ought to too
            if (preg_match('#^(\d{10})(Z|[+-]\d{4})$#', $content, $matches)) {
                $content = $matches[1] . '00' . $matches[2];
            }
            $prefix = substr($content, 0, 2) >= 50 ? '19' : '20';
            $content = $prefix . $content;
        } elseif (str_contains($content, '.')) {
            $format .= '.u';
        }

        if ($content[strlen($content) - 1] == 'Z') {
            $content = substr($content, 0, -1) . '+0000';
        }

        if (str_contains($content, '-') || str_contains($content, '+')) {
            $format .= 'O';
        }

        return DateTime::createFromFormat($format, $content);
    }

    /**
     * ASN.1 Map
     *
     * Provides an ASN.1 semantic mapping ($mapping) from a parsed BER-encoding to a human readable format.
     *
     * "Special" mappings may be applied on a per tag-name basis via $special.
     *
     * @param array<string, mixed> $decoded
     * @param array<string, mixed> $mapping
     * @param array<string, callable> $special
     *
     * @return list<array<int|string, mixed>|string|false|null>|array<int|string, mixed>|string|false|null
     */
    public function asn1map($decoded, $mapping, $special = [])
    {
        if (isset($mapping['explicit']) && is_array($decoded['content'])) {
            $decoded = $decoded['content'][0];
        }

        switch (true) {
            case $mapping['type'] == self::TYPE_ANY:
                $intype = $decoded['type'];
                $inmap = $this->ANYmap[$intype];
                if (is_string($inmap)) {
                    return [$inmap => $this->asn1map($decoded, ['type' => $intype] + $mapping, $special)];
                }
                break;
            case $mapping['type'] == self::TYPE_CHOICE:
                foreach ($mapping['children'] as $key => $option) {
                    switch (true) {
                        case isset($option['constant']) && $option['constant'] == $decoded['constant']:
                        case !isset($option['constant']) && $option['type'] == $decoded['type']:
                            $value = $this->asn1map($decoded, $option, $special);
                            break;
                        case !isset($option['constant']) && $option['type'] == self::TYPE_CHOICE:
                            $v = $this->asn1map($decoded, $option, $special);
                            if (isset($v)) {
                                $value = $v;
                            }
                    }
                    if (isset($value)) {
                        if (isset($special[$key])) {
                            $value = call_user_func($special[$key], $value);
                        }
                        return [$key => $value];
                    }
                }
                return null;
            case isset($mapping['implicit']):
            case isset($mapping['explicit']):
            case $decoded['type'] == $mapping['type']:
                break;
            default:
                // if $decoded['type'] and $mapping['type'] are both strings, but different types of strings,
                // let it through
                switch (true) {
                    case $decoded['type'] < 18: // self::TYPE_NUMERIC_STRING == 18
                    case $decoded['type'] > 30: // self::TYPE_BMP_STRING == 30
                    case $mapping['type'] < 18:
                    case $mapping['type'] > 30:
                        return null;
                }
        }

        if (isset($mapping['implicit'])) {
            $decoded['type'] = $mapping['type'];
        }

        switch ($decoded['type']) {
            case self::TYPE_SEQUENCE:
                $map = [];

                // ignore the min and max
                if (isset($mapping['min']) && isset($mapping['max'])) {
                    $child = $mapping['children'];
                    foreach ($decoded['content'] as $content) {
                        if (($map[] = $this->asn1map($content, $child, $special)) === null) {
                            return null;
                        }
                    }

                    return $map;
                }

                $n = count($decoded['content']);
                $i = 0;

                foreach ($mapping['children'] as $key => $child) {
                    $maymatch = $i < $n; // Match only existing input.
                    if ($maymatch) {
                        $temp = $decoded['content'][$i];

                        if ($child['type'] != self::TYPE_CHOICE) {
                            // Get the mapping and input class & constant.
                            $childClass = $tempClass = self::CLASS_UNIVERSAL;
                            $constant = null;
                            if (isset($temp['constant'])) {
                                $tempClass = $temp['type'];
                            }
                            if (isset($child['class'])) {
                                $childClass = $child['class'];
                                $constant = $child['cast'];
                            } elseif (isset($child['constant'])) {
                                $childClass = self::CLASS_CONTEXT_SPECIFIC;
                                $constant = $child['constant'];
                            }

                            if (isset($constant) && isset($temp['constant'])) {
                                // Can only match if constants and class match.
                                $maymatch = $constant == $temp['constant'] && $childClass == $tempClass;
                            } else {
                                // Can only match if no constant expected and type matches or is generic.
                                $maymatch = !isset($child['constant']) &&
                                    in_array($child['type'], [$temp['type'], self::TYPE_ANY, self::TYPE_CHOICE]);
                            }
                        }
                    }

                    if ($maymatch && isset($temp)) {
                        // Attempt submapping.
                        $candidate = $this->asn1map($temp, $child, $special);
                        $maymatch = $candidate !== null;
                    }

                    if ($maymatch) {
                        // Got the match: use it.
                        if (isset($special[$key])) {
                            $candidate = call_user_func($special[$key], $candidate ?? null);
                        }
                        $map[$key] = $candidate ?? null;
                        $i++;
                    } elseif (isset($child['default'])) {
                        $map[$key] = $child['default']; // Use default.
                    } elseif (!isset($child['optional'])) {
                        return null; // Syntax error.
                    }
                }

                // Fail mapping if all input items have not been consumed.
                return $i < $n ? null : $map;

            // the main diff between sets and sequences is the encapsulation of the foreach in another for loop
            case self::TYPE_SET:
                $map = [];

                // ignore the min and max
                if (isset($mapping['min']) && isset($mapping['max'])) {
                    $child = $mapping['children'];
                    foreach ($decoded['content'] as $content) {
                        if (($map[] = $this->asn1map($content, $child, $special)) === null) {
                            return null;
                        }
                    }

                    return $map;
                }

                for ($i = 0; $i < count($decoded['content']); $i++) {
                    $temp = $decoded['content'][$i];
                    $tempClass = self::CLASS_UNIVERSAL;
                    if (isset($temp['constant'])) {
                        $tempClass = $temp['type'];
                    }

                    foreach ($mapping['children'] as $key => $child) {
                        if (isset($map[$key])) {
                            continue;
                        }
                        $maymatch = true;
                        $candidate = null;
                        if ($child['type'] != self::TYPE_CHOICE) {
                            $childClass = self::CLASS_UNIVERSAL;
                            $constant = null;
                            if (isset($child['class'])) {
                                $childClass = $child['class'];
                                $constant = $child['cast'];
                            } elseif (isset($child['constant'])) {
                                $childClass = self::CLASS_CONTEXT_SPECIFIC;
                                $constant = $child['constant'];
                            }

                            if (isset($constant) && isset($temp['constant'])) {
                                // Can only match if constants and class match.
                                $maymatch = $constant == $temp['constant'] && $childClass == $tempClass;
                            } else {
                                // Can only match if no constant expected and type matches or is generic.
                                $maymatch = !isset($child['constant']) &&
                                    in_array($child['type'], [$temp['type'], self::TYPE_ANY, self::TYPE_CHOICE]);
                            }
                        }

                        if ($maymatch) {
                            // Attempt submapping.
                            $candidate = $this->asn1map($temp, $child, $special);
                            $maymatch = $candidate !== null;
                        }

                        if (!$maymatch) {
                            break;
                        }

                        // Got the match: use it.
                        if (isset($special[$key])) {
                            $candidate = call_user_func($special[$key], $candidate);
                        }
                        $map[$key] = $candidate;
                        break;
                    }
                }

                foreach ($mapping['children'] as $key => $child) {
                    if (!isset($map[$key])) {
                        if (isset($child['default'])) {
                            $map[$key] = $child['default'];
                        } elseif (!isset($child['optional'])) {
                            return null;
                        }
                    }
                }
                return $map;
            case self::TYPE_OBJECT_IDENTIFIER:
                return $this->oids[$decoded['content']] ?? $decoded['content'];
            case self::TYPE_UTC_TIME:
            case self::TYPE_GENERALIZED_TIME:
                // for explicitly tagged optional stuff
                if (is_array($decoded['content'])) {
                    $decoded['content'] = $decoded['content'][0]['content'];
                }
                // for implicitly tagged optional stuff
                // in theory, doing isset($mapping['implicit']) would work but malformed certs do exist
                // in the wild that OpenSSL decodes without issue so we'll support them as well
                if (!is_object($decoded['content'])) {
                    $decoded['content'] = $this->decodeTime($decoded['content'], $decoded['type']);
                }
                return $decoded['content'] instanceof DateTimeInterface ?
                    $decoded['content']->format($this->format) : false;
            case self::TYPE_BIT_STRING:
                if (isset($mapping['mapping'])) {
                    $offset = ord($decoded['content'][0]);
                    $size = (strlen($decoded['content']) - 1) * 8 - $offset;
                    /*
                       From X.680-0207.pdf#page=46 (21.7):

                       "When a "NamedBitList" is used in defining a bitstring type ASN.1 encoding
                        rules are free to add (or remove) arbitrarily any trailing 0 bits to (or from)
                        values that are being encoded or decoded. Application designers should therefore
                        ensure that different semantics are not associated with such values which differ
                        only in the number of trailing 0 bits."
                    */
                    $fillSize = count($mapping['mapping']) - $size;
                    $bits = $fillSize <= 0 ? [] :
                        array_fill(0, $fillSize, false);
                    for ($i = strlen($decoded['content']) - 1; $i > 0; $i--) {
                        $current = ord($decoded['content'][$i]);
                        for ($j = $offset; $j < 8; $j++) {
                            $bits[] = (bool)($current & (1 << $j));
                        }
                        $offset = 0;
                    }
                    $values = [];
                    $map = array_reverse($mapping['mapping']);
                    foreach ($map as $i => $value) {
                        if ($bits[$i]) {
                            $values[] = $value;
                        }
                    }
                    return $values;
                }
            // no break
            case self::TYPE_OCTET_STRING:
                return base64_encode($decoded['content']);
            case self::TYPE_NULL:
                return '';
            case self::TYPE_BOOLEAN:
            case self::TYPE_NUMERIC_STRING:
            case self::TYPE_PRINTABLE_STRING:
            case self::TYPE_TELETEX_STRING:
            case self::TYPE_VIDEOTEX_STRING:
            case self::TYPE_IA5_STRING:
            case self::TYPE_GRAPHIC_STRING:
            case self::TYPE_VISIBLE_STRING:
            case self::TYPE_GENERAL_STRING:
            case self::TYPE_UNIVERSAL_STRING:
            case self::TYPE_UTF8_STRING:
            case self::TYPE_BMP_STRING:
                return $decoded['content'];
            case self::TYPE_INTEGER:
            case self::TYPE_ENUMERATED:
                $temp = $decoded['content'];
                if (isset($mapping['implicit'])) {
                    $temp = new BigInteger($decoded['content'], -256);
                }
                if (isset($mapping['mapping'])) {
                    $temp = (int)$temp->toString();
                    return $mapping['mapping'][$temp] ?? false;
                }
                return $temp;
            default:
                throw new LogicException('Decoded type not handled.');
        }
    }

    public function loadFilters($filters): void
    {
        $this->filters = $filters;
    }

    public function encodeDER($source, $mapping, $special = []): string
    {
        $this->location = [];
        if (!($encodedDer = $this->encodeDERInternal($source, $mapping, null, $special))) {
            throw new LogicException('DER was not encoded.');
        }
        return $encodedDer;
    }

    /**
     * DER-encode a PHP value (internal recursive implementation).
     *
     * Recursively encodes the value in $source according to $mapping. $idx is
     * the field key within the parent SEQUENCE/SET and is used to maintain the
     * internal $location path for filter lookups and error messages. $special
     * holds optional pre-encoding callbacks keyed by field name.
     *
     * Returns an empty string for fields whose value equals the mapping default
     * (i.e. implicitly optional fields that should be omitted from the output).
     *
     * @param mixed $source PHP value to encode.
     * @param array<string, mixed> $mapping ASN.1 type mapping descriptor.
     * @param string|null $idx Field key within the parent structure, or null at the root.
     * @param array<string, callable> $special Optional callbacks keyed by field name, applied before encoding.
     *
     * @return string|false DER-encoded bytes, empty string if omitted, or false on error.
     */
    private function encodeDERInternal($source, array $mapping, ?string $idx = null, array $special = []): string|false
    {
        // do not encode (implicitly optional) fields with value set to default
        if (isset($mapping['default']) && $source === $mapping['default']) {
            return '';
        }

        if (isset($idx)) {
            if (isset($special[$idx])) {
                $source = call_user_func($special[$idx], $source);
            }
            $this->location[] = $idx;
        }

        $tag = $mapping['type'];

        switch ($tag) {
            case self::TYPE_SET: // SET OF children are sorted after encoding; SET children order is not significant.
            case self::TYPE_SEQUENCE:
                $tag |= 0x20; // set the constructed bit

                // ignore the min and max
                if (isset($mapping['min']) && isset($mapping['max'])) {
                    $value = [];
                    $child = $mapping['children'];

                    foreach ($source as $content) {
                        $temp = $this->encodeDERInternal($content, $child, null, $special);
                        if ($temp === false) {
                            return false;
                        }
                        $value[] = $temp;
                    }
                    /* "The encodings of the component values of a set-of value shall appear in ascending
                        order, the encodings being compared as octet strings with the shorter components
                        being padded at their trailing end with 0-octets.  NOTE - The padding octets are for
                        comparison purposes only and do not appear in the encodings."

                       -- sec 11.6 of http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf  */
                    if ($mapping['type'] == self::TYPE_SET) {
                        sort($value);
                    }
                    $value = implode('', $value);
                    break;
                }

                $value = '';
                foreach ($mapping['children'] as $key => $child) {
                    if (!array_key_exists($key, $source)) {
                        if (!isset($child['optional'])) {
                            return false;
                        }
                        continue;
                    }

                    $temp = $this->encodeDERInternal($source[$key], $child, $key, $special);
                    if ($temp === false) {
                        return false;
                    }

                    // An empty child encoding means it has been optimized out.
                    // Else we should have at least one tag byte.
                    if ($temp === '') {
                        continue;
                    }

                    // if isset($child['constant']) is true then isset($child['optional']) should be true as well
                    if (isset($child['constant'])) {
                        /*
                           From X.680-0207.pdf#page=58 (30.6):

                           "The tagging construction specifies explicit tagging if any of the following holds:
                            ...
                            c) the "Tag Type" alternative is used and the value of "TagDefault" for the
                            module is IMPLICIT TAGS or AUTOMATIC TAGS, but the type defined by "Type" is
                            an untagged choice type, an untagged open type, or an untagged "DummyReference"
                            (see ITU-T Rec. X.683 | ISO/IEC 8824-4, 8.3)."
                         */
                        if (isset($child['explicit']) || $child['type'] == self::TYPE_CHOICE) {
                            $subtag = chr(((self::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | $child['constant']) & 0xFF);
                            $temp = $subtag . $this->encodeLength(strlen($temp)) . $temp;
                        } else {
                            $subtag = chr(
                                ((self::CLASS_CONTEXT_SPECIFIC << 6) | (ord(
                                    $temp[0]
                                ) & 0x20) | $child['constant']) & 0xFF
                            );
                            $temp = $subtag . substr($temp, 1);
                        }
                    }
                    $value .= $temp;
                }
                break;
            case self::TYPE_CHOICE:
                $temp = false;

                foreach ($mapping['children'] as $key => $child) {
                    if (!isset($source[$key])) {
                        continue;
                    }

                    $temp = $this->encodeDERInternal($source[$key], $child, $key, $special);
                    if ($temp === false) {
                        return false;
                    }

                    // An empty child encoding means it has been optimized out.
                    // Else we should have at least one tag byte.
                    if ($temp === '') {
                        continue;
                    }

                    $tag = ord($temp[0]);

                    // if isset($child['constant']) is true then isset($child['optional']) should be true as well
                    if (isset($child['constant'])) {
                        if (isset($child['explicit']) || $child['type'] == self::TYPE_CHOICE) {
                            $subtag = chr(((self::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | $child['constant']) & 0xFF);
                            $temp = $subtag . $this->encodeLength(strlen($temp)) . $temp;
                        } else {
                            $subtag = chr(
                                ((self::CLASS_CONTEXT_SPECIFIC << 6) | (ord(
                                    $temp[0]
                                ) & 0x20) | $child['constant']) & 0xFF
                            );
                            $temp = $subtag . substr($temp, 1);
                        }
                    }
                }

                if (isset($idx)) {
                    array_pop($this->location);
                }

                if ($temp && isset($mapping['cast'])) {
                    $temp[0] = chr((($mapping['class'] << 6) | ($tag & 0x20) | $mapping['cast']) & 0xFF);
                }

                return $temp;
            case self::TYPE_INTEGER:
            case self::TYPE_ENUMERATED:
                if (!isset($mapping['mapping'])) {
                    if (is_numeric($source)) {
                        $source = new BigInteger((string)$source);
                    }
                    $value = $source->toBytes(true);
                } else {
                    $value = array_search($source, $mapping['mapping']);
                    if ($value === false) {
                        return false;
                    }
                    $value = new BigInteger($value);
                    $value = $value->toBytes(true);
                }
                if (!strlen($value)) {
                    $value = chr(0);
                }
                break;
            case self::TYPE_UTC_TIME:
            case self::TYPE_GENERALIZED_TIME:
                $format = $mapping['type'] == self::TYPE_UTC_TIME ? 'y' : 'Y';
                $format .= 'mdHis';
                $date = new DateTime($source, new DateTimeZone('GMT'));
                $value = $date->format($format) . 'Z';
                break;
            case self::TYPE_BIT_STRING:
                if (isset($mapping['mapping'])) {
                    $bits = array_fill(0, count($mapping['mapping']), 0);
                    $size = 0;
                    for ($i = 0; $i < count($mapping['mapping']); $i++) {
                        if (in_array($mapping['mapping'][$i], $source)) {
                            $bits[$i] = 1;
                            $size = $i;
                        }
                    }

                    if (isset($mapping['min']) && $mapping['min'] >= 1 && $size < $mapping['min']) {
                        $size = $mapping['min'] - 1;
                    }

                    $offset = 8 - (($size + 1) & 7);
                    $offset = $offset !== 8 ? $offset : 0;

                    $value = chr($offset);

                    for ($i = $size + 1; $i < count($mapping['mapping']); $i++) {
                        unset($bits[$i]);
                    }

                    $bits = implode('', array_pad($bits, $size + $offset + 1, 0));
                    $bytes = explode(' ', rtrim(chunk_split($bits, 8, ' ')));
                    foreach ($bytes as $byte) {
                        $value .= chr((int)bindec($byte) & 0xFF);
                    }

                    break;
                }
            // no break
            case self::TYPE_OCTET_STRING:
                /* The initial octet shall encode, as an unsigned binary integer with bit 1
                   as the least significant bit, the number of unused bits in the final subsequent
                   octet. The number shall be in the range zero to seven.

                   -- http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=16 */
                $value = base64_decode($source);
                break;
            case self::TYPE_OBJECT_IDENTIFIER:
                $value = $this->encodeOID($source);
                break;
            case self::TYPE_ANY:
                $loc = $this->location;
                if (isset($idx)) {
                    array_pop($this->location);
                }

                switch (true) {
                    case !isset($source):
                        return $this->encodeDERInternal(
                            null,
                            ['type' => self::TYPE_NULL] + $mapping,
                            null,
                            $special
                        );
                    case is_int($source):
                    case $source instanceof BigInteger:
                        return $this->encodeDERInternal(
                            $source,
                            ['type' => self::TYPE_INTEGER] + $mapping,
                            null,
                            $special
                        );
                    case is_float($source):
                        return $this->encodeDERInternal(
                            $source,
                            ['type' => self::TYPE_REAL] + $mapping,
                            null,
                            $special
                        );
                    case is_bool($source):
                        return $this->encodeDERInternal(
                            $source,
                            ['type' => self::TYPE_BOOLEAN] + $mapping,
                            null,
                            $special
                        );
                    case is_array($source) && count($source) == 1:
                        $typename = implode('', array_keys($source));
                        $outtype = array_search($typename, $this->ANYmap, true);
                        if ($outtype !== false) {
                            return $this->encodeDERInternal(
                                $source[$typename],
                                ['type' => $outtype] + $mapping,
                                null,
                                $special
                            );
                        }
                }

                $filters = $this->filters;
                foreach ($loc as $part) {
                    if (!isset($filters[$part])) {
                        $filters = false;
                        break;
                    }
                    $filters = $filters[$part];
                }
                if ($filters === false) {
                    throw new LogicException('No filters defined for ' . implode('/', $loc));
                }
                return $this->encodeDERInternal($source, $filters + $mapping, null, $special);
            case self::TYPE_NULL:
                $value = '';
                break;
            case self::TYPE_NUMERIC_STRING:
            case self::TYPE_TELETEX_STRING:
            case self::TYPE_PRINTABLE_STRING:
            case self::TYPE_UNIVERSAL_STRING:
            case self::TYPE_UTF8_STRING:
            case self::TYPE_BMP_STRING:
            case self::TYPE_IA5_STRING:
            case self::TYPE_VISIBLE_STRING:
            case self::TYPE_VIDEOTEX_STRING:
            case self::TYPE_GRAPHIC_STRING:
            case self::TYPE_GENERAL_STRING:
                $value = $source;
                break;
            case self::TYPE_BOOLEAN:
                $value = $source ? "\xFF" : "\x00";
                break;
            default:
                throw new LogicException(
                    'Mapping provides no type definition for ' . implode('/', $this->location)
                );
        }

        if (isset($idx)) {
            array_pop($this->location);
        }

        if (isset($mapping['cast'])) {
            if (isset($mapping['explicit']) || $mapping['type'] == self::TYPE_CHOICE) {
                $value = chr($tag) . $this->encodeLength(strlen($value)) . $value;
                $tag = ($mapping['class'] << 6) | 0x20 | $mapping['cast'];
            } elseif (isset($temp)) {
                $tag = ($mapping['class'] << 6) | (ord($temp[0]) & 0x20) | $mapping['cast'];
            }
        }

        return chr($tag) . $this->encodeLength(strlen($value)) . $value;
    }

    /**
     * DER-encode a length value.
     *
     * Uses short form (single octet) for lengths up to 0x7F, and long form
     * (multi-octet) for larger values. Supports lengths up to (2**8)**4
     * (i.e. fits in four bytes), though the standard allows up to (2**8)**126.
     *
     * @link https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=13 X.690 §8.1.3
     *
     * @param int $length Non-negative integer length value to encode.
     *
     * @return string Encoded length bytes.
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
     * DER-encode an OID value.
     *
     * Called by encodeDERInternal(). Accepts either a dotted-decimal OID string
     * (e.g. '1.2.840.113549') or a name resolvable via the loaded OID map.
     * Encodes the first two arc components into a single octet per X.690 §8.19.4,
     * then encodes subsequent components as base-128 big-endian septets.
     *
     * @param string $source Dotted-decimal OID or OID name.
     *
     * @return string DER-encoded OID value bytes (without tag or length).
     */
    private function encodeOID(string $source): string
    {
        static $mask, $zero, $forty;
        if (!$mask) {
            $mask = new BigInteger(0x7F);
            $zero = new BigInteger();
            $forty = new BigInteger(40);
        }

        $oid = preg_match('#(?:\d+\.)+#', $source) ? $source : array_search($source, $this->oids);
        if ($oid === false) {
            throw new LogicException('Invalid OID');
        }
        $parts = explode('.', (string)$oid);
        $part1 = array_shift($parts);
        $part2 = array_shift($parts);

        $first = new BigInteger($part1);
        $first = $first->multiply($forty);
        $first = $first->add(new BigInteger($part2));

        array_unshift($parts, $first->toString());

        $value = '';
        foreach ($parts as $part) {
            if (!$part) {
                $temp = "\0";
            } else {
                $temp = '';
                $part = new BigInteger($part);
                while (!$part->equals($zero)) {
                    $submask = $part->bitwiseAnd($mask);
                    $submask->setupPrecision(8);
                    $temp = (chr(0x80) | $submask->toBytes()) . $temp;
                    $part = $part->bitwiseRightShift(7);
                }
                $temp[strlen($temp) - 1] = $temp[strlen($temp) - 1] & chr(0x7F);
            }
            $value .= $temp;
        }

        return $value;
    }

    public function convert($in, $from = self::TYPE_UTF8_STRING, $to = self::TYPE_UTF8_STRING): string|false
    {
        if (!isset($this->stringTypeSize[$from]) || !isset($this->stringTypeSize[$to])) {
            return false;
        }
        $insize = $this->stringTypeSize[$from];
        $outsize = $this->stringTypeSize[$to];
        $inlength = strlen($in);
        $out = '';

        for ($i = 0; $i < $inlength;) {
            if ($inlength - $i < $insize) {
                return false;
            }

            // Get an input character as a 32-bit value.
            $c = ord($in[$i++]);
            switch (true) {
                case $insize == 4:
                    $c = ($c << 8) | ord($in[$i++]);
                    $c = ($c << 8) | ord($in[$i++]);
                // no break
                case $insize == 2:
                    $c = ($c << 8) | ord($in[$i++]);
                // no break
                case $insize == 1:
                case ($c & 0x80) == 0x00:
                    break;
                case ($c & 0x40) == 0x00:
                    return false;
                default:
                    $bit = 6;
                    do {
                        if ($bit > 25 || $i >= $inlength || (ord($in[$i]) & 0xC0) != 0x80) {
                            return false;
                        }
                        $c = ($c << 6) | (ord($in[$i++]) & 0x3F);
                        $bit += 5;
                        $mask = 1 << $bit;
                    } while ($c & $bit);
                    $c &= $mask - 1;
                    break;
            }

            // Convert and append the character to output string.
            $v = '';
            switch (true) {
                case $outsize == 4:
                    $v .= chr($c & 0xFF);
                    $c >>= 8;
                    $v .= chr($c & 0xFF);
                    $c >>= 8;
                // no break
                case $outsize == 2:
                    $v .= chr($c & 0xFF);
                    $c >>= 8;
                // no break
                case $outsize == 1:
                    $v .= chr($c & 0xFF);
                    $c >>= 8;
                    if ($c) {
                        return false;
                    }
                    break;
                case ($c & 0x80000000) != 0:
                    return false;
                case $c >= 0x04000000:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x04000000;
                // no break
                case $c >= 0x00200000:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x00200000;
                // no break
                case $c >= 0x00010000:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x00010000;
                // no break
                case $c >= 0x00000800:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x00000800;
                // no break
                case $c >= 0x00000080:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x000000C0;
                // no break
                default:
                    $v .= chr($c & 0xFF);
                    break;
            }
            $out .= strrev($v);
        }
        return $out;
    }

    /**
     * Get property ANYmap.
     *
     * @return array<int, bool|string>
     */
    public function getANYmap(): array
    {
        return $this->ANYmap;
    }

    /**
     * Get property stringTypeSize.
     *
     * @return array<int, int>
     */
    public function getStringTypeSize(): array
    {
        return $this->stringTypeSize;
    }
}
