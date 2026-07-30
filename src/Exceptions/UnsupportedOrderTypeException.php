<?php

namespace EbicsApi\Ebics\Exceptions;

/**
 * UnsupportedOrderTypeException used for 091006 EBICS error
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Guillaume Sainthillier
 */
final class UnsupportedOrderTypeException extends EbicsResponseException
{
    public function __construct(?string $responseMessage = null)
    {
        parent::__construct(
            '091006',
            $responseMessage,
            'Upon verification, the bank finds that the order type ' .
            'specified is valid but not supported by the bank.'
        );
    }
}
