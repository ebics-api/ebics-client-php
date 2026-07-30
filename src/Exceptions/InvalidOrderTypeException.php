<?php

namespace EbicsApi\Ebics\Exceptions;

/**
 * InvalidOrderTypeException used for 091005 EBICS error
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Guillaume Sainthillier
 */
final class InvalidOrderTypeException extends EbicsResponseException
{
    public function __construct(?string $responseMessage = null)
    {
        parent::__construct(
            '091005',
            $responseMessage,
            'Upon verification, the bank finds that the order type specified is not valid.'
        );
    }
}
