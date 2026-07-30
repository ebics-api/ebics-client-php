<?php

namespace EbicsApi\Ebics\Exceptions;

/**
 * InvalidOrderParamsException used for 091112 EBICS error
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Guillaume Sainthillier
 */
final class InvalidOrderParamsException extends EbicsResponseException
{
    public function __construct(?string $responseMessage = null)
    {
        parent::__construct(
            '091112',
            $responseMessage,
            'In an HVT request, the subscriber specifies the order for which they want ' .
            'to retrieve the VEU transaction details. The HVT request also specifies an offset ' .
            'position in the original order file that marks the starting point of the transaction ' .
            'details to be transmitted. The order details after the specified offset position are returned. ' .
            'If the value specified for offset is higher than the total number of order ' .
            'details, the error EBICS_INVALID_ORDER_PARAMS is returned. ' .
            'The error EBICS_INVALID_ORDER_PARAMS may also be returned for FUL or FDL orders when ' .
            'the there is a mismatch between the order type and file format set up in the server configuration ' .
            'and the request from the client.'
        );
    }
}
