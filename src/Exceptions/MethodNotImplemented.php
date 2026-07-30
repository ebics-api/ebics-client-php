<?php

namespace EbicsApi\Ebics\Exceptions;

use LogicException;

/**
 * MethodNotImplemented error
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class MethodNotImplemented extends LogicException
{
    public function __construct(string $version)
    {
        parent::__construct('The requested method is not implemented for EBICS version ' . $version);
    }
}
