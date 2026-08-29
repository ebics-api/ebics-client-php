<?php

namespace EbicsApi\Ebics\Models;

/**
 * Class GenericOrderData represents a generic XML container for order data.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class GenericOrderData extends XmlData
{
    public function shouldChunk(): bool
    {
        return false;
    }
}
