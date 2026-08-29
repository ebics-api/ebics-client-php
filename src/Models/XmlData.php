<?php

namespace EbicsApi\Ebics\Models;

use EbicsApi\Ebics\Contracts\OrderDataInterface;

/**
 * Class OrderData represents OrderData model.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
abstract class XmlData extends DOMDocument implements OrderDataInterface
{
    use ChunkableData;

    public function __construct()
    {
        parent::__construct(encoding: 'utf-8');
    }

    public function getContent(): string
    {
        return (string)$this->saveXML();
    }

    public function getTrimmedContent(): string
    {
        $this->preserveWhiteSpace = false;
        $content = (string)$this->saveXML();

        return preg_replace('/[\r\n]/u', '', $content);
    }

    public function getFormattedContent(): string
    {
        $this->formatOutput = true;

        return (string)$this->saveXML();
    }
}
