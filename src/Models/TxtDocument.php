<?php

namespace EbicsApi\Ebics\Models;

use EbicsApi\Ebics\Contracts\OrderDataInterface;

/**
 * Class TXT Document.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class TxtDocument implements OrderDataInterface
{
    use ChunkableData;

    private string $content;

    public function getContent(): string
    {
        return $this->content;
    }

    public function getTrimmedContent(): string
    {
        return $this->content;
    }

    public function getFormattedContent(): string
    {
        return $this->content;
    }

    public function setContent(string $content): void
    {
        $this->content = $content;
    }
}
