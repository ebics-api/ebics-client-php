<?php

namespace EbicsApi\Ebics\Handlers\Traits;

use DOMNameSpaceNode;
use DOMNode;
use DOMNodeList;
use EbicsApi\Ebics\Exceptions\AlgoEbicsException;

/**
 * Class C14NTrait manage c14n building.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
trait C14NTrait
{
    /**
     * Extract C14N content by path from the XML DOM.
     *
     * @param DOMNodeList<DOMNameSpaceNode|DOMNode> $nodes
     * @param string $algorithm
     *
     * @throws AlgoEbicsException
     */
    private function calculateC14N(
        DOMNodeList $nodes,
        string $algorithm = 'REC-xml-c14n-20010315'
    ): string {
        switch ($algorithm) {
            case 'REC-xml-c14n-20010315':
                $exclusive = false;
                $withComments = false;
                break;
            default:
                throw new AlgoEbicsException(sprintf('Define algo for %s', $algorithm));
        }
        $result = '';

        foreach ($nodes as $node) {
            if ($node instanceof DOMNode) {
                $result .= $node->C14N($exclusive, $withComments);
            }
        }

        return $result;
    }

    /**
     * Canonicalize an XML-DSig node-set (e.g. the elements selected by
     * "#xpointer(//*[@authenticate='true'])").
     *
     * A node-set must be serialized with each node rendered exactly once, in
     * document order. When the selection contains a node and one of its own
     * descendants (nested authenticate="true" markers), the descendant is
     * already part of the ancestor's canonical subtree and must NOT be
     * serialized a second time. Naively concatenating the canonical form of
     * every selected node double-counts such descendants and produces a digest
     * that does not match the bank's signature.
     *
     * If $inContext is true, the canonicalization also propagates every
     * in-scope root namespace (e.g. xmlns:ds / xmlns:xsi declared on the
     * document root) to each top-level selected node. This matches how a
     * standard XML-DSig verifier canonicalizes a node-set in document context,
     * and is necessary for exclusive C14N where PHP drops un-utilized
     * declarations.
     *
     * @param DOMNodeList<DOMNameSpaceNode|DOMNode> $nodes
     */
    private function canonicalizeNodeSet(DOMNodeList $nodes, bool $exclusive, bool $inContext = false): string
    {
        $selected = [];
        foreach ($nodes as $node) {
            if ($node instanceof DOMNode) {
                $selected[] = $node;
            }
        }

        if ([] === $selected) {
            return '';
        }

        $result = '';
        foreach ($selected as $node) {
            if ($this->hasSelectedAncestor($node, $selected)) {
                continue;
            }
            $result .= $inContext
                ? $this->canonicalizeInContext($node, $exclusive)
                : $node->C14N($exclusive, false);
        }

        return $result;
    }

    /**
     * Canonicalize a single element including every namespace in scope from its
     * ancestors (root namespaces such as xmlns:ds / xmlns:xsi).
     *
     * For inclusive C14N ($exclusive=false), PHP's C14N already includes all
     * in-scope root namespaces, so we just return the native result. For
     * exclusive C14N, PHP drops un-utilized declarations, so we manually
     * re-inject any missing in-scope root namespace declarations.
     */
    private function canonicalizeInContext(DOMNode $node, bool $exclusive): string
    {
        $canonical = $node->C14N($exclusive, false);

        // For inclusive C14N, PHP already propagates in-scope root namespaces.
        // The injection is only needed for exclusive C14N.
        if (!$exclusive) {
            return $canonical;
        }

        $inScope = $this->collectInScopeNamespaces($node);
        if ([] === $inScope) {
            return $canonical;
        }

        $present = [];
        if (preg_match_all('/xmlns(:[A-Za-z0-9_.\-]+)?="[^"]*"/', $canonical, $matches)) {
            foreach ($matches[0] as $declaration) {
                if (preg_match('/xmlns:([A-Za-z0-9_.\-]+)=/', $declaration, $m)) {
                    $present['xmlns:' . $m[1]] = true;
                } else {
                    $present['xmlns'] = true;
                }
            }
        }

        $missing = [];
        foreach ($inScope as $prefix => $uri) {
            $key = 'xmlns' === $prefix ? 'xmlns' : 'xmlns:' . $prefix;
            if (!isset($present[$key])) {
                $missing[$key] = $uri;
            }
        }

        if ([] === $missing) {
            return $canonical;
        }

        ksort($missing);
        $insertion = '';
        foreach ($missing as $key => $uri) {
            $insertion .= sprintf(' %s="%s"', $key, $uri);
        }

        return (string) preg_replace('/^<([A-Za-z0-9_.\-:]+)/', '<$1' . $insertion, $canonical, 1);
    }

    /**
     * @return array<string, string> namespace prefix => uri ('' key for default)
     */
    private function collectInScopeNamespaces(DOMNode $node): array
    {
        $namespaces = [];
        $current = $node;
        while ($current instanceof DOMNode) {
            if ($current->hasAttributes()) {
                foreach ($current->attributes as $attribute) {
                    if ('http://www.w3.org/2000/xmlns/' === $attribute->namespaceURI) {
                        $namespaces['xmlns' === $attribute->localName ? '' : $attribute->localName]
                            = $attribute->nodeValue;
                    }
                }
            }
            $current = $current->parentNode;
        }

        return $namespaces;
    }

    /**
     * @param DOMNode[] $selected
     */
    private function hasSelectedAncestor(DOMNode $node, array $selected): bool
    {
        $parent = $node->parentNode;
        while ($parent instanceof DOMNode) {
            foreach ($selected as $candidate) {
                if ($candidate->isSameNode($parent)) {
                    return true;
                }
            }
            $parent = $parent->parentNode;
        }

        return false;
    }
}
