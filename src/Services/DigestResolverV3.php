<?php

namespace EbicsApi\Ebics\Services;

use EbicsApi\Ebics\Contracts\SignatureInterface;

/**
 * Digest resolver for EBICS protocol version 3.0.
 *
 * In EBICS 3.0, digest calculation normally uses X.509 certificate fingerprints
 * for both signing orders and generating the confirmation letter. However, some
 * banking gateways (e.g. TEN31 / MULTIVIA in Germany) ship plain RSA keys
 * without an X.509 wrapper even on H004 / EBICS 3.0 connections. When the
 * signature carries no certificate content, calculating a fingerprint over an
 * empty string produces a semantically meaningless digest. In that situation
 * this resolver falls back to the public-key digest, matching the behaviour of
 * {@see DigestResolverV2::confirmDigest()}.
 *
 * Key differences from EBICS 2.x:
 * - X.509 certificates are normally required for all signature operations
 * - With a certificate present, both signDigest and confirmDigest use
 *   certificate fingerprints
 * - With no certificate present, both methods fall back to the public-key
 *   digest (same as V2) instead of fingerprinting an empty string
 * - Confirmation digest returns hex-encoded string (bin2hex of raw bytes)
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class DigestResolverV3 extends DigestResolver
{
    public function signDigest(SignatureInterface $signature, string $algorithm = 'sha256'): string
    {
        if (($certificateContent = $signature->getCertificateContent())) {
            return $this->cryptService->calculateCertificateFingerprint($certificateContent, $algorithm);
        }

        return $this->cryptService->calculatePublicKeyDigest($signature, $algorithm);
    }

    public function confirmDigest(SignatureInterface $signature, string $algorithm = 'sha256'): string
    {
        if (($certificateContent = $signature->getCertificateContent())) {
            $digest = $this->cryptService->calculateCertificateFingerprint($certificateContent, $algorithm);
        } else {
            $digest = $this->cryptService->calculatePublicKeyDigest($signature, $algorithm);
        }

        return bin2hex($digest);
    }
}
