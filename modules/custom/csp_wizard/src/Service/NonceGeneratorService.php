<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Service;

use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Generates a cryptographically secure, per-request nonce.
 *
 * The nonce is produced using random_bytes(32) (PHP CSPRNG, backed by
 * /dev/urandom on Linux and CryptGenRandom on Windows). It is Base64url-
 * encoded without padding, yielding 43 characters.
 *
 * The value is stored as a request attribute (_csp_wizard_nonce) so it is
 * generated exactly once per HTTP request and is never written to cache,
 * session, or any persistent storage.
 */
final class NonceGeneratorService {

  /**
   * The request attribute key used to store the per-request nonce.
   */
  private const ATTRIBUTE_KEY = '_csp_wizard_nonce';

  /**
   * Constructs a NonceGeneratorService.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The Symfony request stack.
   */
  public function __construct(
    private readonly RequestStack $requestStack,
  ) {}

  /**
   * Returns the per-request nonce, generating it on first call.
   *
   * Subsequent calls within the same request return the identical value so
   * that the nonce in the CSP header always matches the nonce stamped on
   * inline script elements.
   *
   * @return string
   *   A Base64url-encoded (no padding) random nonce of 32 bytes (43 chars).
   */
  public function getNonce(): string {
    $request = $this->requestStack->getCurrentRequest();
    if ($request === NULL) {
      // Fallback for CLI or test contexts where no current request exists.
      return $this->generateNonceValue();
    }

    if (!$request->attributes->has(self::ATTRIBUTE_KEY)) {
      $nonce = $this->generateNonceValue();
      $request->attributes->set(self::ATTRIBUTE_KEY, $nonce);
    }

    return (string) $request->attributes->get(self::ATTRIBUTE_KEY);
  }

  /**
   * Clears the stored nonce from the current request.
   *
   * Intended for use in test environments only. Calling this in production
   * will cause the nonce in the CSP header to differ from nonces already
   * stamped on page elements within the same request.
   *
   * @return void
   */
  public function resetNonce(): void {
    $request = $this->requestStack->getCurrentRequest();
    if ($request !== NULL) {
      $request->attributes->remove(self::ATTRIBUTE_KEY);
    }
  }

  /**
   * Generates a cryptographically secure Base64url-encoded nonce.
   *
   * @return string
   *   43-character Base64url string (no padding) derived from 32 random bytes.
   */
  private function generateNonceValue(): string {
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
  }

}
