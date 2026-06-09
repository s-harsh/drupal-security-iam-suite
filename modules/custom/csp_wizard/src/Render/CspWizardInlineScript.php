<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Render;

/**
 * Pre-render callback that stamps a CSP nonce attribute on inline script tags.
 *
 * Registered on Drupal core's html_tag render element via
 * hook_element_info_alter(). Runs at render time — after the Dynamic Page
 * Cache boundary — so nonce values are never persisted inside a cache entry.
 */
final class CspWizardInlineScript {

  /**
   * Adds a nonce attribute to inline script render elements.
   *
   * Skips elements that are not <script> tags, have a src attribute (external
   * scripts do not need a nonce in CSP Level 2+), or when nonce injection is
   * disabled in the module configuration.
   *
   * @param array<string, mixed> $element
   *   The render element array for an html_tag element.
   *
   * @return array<string, mixed>
   *   The element array, possibly with a nonce attribute added.
   */
  public static function preRenderAddNonce(array $element): array {
    // Only act on <script> tags.
    if (($element['#tag'] ?? '') !== 'script') {
      return $element;
    }

    // External scripts (those with a src attribute) do not need a nonce.
    if (!empty($element['#attributes']['src'])) {
      return $element;
    }

    // Check that nonce injection is enabled.
    $config = \Drupal::config('csp_wizard.settings');
    if (!(bool) $config->get('nonce_enabled')) {
      return $element;
    }

    // Obtain (or generate) the per-request nonce.
    $nonce = \Drupal::service('csp_wizard.nonce_generator')->getNonce();
    $element['#attributes']['nonce'] = $nonce;

    return $element;
  }

}
