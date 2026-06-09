<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;

/**
 * Assembles Content Security Policy directive arrays and serialises headers.
 *
 * Reads csp_wizard.settings and csp_wizard.service_profiles, merges enabled
 * service profiles, appends nonce values, detects unsafe-inline conflicts, and
 * returns a validated header string ready for output.
 */
final class CspPolicyBuilderService {

  use StringTranslationTrait;

  /**
   * Map of config directive keys to CSP directive names.
   *
   * @var array<string, string>
   */
  private const DIRECTIVE_MAP = [
    'default_src'    => 'default-src',
    'script_src'     => 'script-src',
    'style_src'      => 'style-src',
    'img_src'        => 'img-src',
    'connect_src'    => 'connect-src',
    'frame_src'      => 'frame-src',
    'font_src'       => 'font-src',
    'object_src'     => 'object-src',
    'base_uri'       => 'base-uri',
    'form_action'    => 'form-action',
    'frame_ancestors' => 'frame-ancestors',
  ];

  /**
   * Constructs a CspPolicyBuilderService.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\csp_wizard\Service\NonceGeneratorService $nonceGenerator
   *   The per-request nonce generator.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler, used to detect conflicting modules.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service for admin UI warnings.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly NonceGeneratorService $nonceGenerator,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly MessengerInterface $messenger,
  ) {}

  /**
   * Builds the site-wide CSP header string.
   *
   * @return string
   *   A serialised Content-Security-Policy value, safe for use as an HTTP
   *   header value (no CR or LF characters).
   */
  public function buildHeader(): string {
    $config = $this->configFactory->get('csp_wizard.settings');
    $profiles = $this->configFactory->get('csp_wizard.service_profiles');

    // Start with configured base directives.
    $directives = $this->buildBaseDirectives($config->get('directives') ?? []);

    // Merge enabled service profiles.
    $services = $config->get('services') ?? [];
    foreach (['ckeditor5', 'gtm', 'stripe', 'youtube', 'recaptcha_v2', 'recaptcha_v3'] as $serviceKey) {
      if (!empty($services[$serviceKey])) {
        $profile = $profiles->get($serviceKey) ?? [];
        $directives = $this->mergeProfileDirectives($directives, $profile);
      }
    }

    // Append custom domains to script-src.
    $customDomains = $services['custom_domains'] ?? [];
    foreach ($customDomains as $domain) {
      $domain = trim((string) $domain);
      if ($domain !== '') {
        $directives['script-src'][] = $domain;
      }
    }

    // Apply nonce and strict-dynamic when nonce injection is enabled.
    $nonceEnabled = (bool) $config->get('nonce_enabled');
    $gtmEnabled = !empty($services['gtm']);

    if ($nonceEnabled) {
      $nonce = $this->nonceGenerator->getNonce();
      $directives['script-src'][] = "'nonce-{$nonce}'";

      // strict-dynamic allows nonce-trusted scripts to load further scripts.
      if ($gtmEnabled) {
        $directives['script-src'][] = "'strict-dynamic'";
      }

      // Warn if unsafe-inline coexists with the nonce (negates nonce benefit).
      if ($this->containsUnsafeInline($directives['script-src'] ?? [])) {
        $this->messenger->addWarning(
          $this->t('CSP Wizard: <em>unsafe-inline</em> is present in script-src alongside a nonce. Browsers will ignore the nonce. Remove unsafe-inline to restore nonce-based protection.')
        );
      }
    }

    // upgrade-insecure-requests.
    $upgradeInsecure = (bool) ($config->get('directives')['upgrade_insecure'] ?? TRUE);
    if ($upgradeInsecure) {
      $directives['upgrade-insecure-requests'] = [];
    }

    return $this->serialiseDirectives($directives);
  }

  /**
   * Builds the stricter payment-page CSP header string for PCI DSS mode.
   *
   * @return string
   *   A serialised Content-Security-Policy value for payment page paths.
   */
  public function buildPaymentHeader(): string {
    $settings = $this->configFactory->get('csp_wizard.settings');
    $paymentPolicy = $this->configFactory->get('csp_wizard.payment_policy');
    $pciMode = $settings->get('pci_mode') ?? [];

    $directives = $this->buildBaseDirectives($paymentPolicy->get('directives') ?? []);

    // Apply nonce when enabled.
    $nonceEnabled = (bool) $settings->get('nonce_enabled');
    if ($nonceEnabled) {
      $nonce = $this->nonceGenerator->getNonce();
      $directives['script-src'][] = "'nonce-{$nonce}'";
    }

    // PCI DSS compliance: add require-trusted-types-for when configured.
    if (!empty($pciMode['trusted_types'])) {
      $directives['require-trusted-types-for'] = ["'script'"];
    }

    $policyNames = $paymentPolicy->get('directives')['trusted_types_policy_names'] ?? [];
    if (!empty($policyNames)) {
      $directives['trusted-types'] = array_map(
        static fn(string $n): string => $n,
        $policyNames
      );
    }

    return $this->serialiseDirectives($directives);
  }

  /**
   * Returns the list of script-src origins for PCI DSS inventory export.
   *
   * @return array<int, array{directive: string, origin: string, rationale: string}>
   *   An array of inventory rows suitable for CSV or JSON export.
   */
  public function buildScriptInventory(): array {
    $config = $this->configFactory->get('csp_wizard.settings');
    $profiles = $this->configFactory->get('csp_wizard.service_profiles');
    $services = $config->get('services') ?? [];

    $inventory = [];
    $baseScriptSrc = $config->get('directives')['script_src'] ?? [];
    foreach ($baseScriptSrc as $origin) {
      $inventory[] = [
        'directive' => 'script-src',
        'origin' => $origin,
        'rationale' => 'Base configuration',
      ];
    }

    foreach (['ckeditor5', 'gtm', 'stripe', 'youtube', 'recaptcha_v2', 'recaptcha_v3'] as $serviceKey) {
      if (!empty($services[$serviceKey])) {
        $profile = $profiles->get($serviceKey) ?? [];
        foreach ($profile['script_src'] ?? [] as $origin) {
          $inventory[] = [
            'directive' => 'script-src',
            'origin' => $origin,
            'rationale' => "Required by service: {$serviceKey}",
          ];
        }
      }
    }

    foreach ($services['custom_domains'] ?? [] as $domain) {
      $domain = trim((string) $domain);
      if ($domain !== '') {
        $inventory[] = [
          'directive' => 'script-src',
          'origin' => $domain,
          'rationale' => 'Custom domain (administrator-configured)',
        ];
      }
    }

    return $inventory;
  }

  /**
   * Builds a directive array from the base config directives mapping.
   *
   * @param array<string, mixed> $configDirectives
   *   The 'directives' sub-array from csp_wizard.settings.
   *
   * @return array<string, list<string>>
   *   Associative array keyed by CSP directive name.
   */
  private function buildBaseDirectives(array $configDirectives): array {
    $directives = [];
    foreach (self::DIRECTIVE_MAP as $configKey => $directiveName) {
      $values = $configDirectives[$configKey] ?? [];
      if (!empty($values)) {
        $directives[$directiveName] = array_values(array_filter(
          array_map('strval', $values)
        ));
      }
    }
    return $directives;
  }

  /**
   * Merges a service profile's directives into the existing directives array.
   *
   * @param array<string, list<string>> $directives
   *   Existing directives array.
   * @param array<string, list<string>> $profile
   *   Service profile directives keyed by config key (e.g. 'script_src').
   *
   * @return array<string, list<string>>
   *   Merged directives array.
   */
  private function mergeProfileDirectives(array $directives, array $profile): array {
    foreach (self::DIRECTIVE_MAP as $configKey => $directiveName) {
      if (!empty($profile[$configKey])) {
        $existing = $directives[$directiveName] ?? [];
        $directives[$directiveName] = array_values(array_unique(
          array_merge($existing, array_map('strval', $profile[$configKey]))
        ));
      }
    }
    return $directives;
  }

  /**
   * Checks whether the given source list contains 'unsafe-inline'.
   *
   * @param list<string> $sources
   *   List of CSP source expressions.
   *
   * @return bool
   *   TRUE if unsafe-inline is present.
   */
  private function containsUnsafeInline(array $sources): bool {
    foreach ($sources as $source) {
      if (str_contains(strtolower($source), 'unsafe-inline')) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Serialises a directive array into a CSP header string.
   *
   * @param array<string, list<string>> $directives
   *   Associative array keyed by CSP directive name, values are source lists.
   *   Directives with empty arrays (like upgrade-insecure-requests) are
   *   serialised as the directive name only.
   *
   * @return string
   *   The serialised CSP header value with directives separated by '; '.
   */
  private function serialiseDirectives(array $directives): string {
    $parts = [];
    foreach ($directives as $directive => $sources) {
      if (empty($sources)) {
        $parts[] = $directive;
      }
      else {
        $parts[] = $directive . ' ' . implode(' ', $sources);
      }
    }
    return implode('; ', $parts);
  }

}
