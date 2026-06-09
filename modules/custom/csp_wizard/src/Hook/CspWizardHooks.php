<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\csp_wizard\Service\NonceGeneratorService;

/**
 * OOP hook implementations for the CSP Wizard module.
 *
 * This class is tagged as a drupal.hook service and implements hooks via the
 * #[Hook] attribute, following Drupal 11 coding standards.
 */
final class CspWizardHooks {

  use StringTranslationTrait;

  /**
   * Constructs a CspWizardHooks instance.
   *
   * @param \Drupal\csp_wizard\Service\NonceGeneratorService $nonceGenerator
   *   The per-request nonce generator.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler.
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   */
  public function __construct(
    private readonly NonceGeneratorService $nonceGenerator,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly Connection $database,
  ) {}

  /**
   * Implements hook_requirements().
   *
   * Surfaces CSP Wizard status in the Drupal status report.
   */
  #[Hook('requirements')]
  public function requirements(string $phase): array {
    if ($phase !== 'runtime') {
      return [];
    }

    $requirements = [];
    $config = $this->configFactory->get('csp_wizard.settings');
    $mode = (string) ($config->get('mode') ?? 'report_only');

    $modeLabel = $mode === 'enforce'
      ? $this->t('Enforcement mode active')
      : $this->t('Report-Only mode active — policy is not being enforced');

    $severity = REQUIREMENT_INFO;

    // Warn if enforce mode is on but nonce is disabled.
    if ($mode === 'enforce' && !(bool) $config->get('nonce_enabled')) {
      $severity = REQUIREMENT_WARNING;
      $modeLabel = $this->t('Enforcement mode active (nonce injection is disabled — inline scripts may be blocked)');
    }

    // Warn if the community csp module is also installed.
    if ($this->moduleHandler->moduleExists('csp')) {
      $severity = REQUIREMENT_WARNING;
      $modeLabel = $this->t('CSP Wizard is active but the community <em>csp</em> module is also enabled. Disable one to avoid conflicting Content-Security-Policy headers.');
    }

    $requirements['csp_wizard_mode'] = [
      'title'    => $this->t('CSP Wizard'),
      'value'    => $modeLabel,
      'severity' => $severity,
      'description' => $this->t(
        'Manage settings at <a href=":url">CSP Wizard Settings</a>.',
        [':url' => Url::fromRoute('csp_wizard.settings')->toString()]
      ),
    ];

    // Last violation timestamp from watchdog.
    try {
      $lastViolation = $this->database->select('watchdog', 'w')
        ->fields('w', ['timestamp'])
        ->condition('w.type', 'csp_wizard')
        ->orderBy('w.timestamp', 'DESC')
        ->range(0, 1)
        ->execute()
        ?->fetchField();

      $violationValue = $lastViolation
        ? $this->t('Last violation: @timestamp', [
            '@timestamp' => \Drupal::service('date.formatter')->format((int) $lastViolation, 'short'),
          ])
        : $this->t('No violations logged');
    }
    catch (\Exception) {
      $violationValue = $this->t('Unable to query violation log.');
    }

    $requirements['csp_wizard_violations'] = [
      'title'    => $this->t('CSP Violations'),
      'value'    => $violationValue,
      'severity' => REQUIREMENT_INFO,
    ];

    return $requirements;
  }

  /**
   * Implements hook_help().
   *
   * Provides contextual help for CSP Wizard admin routes.
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): string|array {
    if ($route_name !== 'help.page.csp_wizard') {
      return '';
    }

    return [
      '#type'   => 'markup',
      '#markup' => $this->t(
        '<p>CSP Wizard provides a guided, six-step wizard that generates a Content Security Policy tailored to your site\'s third-party services. '
        . 'It injects a cryptographic nonce on every inline script, logs violation reports to Drupal\'s watchdog, '
        . 'and includes a PCI DSS 6.4.3 compliance mode for payment pages.</p>'
        . '<ul>'
        . '<li><a href=":wizard_url">Launch the Policy Wizard</a></li>'
        . '<li><a href=":settings_url">Quick-edit Settings</a></li>'
        . '<li><a href=":owasp_url" target="_blank" rel="noreferrer noopener">OWASP CSP Cheat Sheet</a></li>'
        . '</ul>',
        [
          ':wizard_url'   => Url::fromRoute('csp_wizard.wizard')->toString(),
          ':settings_url' => Url::fromRoute('csp_wizard.settings')->toString(),
          ':owasp_url'    => 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
        ]
      ),
    ];
  }

  /**
   * Implements hook_page_attachments_alter().
   *
   * Injects the per-request nonce into drupalSettings and stamps it on all
   * inline html_head script elements.
   */
  #[Hook('page_attachments_alter')]
  public function pageAttachmentsAlter(array &$attachments): void {
    $config = $this->configFactory->get('csp_wizard.settings');

    if (!(bool) $config->get('nonce_enabled')) {
      return;
    }

    $nonce = $this->nonceGenerator->getNonce();

    // Expose nonce to JavaScript for dynamic script creation (e.g. GTM).
    $attachments['#attached']['drupalSettings']['cspWizard']['nonce'] = $nonce;

    // Stamp nonce on inline html_head script elements.
    if (!empty($attachments['#attached']['html_head'])) {
      foreach ($attachments['#attached']['html_head'] as &$element) {
        if (
          isset($element[0]['#tag']) &&
          $element[0]['#tag'] === 'script' &&
          empty($element[0]['#attributes']['src'])
        ) {
          $element[0]['#attributes']['nonce'] = $nonce;
        }
      }
      unset($element);
    }
  }

  /**
   * Implements hook_element_info_alter().
   *
   * Registers CspWizardInlineScript::preRenderAddNonce as a #pre_render
   * callback on the html_tag render element so all inline script tags on any
   * page receive a nonce attribute at render time (outside the cache boundary).
   *
   * Note: This hook is also implemented procedurally in csp_wizard.module for
   * Drupal 11 compatibility during the legacy hook transition period.
   */
  #[Hook('element_info_alter')]
  public function elementInfoAlter(array &$types): void {
    if (isset($types['html_tag'])) {
      $callback = [\Drupal\csp_wizard\Render\CspWizardInlineScript::class, 'preRenderAddNonce'];
      if (!in_array($callback, $types['html_tag']['#pre_render'] ?? [], TRUE)) {
        $types['html_tag']['#pre_render'][] = $callback;
      }
    }
  }

}
