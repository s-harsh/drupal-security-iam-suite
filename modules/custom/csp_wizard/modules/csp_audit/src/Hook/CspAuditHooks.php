<?php

declare(strict_types=1);

namespace Drupal\csp_audit\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\csp_audit\Scanner\ModuleScanner;

/**
 * OOP hook implementations for the csp_audit sub-module.
 *
 * Implements hook_requirements() to surface audit finding counts in the
 * Drupal status report.
 */
final class CspAuditHooks {

  use StringTranslationTrait;

  /**
   * Constructs CspAuditHooks.
   *
   * @param \Drupal\csp_audit\Scanner\ModuleScanner $moduleScanner
   *   The module scanner service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   */
  public function __construct(
    private readonly ModuleScanner $moduleScanner,
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * Implements hook_requirements().
   *
   * Adds a CSP Audit row to the Drupal status report.
   */
  #[Hook('requirements')]
  public function requirements(string $phase): array {
    if ($phase !== 'runtime') {
      return [];
    }

    $allowlist = $this->configFactory->get('csp_audit.settings')->get('allowlist') ?? [];
    $allFindings = $this->moduleScanner->getFindings();

    // Filter out allowlisted modules.
    $findings = array_filter(
      $allFindings,
      static fn($f) => !in_array($f->moduleName, $allowlist, TRUE)
    );

    $count = count($findings);
    $errorCount = count(array_filter($findings, static fn($f) => $f->severity === 'error'));

    if ($count === 0) {
      $severity = REQUIREMENT_INFO;
      $value = $this->t('No findings — all enabled modules pass the CSP audit.');
    }
    elseif ($errorCount > 0) {
      $severity = REQUIREMENT_WARNING;
      $value = $this->t(
        '@count finding(s) detected (@errors error(s)). <a href=":url">View CSP Audit Report</a>.',
        [
          '@count'  => $count,
          '@errors' => $errorCount,
          ':url'    => Url::fromRoute('csp_audit.report')->toString(),
        ]
      );
    }
    else {
      $severity = REQUIREMENT_INFO;
      $value = $this->t(
        '@count warning(s) detected. <a href=":url">View CSP Audit Report</a>.',
        [
          '@count' => $count,
          ':url'   => Url::fromRoute('csp_audit.report')->toString(),
        ]
      );
    }

    return [
      'csp_audit_findings' => [
        'title'    => $this->t('CSP Audit'),
        'value'    => $value,
        'severity' => $severity,
      ],
    ];
  }

}
