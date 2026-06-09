<?php

declare(strict_types=1);

namespace Drupal\csp_audit\Controller;

use Drupal\Component\Utility\Html;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Render\Markup;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\csp_audit\Scanner\ModuleScanner;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Controller for the CSP Audit report page.
 *
 * Renders a grouped findings table, provides a re-scan action, and streams a
 * CSV export of all findings.
 */
final class CspAuditReportController implements ContainerInjectionInterface {

  use StringTranslationTrait;

  /**
   * Constructs a CspAuditReportController.
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
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('csp_audit.module_scanner'),
      $container->get('config.factory'),
    );
  }

  /**
   * Renders the CSP Audit report page.
   *
   * @return array<string, mixed>
   *   A Drupal render array.
   */
  public function report(): array {
    $allowlist = $this->configFactory->get('csp_audit.settings')->get('allowlist') ?? [];
    $allFindings = $this->moduleScanner->getFindings();

    // Filter out allowlisted modules.
    $findings = array_values(array_filter(
      $allFindings,
      static fn($f) => !in_array($f->moduleName, $allowlist, TRUE)
    ));

    $rescanUrl = Url::fromRoute('csp_audit.rescan', [], [
      'query' => [\Drupal::service('csrf_token')->get('csp-audit/rescan') => '1'],
    ])->toString();

    $exportUrl = Url::fromRoute('csp_audit.export')->toString();

    $build = [];

    $build['actions'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<div class="csp-audit-actions">'
        . '<a href="' . Html::escape($rescanUrl) . '" class="button">' . $this->t('Re-scan') . '</a>'
        . ' <a href="' . Html::escape($exportUrl) . '" class="button">' . $this->t('Export CSV') . '</a>'
        . '</div>'
      ),
      '#weight' => -10,
    ];

    if (empty($findings)) {
      $build['empty'] = [
        '#type'   => 'markup',
        '#markup' => Markup::create(
          '<p class="messages messages--status">' . $this->t('No findings detected. All enabled modules pass the CSP audit.') . '</p>'
        ),
      ];
      return $build;
    }

    // Group findings by module.
    $grouped = [];
    foreach ($findings as $finding) {
      $grouped[$finding->moduleName][] = $finding;
    }
    ksort($grouped);

    $header = [
      $this->t('Module'),
      $this->t('File'),
      $this->t('Pattern'),
      $this->t('Severity'),
      $this->t('Line'),
    ];

    $rows = [];
    foreach ($grouped as $moduleName => $moduleFindings) {
      foreach ($moduleFindings as $finding) {
        $severityClass = $finding->severity === 'error' ? 'color-error' : 'color-warning';
        $rows[] = [
          Html::escape($moduleName),
          Html::escape(basename($finding->filePath)),
          Html::escape($finding->pattern),
          ['data' => Markup::create('<span class="' . $severityClass . '">' . Html::escape(ucfirst($finding->severity)) . '</span>')],
          $finding->lineNumber,
        ];
      }
    }

    $build['findings_table'] = [
      '#type'       => 'table',
      '#header'     => $header,
      '#rows'       => $rows,
      '#caption'    => $this->t('@count finding(s) in @modules module(s)', [
        '@count'   => count($findings),
        '@modules' => count($grouped),
      ]),
      '#empty'      => $this->t('No findings detected.'),
      '#attributes' => ['class' => ['csp-audit-findings']],
    ];

    $build['allowlist_link'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<p>' . $this->t('<a href=":url">Manage the known-safe allowlist</a> to exclude reviewed modules from this report.', [
          ':url' => Url::fromRoute('csp_wizard.audit_allowlist')->toString(),
        ]) . '</p>'
      ),
      '#weight' => 10,
    ];

    return $build;
  }

  /**
   * Clears the scan cache and redirects back to the report page.
   *
   * CSRF-protected via the route definition.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function rescan(): RedirectResponse {
    $this->moduleScanner->clearCache();
    \Drupal::messenger()->addStatus($this->t('CSP Audit cache cleared. The module scan will run on the next page load.'));
    return new RedirectResponse(Url::fromRoute('csp_audit.report')->toString());
  }

  /**
   * Streams all findings as a CSV download.
   *
   * @return \Symfony\Component\HttpFoundation\StreamedResponse
   */
  public function exportCsv(): StreamedResponse {
    $allFindings = $this->moduleScanner->getFindings();
    $allowlist = $this->configFactory->get('csp_audit.settings')->get('allowlist') ?? [];
    $findings = array_values(array_filter(
      $allFindings,
      static fn($f) => !in_array($f->moduleName, $allowlist, TRUE)
    ));

    $response = new StreamedResponse(function () use ($findings): void {
      $handle = fopen('php://output', 'w');
      if ($handle === FALSE) {
        return;
      }
      fputcsv($handle, ['Module', 'File', 'Pattern', 'Severity', 'Line Number', 'Export Date']);
      $date = date('Y-m-d');
      foreach ($findings as $finding) {
        fputcsv($handle, [
          $finding->moduleName,
          $finding->filePath,
          $finding->pattern,
          $finding->severity,
          $finding->lineNumber,
          $date,
        ]);
      }
      fclose($handle);
    });

    $response->headers->set('Content-Type', 'text/csv; charset=UTF-8');
    $response->headers->set(
      'Content-Disposition',
      'attachment; filename="csp-audit-findings-' . date('Y-m-d') . '.csv"'
    );

    return $response;
  }

}
