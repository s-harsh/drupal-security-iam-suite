<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Mail\MailManagerInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\sbom_sentinel\Service\NisRiskScorer;
use Drupal\sbom_sentinel\Service\SbomGenerator;
use Psr\Log\LoggerInterface;

/**
 * OOP hook implementations for the SBOM Sentinel module.
 *
 * Implements hook_requirements (status report), hook_help, and hook_cron
 * via Drupal 11's #[Hook] attribute system. The cron handler triggers the
 * weekly OSV.dev scan and optionally dispatches an email report to the
 * configured site administrator address.
 */
final class SbomSentinelHooks {

  use StringTranslationTrait;

  /**
   * The module settings config object name.
   */
  private const CONFIG_NAME = 'sbom_sentinel.settings';

  /**
   * State key tracking the last cron run timestamp.
   */
  private const CRON_STATE_KEY = 'sbom_sentinel.last_cron_run';

  /**
   * Weekly cron interval in seconds (7 days).
   */
  private const CRON_INTERVAL = 604800;

  /**
   * Constructs an SbomSentinelHooks.
   *
   * @param \Drupal\sbom_sentinel\Service\SbomGenerator $sbomGenerator
   *   The SBOM generator service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The module logger channel.
   */
  public function __construct(
    private readonly SbomGenerator $sbomGenerator,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Implements hook_requirements().
   *
   * Reports the number of vulnerable components and the highest NIS2 risk
   * level found in the most recent cached scan on the Drupal Status Report.
   *
   * @param string $phase
   *   The phase: 'install', 'update', or 'runtime'.
   *
   * @return array<string, array<string, mixed>>
   *   Requirements array keyed by requirement name.
   */
  #[Hook('requirements')]
  public function requirements(string $phase): array {
    if ($phase !== 'runtime') {
      return [];
    }

    $config = $this->configFactory->get(self::CONFIG_NAME);
    if (!(bool) $config->get('enabled')) {
      return [
        'sbom_sentinel' => [
          'title' => $this->t('SBOM Sentinel'),
          'value' => $this->t('Disabled'),
          'description' => $this->t('SBOM Sentinel is disabled. Enable it in the module settings.'),
          'severity' => REQUIREMENT_INFO,
        ],
      ];
    }

    $cached = $this->sbomGenerator->getCachedResults();
    if ($cached === NULL) {
      return [
        'sbom_sentinel' => [
          'title' => $this->t('SBOM Sentinel'),
          'value' => $this->t('No scan results yet'),
          'description' => $this->t(
            'No SBOM scan has been run. Visit the <a href=":report_url">SBOM Sentinel report</a> or run <code>drush sbom:generate</code> to perform the first scan.',
            [':report_url' => Url::fromRoute('sbom_sentinel.report')->toString()],
          ),
          'severity' => REQUIREMENT_WARNING,
        ],
      ];
    }

    /** @var array<string, \Drupal\sbom_sentinel\Value\CveResult> $results */
    $results = $cached['results'] ?? [];
    $vulnerableCount = 0;
    $worstLevel = NisRiskScorer::LEVEL_NONE;
    $levelOrder = [
      NisRiskScorer::LEVEL_NONE => 0,
      NisRiskScorer::LEVEL_LOW => 1,
      NisRiskScorer::LEVEL_MEDIUM => 2,
      NisRiskScorer::LEVEL_HIGH => 3,
      NisRiskScorer::LEVEL_CRITICAL => 4,
    ];

    foreach ($results as $result) {
      if ($result->hasVulnerabilities()) {
        $vulnerableCount++;
        if (($levelOrder[$result->nisRiskLevel] ?? 0) > ($levelOrder[$worstLevel] ?? 0)) {
          $worstLevel = $result->nisRiskLevel;
        }
      }
    }

    $scannedAt = isset($cached['scanned_at'])
      ? date('Y-m-d H:i:s', (int) $cached['scanned_at'])
      : $this->t('unknown');

    $reportUrl = Url::fromRoute('sbom_sentinel.report')->toString();

    if ($vulnerableCount === 0) {
      return [
        'sbom_sentinel' => [
          'title' => $this->t('SBOM Sentinel — Supply Chain Security'),
          'value' => $this->t('No known vulnerabilities (@count components scanned)', [
            '@count' => count($results),
          ]),
          'description' => $this->t(
            'Last scan: @date. <a href=":url">View full report</a>.',
            [':url' => $reportUrl, '@date' => $scannedAt],
          ),
          'severity' => REQUIREMENT_OK,
        ],
      ];
    }

    $severity = match ($worstLevel) {
      NisRiskScorer::LEVEL_CRITICAL, NisRiskScorer::LEVEL_HIGH => REQUIREMENT_ERROR,
      NisRiskScorer::LEVEL_MEDIUM => REQUIREMENT_WARNING,
      default => REQUIREMENT_WARNING,
    };

    return [
      'sbom_sentinel' => [
        'title' => $this->t('SBOM Sentinel — Supply Chain Security'),
        'value' => $this->t('@count vulnerable component(s), highest NIS2 risk: @level', [
          '@count' => $vulnerableCount,
          '@level' => strtoupper($worstLevel),
        ]),
        'description' => $this->t(
          'Last scan: @date. <a href=":url">View full report</a> for CVE details and remediation guidance.',
          [':url' => $reportUrl, '@date' => $scannedAt],
        ),
        'severity' => $severity,
      ],
    ];
  }

  /**
   * Implements hook_help().
   *
   * Returns a render array with module description and relevant links when
   * the user visits the module help page.
   *
   * @param string $route_name
   *   The current route name.
   * @param \Drupal\Core\Routing\RouteMatchInterface $route_match
   *   The current route match.
   *
   * @return string|array<mixed>
   *   A render array or empty string.
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): string|array {
    if ($route_name !== 'help.page.sbom_sentinel') {
      return '';
    }

    $settingsUrl = Url::fromRoute('sbom_sentinel.settings')->toString();
    $reportUrl = Url::fromRoute('sbom_sentinel.report')->toString();

    $output = '<h2>' . $this->t('SBOM Sentinel') . '</h2>';
    $output .= '<p>' . $this->t(
      'SBOM Sentinel generates <a href=":cyclonedx_url">CycloneDX 1.6</a> Software Bill of Materials (SBOM) documents from your Drupal installation\'s <code>composer.lock</code>, checks each component against the <a href=":osv_url">OSV.dev</a> vulnerability database, and computes NIS2 Article 21 risk scores.',
      [
        ':cyclonedx_url' => 'https://cyclonedx.org/specification/overview/',
        ':osv_url' => 'https://osv.dev/',
      ],
    ) . '</p>';
    $output .= '<p>' . $this->t(
      'View the <a href=":report_url">Component Risk Report</a> for a sortable table of installed components with CVE counts, NIS2 severity badges (Critical / High / Medium / Low), and direct links to OSV vulnerability records.',
      [':report_url' => $reportUrl],
    ) . '</p>';
    $output .= '<p>' . $this->t(
      'Download the SBOM as CycloneDX JSON or XML from the report page for submission to regulators or integration with your supply chain security tooling.',
    ) . '</p>';
    $output .= '<p>' . $this->t(
      'Configure the module at <a href=":settings_url">SBOM Sentinel Settings</a>. Options include the path to <code>composer.lock</code>, OSV API timeout, weekly cron scanning, and email reporting.',
      [':settings_url' => $settingsUrl],
    ) . '</p>';

    return [
      '#markup' => $output,
      '#allowed_tags' => ['h2', 'p', 'em', 'a', 'code'],
    ];
  }

  /**
   * Implements hook_cron().
   *
   * Runs a fresh SBOM scan at most once per week when cron scanning is
   * enabled. Optionally sends an email report to the configured recipient.
   */
  #[Hook('cron')]
  public function cron(): void {
    $config = $this->configFactory->get(self::CONFIG_NAME);

    if (!(bool) $config->get('enabled') || !(bool) $config->get('cron_enabled')) {
      return;
    }

    $stateKey = self::CRON_STATE_KEY;
    $lastRun = \Drupal::state()->get($stateKey, 0);

    if ((time() - $lastRun) < self::CRON_INTERVAL) {
      return;
    }

    $this->logger->info('SBOM Sentinel: starting weekly cron scan.');

    try {
      $scanResult = $this->sbomGenerator->scan(bypassCache: TRUE);
      \Drupal::state()->set($stateKey, time());

      $componentCount = (int) ($scanResult['component_count'] ?? 0);
      /** @var array<string, \Drupal\sbom_sentinel\Value\CveResult> $results */
      $results = $scanResult['results'] ?? [];
      $vulnerableCount = count(array_filter(
        $results,
        fn($r) => $r->hasVulnerabilities(),
      ));

      $this->logger->info(
        'SBOM Sentinel cron scan complete: @total components, @vuln vulnerable.',
        ['@total' => $componentCount, '@vuln' => $vulnerableCount],
      );

      if ((bool) $config->get('email_report_enabled')) {
        $this->sendEmailReport($config, $scanResult);
      }
    }
    catch (\Throwable $e) {
      $this->logger->error(
        'SBOM Sentinel cron scan failed: @message',
        ['@message' => $e->getMessage()],
      );
    }
  }

  /**
   * Sends an email summary of the cron scan results.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The module configuration object.
   * @param array<string, mixed> $scanResult
   *   The scan result array returned by SbomGenerator::scan().
   */
  private function sendEmailReport(
    \Drupal\Core\Config\ImmutableConfig $config,
    array $scanResult,
  ): void {
    $recipient = trim((string) $config->get('email_recipient'));
    if ($recipient === '') {
      $siteConfig = $this->configFactory->get('system.site');
      $recipient = (string) $siteConfig->get('mail');
    }

    if ($recipient === '') {
      $this->logger->warning('SBOM Sentinel: no email recipient configured for cron report.');
      return;
    }

    /** @var array<string, \Drupal\sbom_sentinel\Value\CveResult> $results */
    $results = $scanResult['results'] ?? [];
    $vulnerableCount = count(array_filter($results, fn($r) => $r->hasVulnerabilities()));
    $componentCount = (int) ($scanResult['component_count'] ?? 0);

    $params = [
      'subject' => 'SBOM Sentinel Weekly Scan Report',
      'component_count' => $componentCount,
      'vulnerable_count' => $vulnerableCount,
      'results' => $results,
      'scanned_at' => $scanResult['scanned_at'] ?? time(),
      'report_url' => \Drupal::request()->getSchemeAndHttpHost()
        . Url::fromRoute('sbom_sentinel.report')->toString(),
    ];

    /** @var \Drupal\Core\Mail\MailManagerInterface $mailManager */
    $mailManager = \Drupal::service('plugin.manager.mail');
    $mailManager->mail(
      module: 'sbom_sentinel',
      key: 'cron_report',
      to: $recipient,
      langcode: \Drupal::currentUser()->getPreferredLangcode(),
      params: $params,
    );

    $this->logger->info(
      'SBOM Sentinel cron report sent to @recipient.',
      ['@recipient' => $recipient],
    );
  }

}
