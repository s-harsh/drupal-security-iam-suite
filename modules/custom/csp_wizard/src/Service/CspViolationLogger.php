<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Service;

use Drupal\Component\Utility\Html;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\csp_wizard\Value\CspViolationReport;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Log\LoggerInterface;

/**
 * Sanitises and logs CSP violation reports to watchdog.
 *
 * Optionally forwards raw violation payloads to an external SIEM webhook.
 * All user-supplied string fields are passed through Html::escape() before
 * reaching the logger to prevent log-injection attacks.
 */
final class CspViolationLogger {

  /**
   * Constructs a CspViolationLogger.
   *
   * @param \Psr\Log\LoggerInterface $logger
   *   The csp_wizard logger channel.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   The HTTP client for SIEM webhook forwarding.
   */
  public function __construct(
    private readonly LoggerInterface $logger,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ClientInterface $httpClient,
  ) {}

  /**
   * Logs a violation report to watchdog and optionally forwards to SIEM.
   *
   * @param \Drupal\csp_wizard\Value\CspViolationReport $report
   *   The parsed violation report value object.
   * @param string $rawBody
   *   The raw request body, forwarded verbatim to the SIEM webhook.
   *
   * @return void
   */
  public function log(CspViolationReport $report, string $rawBody = ''): void {
    $this->logger->warning(
      'CSP violation: blocked-uri=@blocked_uri violated-directive=@violated_directive document-uri=@document_uri source-file=@source_file line=@line_number column=@column_number script-sample=@script_sample disposition=@disposition',
      [
        '@blocked_uri'        => Html::escape($report->blockedUri),
        '@violated_directive' => Html::escape($report->violatedDirective),
        '@document_uri'       => Html::escape($report->documentUri),
        '@source_file'        => Html::escape($report->sourceFile),
        '@line_number'        => $report->lineNumber,
        '@column_number'      => $report->columnNumber,
        '@script_sample'      => Html::escape($report->scriptSample),
        '@disposition'        => Html::escape($report->disposition),
      ]
    );

    $siemUrl = (string) $this->configFactory->get('csp_wizard.settings')->get('report_siem_url');
    if ($siemUrl !== '' && $rawBody !== '') {
      $this->forwardToSiem($siemUrl, $rawBody);
    }
  }

  /**
   * Forwards the raw violation body to an external SIEM webhook.
   *
   * Failures are swallowed silently (best-effort). A watchdog NOTICE is
   * written on failure so administrators can diagnose connectivity issues
   * without disrupting the 204 response to the browser.
   *
   * @param string $siemUrl
   *   The HTTPS webhook URL.
   * @param string $rawBody
   *   The raw JSON body to forward.
   *
   * @return void
   */
  private function forwardToSiem(string $siemUrl, string $rawBody): void {
    try {
      $this->httpClient->request('POST', $siemUrl, [
        'body'            => $rawBody,
        'headers'         => ['Content-Type' => 'application/json'],
        'connect_timeout' => 2,
        'timeout'         => 2,
        'verify'          => TRUE,
      ]);
    }
    catch (GuzzleException $e) {
      $this->logger->notice(
        'CSP Wizard: SIEM webhook forwarding failed for @url — @message',
        [
          '@url'     => Html::escape($siemUrl),
          '@message' => Html::escape($e->getMessage()),
        ]
      );
    }
  }

}
