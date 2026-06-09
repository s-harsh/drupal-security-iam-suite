<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Url;
use Drupal\csp_wizard\Service\CspViolationLogger;
use Drupal\csp_wizard\Value\CspViolationReport;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Handles CSP violation report submissions and the informational GET page.
 *
 * POST /csp-wizard/report — public, flood-controlled, accepts both
 * application/csp-report (CSP Level 2) and application/reports+json
 * (Reporting API Level 1) payloads.
 *
 * GET  /csp-wizard/report — requires 'view csp violations' permission; shows
 * status and links to the dblog filter.
 */
final class CspReportController implements ContainerInjectionInterface {

  /**
   * Maximum accepted request body size in bytes.
   */
  private const MAX_BODY_SIZE = 4096;

  /**
   * Flood event identifier.
   */
  private const FLOOD_EVENT = 'csp_wizard_report';

  /**
   * Constructs a CspReportController.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $loggerFactory
   *   The logger channel factory.
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood control service.
   * @param \Drupal\csp_wizard\Service\CspViolationLogger $violationLogger
   *   The violation logger service.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerChannelFactoryInterface $loggerFactory,
    private readonly FloodInterface $flood,
    private readonly CspViolationLogger $violationLogger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('logger.factory'),
      $container->get('flood'),
      $container->get('csp_wizard.violation_logger'),
    );
  }

  /**
   * Receives and processes a CSP violation report POST request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming HTTP request.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   204 No Content on success.
   *   429 Too Many Requests when flood limit exceeded.
   *   413 Content Too Large when body exceeds 4 KB.
   *   400 Bad Request on malformed or missing JSON.
   */
  public function receive(Request $request): Response {
    $config = $this->configFactory->get('csp_wizard.settings');
    $floodLimit = (int) ($config->get('flood_limit') ?? 60);
    $floodWindow = (int) ($config->get('flood_window') ?? 60);
    $clientIp = $request->getClientIp() ?? '0.0.0.0';

    // Flood control check.
    if (!$this->flood->isAllowed(self::FLOOD_EVENT, $floodLimit, $floodWindow, $clientIp)) {
      return new Response('', Response::HTTP_TOO_MANY_REQUESTS);
    }

    // Body size limit.
    $body = (string) $request->getContent();
    if (strlen($body) > self::MAX_BODY_SIZE) {
      return new Response('', Response::HTTP_REQUEST_ENTITY_TOO_LARGE);
    }

    if ($body === '') {
      return new Response('', Response::HTTP_BAD_REQUEST);
    }

    // Determine content type and parse accordingly.
    $contentType = $request->headers->get('Content-Type', '');

    try {
      $reports = $this->parseBody($body, $contentType);
    }
    catch (\JsonException) {
      return new Response('', Response::HTTP_BAD_REQUEST);
    }

    if (empty($reports)) {
      return new Response('', Response::HTTP_BAD_REQUEST);
    }

    // Register flood event after successful parse.
    $this->flood->register(self::FLOOD_EVENT, $floodWindow, $clientIp);

    // Log each report.
    foreach ($reports as $report) {
      $this->violationLogger->log($report, $body);
    }

    return new Response('', Response::HTTP_NO_CONTENT);
  }

  /**
   * Returns the informational GET page confirming the endpoint is active.
   *
   * @return array<string, mixed>
   *   A Drupal render array.
   */
  public function info(): array {
    return [
      '#type'  => 'markup',
      '#markup' => \Drupal\Core\Render\Markup::create(
        '<p>' . t('The CSP Wizard violation reporting endpoint is active. Browsers will POST violation reports to this URL automatically.') . '</p>'
        . '<p>' . t('<a href=":dblog_url">View violation log entries</a> in the database log (filter by channel: csp_wizard).', [
          ':dblog_url' => Url::fromRoute('dblog.overview')->toString(),
        ]) . '</p>'
      ),
    ];
  }

  /**
   * Parses the request body into an array of CspViolationReport objects.
   *
   * Supports both CSP Level 2 (application/csp-report) and Reporting API
   * Level 1 (application/reports+json) formats.
   *
   * @param string $body
   *   The raw request body.
   * @param string $contentType
   *   The Content-Type request header value.
   *
   * @return list<\Drupal\csp_wizard\Value\CspViolationReport>
   *   Parsed violation reports.
   *
   * @throws \JsonException
   *   If the JSON body is malformed.
   */
  private function parseBody(string $body, string $contentType): array {
    $decoded = json_decode($body, associative: TRUE, depth: 8, flags: JSON_THROW_ON_ERROR);

    if (!is_array($decoded)) {
      return [];
    }

    // Reporting API Level 1: array of report objects.
    if (str_contains($contentType, 'application/reports+json')) {
      if (!array_is_list($decoded)) {
        // Some browsers send a single object instead of an array.
        $decoded = [$decoded];
      }
      return array_map(
        static fn(array $item): CspViolationReport => CspViolationReport::fromReportingApi($item),
        $decoded
      );
    }

    // CSP Level 2: { "csp-report": { ... } } wrapper.
    if (isset($decoded['csp-report']) && is_array($decoded['csp-report'])) {
      return [CspViolationReport::fromCspReport($decoded['csp-report'])];
    }

    // Fallback: try to parse as a bare csp-report object.
    if (isset($decoded['document-uri'])) {
      return [CspViolationReport::fromCspReport($decoded)];
    }

    return [];
  }

}
