<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Value;

/**
 * Immutable value object carrying parsed CSP violation report fields.
 *
 * Constructed from W3C CSP Level 2 (application/csp-report) or
 * Reporting API Level 1 (application/reports+json) payloads.
 */
final readonly class CspViolationReport {

  /**
   * Constructs a CspViolationReport.
   *
   * @param string $documentUri
   *   The URI of the document in which the violation occurred.
   * @param string $violatedDirective
   *   The directive whose enforcement caused the violation.
   * @param string $blockedUri
   *   The URI of the resource that was blocked.
   * @param string $sourceFile
   *   The URI of the document or script in which the violation occurred.
   * @param int $lineNumber
   *   The line number at which the violation occurred.
   * @param int $columnNumber
   *   The column number at which the violation occurred.
   * @param string $scriptSample
   *   The first 40 characters of the inline script, event handler, or style
   *   that caused the violation.
   * @param int $statusCode
   *   The HTTP status code of the resource on which the global object was
   *   instantiated.
   * @param string $disposition
   *   Either "enforce" or "report" depending on the header used.
   */
  public function __construct(
    public readonly string $documentUri,
    public readonly string $violatedDirective,
    public readonly string $blockedUri,
    public readonly string $sourceFile = '',
    public readonly int $lineNumber = 0,
    public readonly int $columnNumber = 0,
    public readonly string $scriptSample = '',
    public readonly int $statusCode = 0,
    public readonly string $disposition = 'enforce',
  ) {}

  /**
   * Creates a CspViolationReport from a CSP Level 2 csp-report array.
   *
   * @param array<string, mixed> $report
   *   The decoded JSON csp-report object.
   *
   * @return self
   *   A new CspViolationReport instance.
   */
  public static function fromCspReport(array $report): self {
    return new self(
      documentUri: (string) ($report['document-uri'] ?? ''),
      violatedDirective: (string) ($report['violated-directive'] ?? ''),
      blockedUri: (string) ($report['blocked-uri'] ?? ''),
      sourceFile: (string) ($report['source-file'] ?? ''),
      lineNumber: (int) ($report['line-number'] ?? 0),
      columnNumber: (int) ($report['column-number'] ?? 0),
      scriptSample: (string) ($report['script-sample'] ?? ''),
      statusCode: (int) ($report['status-code'] ?? 0),
      disposition: (string) ($report['disposition'] ?? 'enforce'),
    );
  }

  /**
   * Creates a CspViolationReport from a Reporting API Level 1 report body.
   *
   * @param array<string, mixed> $report
   *   A single decoded report object from the reports+json array.
   *
   * @return self
   *   A new CspViolationReport instance.
   */
  public static function fromReportingApi(array $report): self {
    $body = $report['body'] ?? [];
    return new self(
      documentUri: (string) ($report['url'] ?? ''),
      violatedDirective: (string) ($body['effectiveDirective'] ?? $body['violated-directive'] ?? ''),
      blockedUri: (string) ($body['blockedURL'] ?? $body['blocked-uri'] ?? ''),
      sourceFile: (string) ($body['sourceFile'] ?? ''),
      lineNumber: (int) ($body['lineNumber'] ?? 0),
      columnNumber: (int) ($body['columnNumber'] ?? 0),
      scriptSample: (string) ($body['sample'] ?? ''),
      statusCode: (int) ($body['statusCode'] ?? 0),
      disposition: (string) ($body['disposition'] ?? $report['type'] ?? 'enforce'),
    );
  }

}
