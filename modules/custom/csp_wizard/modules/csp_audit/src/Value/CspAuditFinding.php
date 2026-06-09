<?php

declare(strict_types=1);

namespace Drupal\csp_audit\Value;

/**
 * Immutable value object representing a single CSP audit finding.
 *
 * Produced by ModuleScanner when it detects an unsafe-inline pattern in a
 * module's JavaScript or PHP source files.
 */
final readonly class CspAuditFinding {

  /**
   * Constructs a CspAuditFinding.
   *
   * @param string $moduleName
   *   The machine name of the module containing the finding.
   * @param string $filePath
   *   The absolute file path where the pattern was found.
   * @param string $pattern
   *   A description of the matched pattern (e.g. 'unsafe-inline in JS').
   * @param string $severity
   *   Either 'error' (direct unsafe-inline) or 'warning' (potential inline
   *   script attachment).
   * @param int $lineNumber
   *   The line number at which the pattern was found (0 if not applicable).
   */
  public function __construct(
    public readonly string $moduleName,
    public readonly string $filePath,
    public readonly string $pattern,
    public readonly string $severity,
    public readonly int $lineNumber,
  ) {}

}
