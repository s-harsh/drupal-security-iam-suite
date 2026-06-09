<?php

declare(strict_types=1);

namespace Drupal\csp_audit\Scanner;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\csp_audit\Value\CspAuditFinding;
use Psr\Log\LoggerInterface;

/**
 * Scans enabled module source files for unsafe-inline CSP patterns.
 *
 * Iterates .js files under each module's js/ directory for the literal string
 * 'unsafe-inline', and .php/.module files under src/ for inline script
 * attachment patterns. Results are cached in the csp_audit cache bin with a
 * configurable TTL (default 1 hour).
 */
final class ModuleScanner {

  /**
   * Cache key for scan results.
   */
  private const CACHE_KEY = 'csp_audit:scan_results';

  /**
   * Constructs a ModuleScanner.
   *
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   *   The csp_audit cache backend.
   * @param \Psr\Log\LoggerInterface $logger
   *   The csp_wizard logger channel.
   */
  public function __construct(
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly CacheBackendInterface $cache,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Returns all findings, using the cache when available.
   *
   * @return list<\Drupal\csp_audit\Value\CspAuditFinding>
   *   All detected findings.
   */
  public function getFindings(): array {
    $cached = $this->cache->get(self::CACHE_KEY);
    if ($cached !== FALSE) {
      return $cached->data;
    }

    $findings = $this->scan();
    $ttl = (int) ($this->configFactory->get('csp_audit.settings')->get('cache_ttl') ?? 3600);
    $this->cache->set(self::CACHE_KEY, $findings, time() + $ttl);

    return $findings;
  }

  /**
   * Clears the cached scan results.
   *
   * @return void
   */
  public function clearCache(): void {
    $this->cache->delete(self::CACHE_KEY);
  }

  /**
   * Runs a full scan of all enabled modules.
   *
   * @return list<\Drupal\csp_audit\Value\CspAuditFinding>
   *   All detected findings.
   */
  private function scan(): array {
    $findings = [];

    foreach ($this->moduleHandler->getModuleList() as $machineName => $extension) {
      $modulePath = $extension->getPath();

      // Scan js/ directory for unsafe-inline in JS files.
      $jsDir = DRUPAL_ROOT . '/' . $modulePath . '/js';
      if (is_dir($jsDir)) {
        $findings = array_merge($findings, $this->scanJsDirectory($machineName, $jsDir));
      }

      // Scan src/ directory for inline PHP script attachment patterns.
      $srcDir = DRUPAL_ROOT . '/' . $modulePath . '/src';
      if (is_dir($srcDir)) {
        $findings = array_merge($findings, $this->scanPhpDirectory($machineName, $srcDir));
      }

      // Also scan the module file itself.
      $moduleFile = DRUPAL_ROOT . '/' . $modulePath . '/' . $machineName . '.module';
      if (file_exists($moduleFile)) {
        $findings = array_merge($findings, $this->scanPhpFile($machineName, $moduleFile));
      }
    }

    return $findings;
  }

  /**
   * Scans all .js files in a directory for 'unsafe-inline'.
   *
   * @param string $moduleName
   *   The module machine name.
   * @param string $dir
   *   Absolute path to the js/ directory.
   *
   * @return list<\Drupal\csp_audit\Value\CspAuditFinding>
   */
  private function scanJsDirectory(string $moduleName, string $dir): array {
    $findings = [];
    try {
      $iterator = new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
      );
      foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === 'js') {
          $findings = array_merge($findings, $this->scanJsFile($moduleName, $file->getPathname()));
        }
      }
    }
    catch (\Exception $e) {
      $this->logger->notice('CSP Audit: could not scan js/ directory for @module: @msg', [
        '@module' => $moduleName,
        '@msg'    => $e->getMessage(),
      ]);
    }
    return $findings;
  }

  /**
   * Scans a single JS file for the literal string 'unsafe-inline'.
   *
   * @param string $moduleName
   *   The module machine name.
   * @param string $filePath
   *   Absolute path to the JS file.
   *
   * @return list<\Drupal\csp_audit\Value\CspAuditFinding>
   */
  private function scanJsFile(string $moduleName, string $filePath): array {
    $findings = [];
    try {
      $lines = file($filePath, FILE_IGNORE_NEW_LINES);
      if ($lines === FALSE) {
        return [];
      }
      foreach ($lines as $lineIndex => $line) {
        if (str_contains($line, 'unsafe-inline')) {
          $findings[] = new CspAuditFinding(
            moduleName: $moduleName,
            filePath: $filePath,
            pattern: "String 'unsafe-inline' found in JS file",
            severity: 'error',
            lineNumber: $lineIndex + 1,
          );
        }
      }
    }
    catch (\Exception $e) {
      $this->logger->notice('CSP Audit: could not read file @file: @msg', [
        '@file' => $filePath,
        '@msg'  => $e->getMessage(),
      ]);
    }
    return $findings;
  }

  /**
   * Scans all .php and .module files in a directory.
   *
   * @param string $moduleName
   *   The module machine name.
   * @param string $dir
   *   Absolute path to the src/ directory.
   *
   * @return list<\Drupal\csp_audit\Value\CspAuditFinding>
   */
  private function scanPhpDirectory(string $moduleName, string $dir): array {
    $findings = [];
    try {
      $iterator = new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
      );
      foreach ($iterator as $file) {
        if ($file->isFile() && in_array($file->getExtension(), ['php', 'module'], TRUE)) {
          $findings = array_merge($findings, $this->scanPhpFile($moduleName, $file->getPathname()));
        }
      }
    }
    catch (\Exception $e) {
      $this->logger->notice('CSP Audit: could not scan src/ directory for @module: @msg', [
        '@module' => $moduleName,
        '@msg'    => $e->getMessage(),
      ]);
    }
    return $findings;
  }

  /**
   * Scans a single PHP file for inline script attachment patterns.
   *
   * Looks for '#tag' => 'script' array patterns without an accompanying
   * 'src' attribute, which indicates an inline script is being attached to
   * the page via the render API.
   *
   * @param string $moduleName
   *   The module machine name.
   * @param string $filePath
   *   Absolute path to the PHP file.
   *
   * @return list<\Drupal\csp_audit\Value\CspAuditFinding>
   */
  private function scanPhpFile(string $moduleName, string $filePath): array {
    $findings = [];
    try {
      $lines = file($filePath, FILE_IGNORE_NEW_LINES);
      if ($lines === FALSE) {
        return [];
      }

      $content = implode("\n", $lines);

      // Look for '#tag' => 'script' without 'src' nearby (within 10 lines).
      foreach ($lines as $lineIndex => $line) {
        if (preg_match("/'#tag'\s*=>\s*'script'/", $line)) {
          // Check a window of +/- 5 lines for 'src' attribute.
          $start = max(0, $lineIndex - 5);
          $end = min(count($lines) - 1, $lineIndex + 5);
          $window = implode("\n", array_slice($lines, $start, $end - $start + 1));

          if (!preg_match("/'src'\s*=>|\"src\"\s*=>/", $window)) {
            $findings[] = new CspAuditFinding(
              moduleName: $moduleName,
              filePath: $filePath,
              pattern: "Potential inline script attachment via '#tag' => 'script' without 'src'",
              severity: 'warning',
              lineNumber: $lineIndex + 1,
            );
          }
        }

        // Also catch direct unsafe-inline strings in PHP.
        if (str_contains($line, 'unsafe-inline') && !str_contains($filePath, 'csp_wizard')) {
          $findings[] = new CspAuditFinding(
            moduleName: $moduleName,
            filePath: $filePath,
            pattern: "String 'unsafe-inline' found in PHP file",
            severity: 'error',
            lineNumber: $lineIndex + 1,
          );
        }
      }
    }
    catch (\Exception $e) {
      $this->logger->notice('CSP Audit: could not read PHP file @file: @msg', [
        '@file' => $filePath,
        '@msg'  => $e->getMessage(),
      ]);
    }
    return $findings;
  }

}
