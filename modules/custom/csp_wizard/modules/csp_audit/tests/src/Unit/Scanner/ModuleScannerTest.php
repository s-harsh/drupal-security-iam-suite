<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_audit\Unit\Scanner;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\Extension;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\csp_audit\Scanner\ModuleScanner;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for ModuleScanner.
 *
 * @coversDefaultClass \Drupal\csp_audit\Scanner\ModuleScanner
 * @group csp_audit
 */
final class ModuleScannerTest extends UnitTestCase {

  /**
   * A temporary directory for fixture files.
   */
  private string $tempDir;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->tempDir = sys_get_temp_dir() . '/csp_audit_test_' . uniqid();
    mkdir($this->tempDir . '/js', 0755, TRUE);
    mkdir($this->tempDir . '/src', 0755, TRUE);
  }

  /**
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    parent::tearDown();
    $this->removeDirectory($this->tempDir);
  }

  /**
   * Recursively removes a directory.
   */
  private function removeDirectory(string $dir): void {
    if (!is_dir($dir)) {
      return;
    }
    foreach (scandir($dir) as $item) {
      if ($item === '.' || $item === '..') {
        continue;
      }
      $path = $dir . '/' . $item;
      is_dir($path) ? $this->removeDirectory($path) : unlink($path);
    }
    rmdir($dir);
  }

  /**
   * Creates a ModuleScanner with the temp directory as the sole module.
   */
  private function createScanner(bool $cacheHit = FALSE): ModuleScanner {
    $extension = $this->createMock(Extension::class);
    $extension->method('getPath')->willReturn(
      str_replace(DRUPAL_ROOT . '/', '', $this->tempDir)
    );

    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $moduleHandler->method('getModuleList')->willReturn(['test_module' => $extension]);

    $auditConfig = $this->createMock(Config::class);
    $auditConfig->method('get')->willReturn(3600);

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($auditConfig);

    $cache = $this->createMock(CacheBackendInterface::class);
    $cacheData = $cacheHit
      ? (object) ['data' => []]
      : FALSE;
    $cache->method('get')->willReturn($cacheData);

    $logger = $this->createMock(LoggerInterface::class);

    return new ModuleScanner($moduleHandler, $configFactory, $cache, $logger);
  }

  /**
   * @covers ::getFindings
   */
  public function testJsFileWithUnsafeInlineProducesOneFinding(): void {
    file_put_contents(
      $this->tempDir . '/js/app.js',
      "// some code\nheader.set('Content-Security-Policy', \"default-src 'self'; style-src 'unsafe-inline'\");\n"
    );

    // Use a real DRUPAL_ROOT substitute via a subclass that patches getPath.
    // For this unit test, we call the protected scanJsFile via reflection.
    $scanner = $this->createScanner();

    $refMethod = new \ReflectionMethod($scanner, 'scanJsFile');
    $refMethod->setAccessible(TRUE);
    $findings = $refMethod->invoke($scanner, 'test_module', $this->tempDir . '/js/app.js');

    $this->assertCount(1, $findings, 'One finding expected for a JS file containing unsafe-inline.');
    $this->assertSame('error', $findings[0]->severity);
    $this->assertSame('test_module', $findings[0]->moduleName);
  }

  /**
   * @covers ::getFindings
   */
  public function testPhpFileWithInlineScriptAttachmentProducesOneFinding(): void {
    file_put_contents(
      $this->tempDir . '/src/InlineExample.php',
      "<?php\n\$attachments['#attached']['html_head'][] = [\n['#tag' => 'script', '#value' => 'var x=1;', '#attributes' => []],\n'my_script',\n];\n"
    );

    $scanner = $this->createScanner();

    $refMethod = new \ReflectionMethod($scanner, 'scanPhpFile');
    $refMethod->setAccessible(TRUE);
    $findings = $refMethod->invoke($scanner, 'test_module', $this->tempDir . '/src/InlineExample.php');

    $this->assertCount(1, $findings, 'One finding expected for a PHP file with inline script attachment.');
    $this->assertSame('warning', $findings[0]->severity);
  }

  /**
   * @covers ::getFindings
   */
  public function testPhpFileWithExternalScriptProducesNoFinding(): void {
    file_put_contents(
      $this->tempDir . '/src/ExternalExample.php',
      "<?php\n\$attachments['#attached']['html_head'][] = [\n['#tag' => 'script', '#attributes' => ['src' => 'https://cdn.example.com/app.js']],\n'my_script',\n];\n"
    );

    $scanner = $this->createScanner();

    $refMethod = new \ReflectionMethod($scanner, 'scanPhpFile');
    $refMethod->setAccessible(TRUE);
    $findings = $refMethod->invoke($scanner, 'test_module', $this->tempDir . '/src/ExternalExample.php');

    $this->assertEmpty($findings, 'No findings expected for a PHP file with only external script attachments.');
  }

  /**
   * @covers ::getFindings
   */
  public function testCacheIsUsedOnSecondCall(): void {
    $cachedFindings = [];
    $extension = $this->createMock(Extension::class);
    $extension->method('getPath')->willReturn('modules/test_module');

    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $moduleHandler->method('getModuleList')->willReturn(['test_module' => $extension]);

    $auditConfig = $this->createMock(Config::class);
    $auditConfig->method('get')->willReturn(3600);

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($auditConfig);

    $cache = $this->createMock(CacheBackendInterface::class);
    // Simulate a cache hit with empty findings.
    $cache->method('get')->willReturn((object) ['data' => $cachedFindings]);
    // set() should never be called when cache hits.
    $cache->expects($this->never())->method('set');

    $logger = $this->createMock(LoggerInterface::class);

    $scanner = new ModuleScanner($moduleHandler, $configFactory, $cache, $logger);
    $result = $scanner->getFindings();

    $this->assertSame([], $result, 'Cache hit should return cached (empty) findings without scanning.');
  }

  /**
   * @covers ::clearCache
   */
  public function testClearCacheDeletesCacheEntry(): void {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->expects($this->once())->method('delete')->with('csp_audit:scan_results');
    $cache->method('get')->willReturn(FALSE);

    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $moduleHandler->method('getModuleList')->willReturn([]);

    $auditConfig = $this->createMock(Config::class);
    $auditConfig->method('get')->willReturn(3600);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($auditConfig);

    $logger = $this->createMock(LoggerInterface::class);

    $scanner = new ModuleScanner($moduleHandler, $configFactory, $cache, $logger);
    $scanner->clearCache();
  }

}
