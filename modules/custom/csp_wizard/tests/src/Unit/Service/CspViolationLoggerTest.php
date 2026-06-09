<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Unit\Service;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\csp_wizard\Service\CspViolationLogger;
use Drupal\csp_wizard\Value\CspViolationReport;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\RequestException;
use Psr\Http\Message\RequestInterface;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for CspViolationLogger.
 *
 * @coversDefaultClass \Drupal\csp_wizard\Service\CspViolationLogger
 * @group csp_wizard
 */
final class CspViolationLoggerTest extends UnitTestCase {

  /**
   * Creates a CspViolationLogger with mock dependencies.
   *
   * @param string $siemUrl
   *   The SIEM webhook URL to configure (empty = disabled).
   *
   * @return array{\Drupal\csp_wizard\Service\CspViolationLogger, \Psr\Log\LoggerInterface, \GuzzleHttp\ClientInterface}
   */
  private function createLogger(string $siemUrl = ''): array {
    $logger = $this->createMock(LoggerInterface::class);
    $httpClient = $this->createMock(ClientInterface::class);

    $config = $this->createMock(Config::class);
    $config->method('get')
      ->with('report_siem_url')
      ->willReturn($siemUrl);

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')
      ->with('csp_wizard.settings')
      ->willReturn($config);

    $service = new CspViolationLogger($logger, $configFactory, $httpClient);

    return [$service, $logger, $httpClient];
  }

  /**
   * @covers ::log
   */
  public function testLogCallsLoggerWarningOnce(): void {
    [$service, $logger] = $this->createLogger();

    $logger->expects($this->once())->method('warning');

    $report = new CspViolationReport(
      documentUri: 'https://example.com/page',
      violatedDirective: 'script-src',
      blockedUri: 'https://evil.com/script.js',
    );

    $service->log($report);
  }

  /**
   * @covers ::log
   */
  public function testXssInBlockedUriIsEscapedBeforeLogging(): void {
    [$service, $logger] = $this->createLogger();

    $logger->expects($this->once())
      ->method('warning')
      ->with(
        $this->anything(),
        $this->callback(function (array $context): bool {
          return $context['@blocked_uri'] === '&lt;script&gt;alert(1)&lt;/script&gt;';
        })
      );

    $report = new CspViolationReport(
      documentUri: 'https://example.com',
      violatedDirective: 'script-src',
      blockedUri: '<script>alert(1)</script>',
    );

    $service->log($report);
  }

  /**
   * @covers ::log
   */
  public function testScriptSampleWithScriptTagIsEscaped(): void {
    [$service, $logger] = $this->createLogger();

    $logger->expects($this->once())
      ->method('warning')
      ->with(
        $this->anything(),
        $this->callback(function (array $context): bool {
          return str_contains($context['@script_sample'], '&lt;script&gt;');
        })
      );

    $report = new CspViolationReport(
      documentUri: 'https://example.com',
      violatedDirective: 'script-src',
      blockedUri: 'inline',
      scriptSample: '<script>evil()</script>',
    );

    $service->log($report);
  }

  /**
   * @covers ::log
   */
  public function testSiemForwardingMakesOnePostWhenUrlConfigured(): void {
    [$service, $logger, $httpClient] = $this->createLogger('https://siem.example.com/webhook');

    $httpClient->expects($this->once())
      ->method('request')
      ->with('POST', 'https://siem.example.com/webhook', $this->anything());

    $report = new CspViolationReport(
      documentUri: 'https://example.com',
      violatedDirective: 'script-src',
      blockedUri: 'https://blocked.com',
    );

    $service->log($report, '{"csp-report":{}}');
  }

  /**
   * @covers ::log
   */
  public function testSiemForwardingNotCalledWhenUrlEmpty(): void {
    [$service, $logger, $httpClient] = $this->createLogger('');

    $httpClient->expects($this->never())->method('request');

    $report = new CspViolationReport(
      documentUri: 'https://example.com',
      violatedDirective: 'script-src',
      blockedUri: 'https://blocked.com',
    );

    $service->log($report, '{"csp-report":{}}');
  }

  /**
   * @covers ::log
   */
  public function testGuzzleExceptionFromSiemDoesNotPropagate(): void {
    [$service, $logger, $httpClient] = $this->createLogger('https://siem.example.com/webhook');

    $request = $this->createMock(RequestInterface::class);
    $httpClient->method('request')
      ->willThrowException(new RequestException('connection refused', $request));

    // Logger should receive warning (report) plus notice (SIEM failure).
    $logger->expects($this->atLeastOnce())->method('warning');

    $report = new CspViolationReport(
      documentUri: 'https://example.com',
      violatedDirective: 'script-src',
      blockedUri: 'https://blocked.com',
    );

    // Must not throw.
    $service->log($report, '{"csp-report":{}}');
  }

}
