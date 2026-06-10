<?php

declare(strict_types=1);

namespace Drupal\Tests\session_sentinel\Unit\Service;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\session_sentinel\Service\DeviceFingerprintService;
use Drupal\Tests\UnitTestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for DeviceFingerprintService.
 *
 * @group session_sentinel
 * @coversDefaultClass \Drupal\session_sentinel\Service\DeviceFingerprintService
 */
final class DeviceFingerprintServiceTest extends UnitTestCase {

  /**
   * Builds a DeviceFingerprintService with minimal mocked dependencies.
   *
   * @param array $configValues Config overrides for session_sentinel.settings.
   *
   * @return \Drupal\session_sentinel\Service\DeviceFingerprintService
   */
  private function buildService(array $configValues = []): DeviceFingerprintService {
    $defaults = [
      'enable_device_binding' => TRUE,
      'kill_on_device_change' => FALSE,
    ];
    $merged = array_merge($defaults, $configValues);

    $config = $this->createMock(Config::class);
    $config->method('get')
      ->willReturnCallback(static function (string $key) use ($merged) {
        return $merged[$key] ?? NULL;
      });

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);

    return new DeviceFingerprintService($factory, $logger);
  }

  // ---------------------------------------------------------------------------
  // generate()
  // ---------------------------------------------------------------------------

  /**
   * Tests that generate() returns a 64-character hex string (SHA-256).
   *
   * @covers ::generate
   */
  public function testGenerateReturnsSha256HexString(): void {
    $service = $this->buildService();
    $request = Request::create('/foo', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.1.100']);
    $request->headers->set('User-Agent', 'TestBrowser/1.0');

    $fp = $service->generate($request);

    $this->assertSame(64, strlen($fp));
    $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $fp);
  }

  /**
   * Tests that two requests with identical UA and IP produce the same fingerprint.
   *
   * @covers ::generate
   */
  public function testSameUaAndIpProduceSameFingerprint(): void {
    $service = $this->buildService();

    $r1 = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.1.50']);
    $r1->headers->set('User-Agent', 'MyBrowser/2.0');

    $r2 = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.1.99']);
    $r2->headers->set('User-Agent', 'MyBrowser/2.0');

    // Same /24 subnet (10.0.1.x), same UA → identical fingerprints.
    $this->assertSame($service->generate($r1), $service->generate($r2));
  }

  /**
   * Tests that different User-Agents produce different fingerprints.
   *
   * @covers ::generate
   */
  public function testDifferentUaProducesDifferentFingerprint(): void {
    $service = $this->buildService();

    $r1 = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.1.1']);
    $r1->headers->set('User-Agent', 'BrowserA/1.0');

    $r2 = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.1.1']);
    $r2->headers->set('User-Agent', 'BrowserB/2.0');

    $this->assertNotSame($service->generate($r1), $service->generate($r2));
  }

  /**
   * Tests that different /24 subnets produce different fingerprints.
   *
   * @covers ::generate
   */
  public function testDifferentSubnetProducesDifferentFingerprint(): void {
    $service = $this->buildService();

    $r1 = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.1.1']);
    $r1->headers->set('User-Agent', 'SameBrowser/1.0');

    $r2 = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.2.1']);
    $r2->headers->set('User-Agent', 'SameBrowser/1.0');

    $this->assertNotSame($service->generate($r1), $service->generate($r2));
  }

  // ---------------------------------------------------------------------------
  // generateFromStrings()
  // ---------------------------------------------------------------------------

  /**
   * Tests that generateFromStrings() is consistent with generate().
   *
   * @covers ::generateFromStrings
   */
  public function testGenerateFromStringsMatchesGenerate(): void {
    $service = $this->buildService();

    $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '192.168.5.77']);
    $request->headers->set('User-Agent', 'Consistent/1.0');

    $fromRequest = $service->generate($request);
    $fromStrings = $service->generateFromStrings('Consistent/1.0', '192.168.5.77');

    // Both should produce the same fingerprint (same UA, same /24).
    $this->assertSame($fromRequest, $fromStrings);
  }

  // ---------------------------------------------------------------------------
  // matches()
  // ---------------------------------------------------------------------------

  /**
   * Tests that matches() returns true for identical fingerprints.
   *
   * @covers ::matches
   */
  public function testMatchesReturnsTrueForIdenticalFingerprints(): void {
    $service = $this->buildService();
    $fp = hash('sha256', 'test');
    $this->assertTrue($service->matches($fp, $fp));
  }

  /**
   * Tests that matches() returns false for different fingerprints.
   *
   * @covers ::matches
   */
  public function testMatchesReturnsFalseForDifferentFingerprints(): void {
    $service = $this->buildService();
    $a = hash('sha256', 'deviceA');
    $b = hash('sha256', 'deviceB');
    $this->assertFalse($service->matches($a, $b));
  }

  // ---------------------------------------------------------------------------
  // isEnabled() / killOnChange()
  // ---------------------------------------------------------------------------

  /**
   * Tests isEnabled() returns true when configured as such.
   *
   * @covers ::isEnabled
   */
  public function testIsEnabledReturnsTrueWhenConfigured(): void {
    $service = $this->buildService(['enable_device_binding' => TRUE]);
    $this->assertTrue($service->isEnabled());
  }

  /**
   * Tests isEnabled() returns false when disabled in config.
   *
   * @covers ::isEnabled
   */
  public function testIsEnabledReturnsFalseWhenDisabled(): void {
    $service = $this->buildService(['enable_device_binding' => FALSE]);
    $this->assertFalse($service->isEnabled());
  }

  /**
   * Tests killOnChange() returns true when configured as such.
   *
   * @covers ::killOnChange
   */
  public function testKillOnChangeReturnsTrueWhenConfigured(): void {
    $service = $this->buildService(['kill_on_device_change' => TRUE]);
    $this->assertTrue($service->killOnChange());
  }

  /**
   * Tests killOnChange() returns false when disabled.
   *
   * @covers ::killOnChange
   */
  public function testKillOnChangeReturnsFalseByDefault(): void {
    $service = $this->buildService(['kill_on_device_change' => FALSE]);
    $this->assertFalse($service->killOnChange());
  }

  // ---------------------------------------------------------------------------
  // extractSubnet()
  // ---------------------------------------------------------------------------

  /**
   * Tests extractSubnet() returns /24 for a normal IPv4 address.
   *
   * @covers ::extractSubnet
   */
  public function testExtractSubnetReturnsSlash24ForIpv4(): void {
    $service = $this->buildService();
    $this->assertSame('10.0.1', $service->extractSubnet('10.0.1.55'));
    $this->assertSame('192.168.100', $service->extractSubnet('192.168.100.5'));
  }

  /**
   * Tests extractSubnet() returns /48 for a full IPv6 address.
   *
   * @covers ::extractSubnet
   */
  public function testExtractSubnetReturnsSlash48ForIpv6(): void {
    $service = $this->buildService();
    $subnet = $service->extractSubnet('2001:0db8:0001:0000:0000:0000:0000:0001');
    // First three groups of the expanded form.
    $this->assertStringStartsWith('2001:', $subnet);
    // Should contain exactly 2 colons (3 groups).
    $this->assertSame(2, substr_count($subnet, ':'));
  }

  /**
   * Tests that IPv4-mapped IPv6 (::ffff:x.x.x.x) extracts the IPv4 /24.
   *
   * @covers ::extractSubnet
   */
  public function testExtractSubnetHandlesIpv4MappedIpv6(): void {
    $service = $this->buildService();
    $subnet = $service->extractSubnet('::ffff:10.0.1.55');
    $this->assertSame('10.0.1', $subnet);
  }

  /**
   * Tests that an invalid IP returns an empty string.
   *
   * @covers ::extractSubnet
   */
  public function testExtractSubnetReturnsEmptyForInvalidIp(): void {
    $service = $this->buildService();
    $this->assertSame('', $service->extractSubnet('not-an-ip'));
    $this->assertSame('', $service->extractSubnet(''));
  }

  /**
   * Tests that IPv6 loopback ::1 extracts a valid /48 subnet.
   *
   * @covers ::extractSubnet
   */
  public function testExtractSubnetHandlesIpv6Loopback(): void {
    $service = $this->buildService();
    $subnet = $service->extractSubnet('::1');
    $this->assertNotSame('', $subnet);
  }

}
