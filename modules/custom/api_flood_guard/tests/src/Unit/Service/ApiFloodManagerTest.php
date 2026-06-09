<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Unit\Service;

use Drupal\api_flood_guard\Contract\IpReputationProviderInterface;
use Drupal\api_flood_guard\Plugin\Manager\IpReputationManager;
use Drupal\api_flood_guard\Service\ApiFloodManager;
use Drupal\api_flood_guard\Value\IpReputationResult;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Unit tests for ApiFloodManager.
 *
 * @group api_flood_guard
 * @coversDefaultClass \Drupal\api_flood_guard\Service\ApiFloodManager
 */
final class ApiFloodManagerTest extends UnitTestCase {

  /**
   * Builds a mock ConfigFactoryInterface with the given settings array.
   */
  private function buildConfigFactory(array $settings = []): ConfigFactoryInterface {
    $defaults = [
      'ip_threshold'                          => 100,
      'ip_window'                             => 3600,
      'user_threshold'                        => 20,
      'user_window'                           => 900,
      'allowlist'                             => [],
      'debug_logging'                         => FALSE,
      'reputation_providers.enabled_provider' => '',
    ];
    $merged = array_merge($defaults, $settings);

    $config = $this->createMock(Config::class);
    $config->method('get')
      ->willReturnCallback(static function (string $key) use ($merged) {
        return $merged[$key] ?? NULL;
      });

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturn($config);

    return $factory;
  }

  /**
   * Builds a fully wired ApiFloodManager with mocked collaborators.
   */
  private function buildManager(
    FloodInterface $flood,
    ConfigFactoryInterface $configFactory,
    ?LoggerInterface $logger = NULL,
    ?IpReputationManager $reputationManager = NULL,
  ): ApiFloodManager {
    $logger ??= $this->createMock(LoggerInterface::class);
    $reputationManager ??= $this->createMock(IpReputationManager::class);
    $requestStack = $this->createMock(RequestStack::class);

    return new ApiFloodManager($flood, $configFactory, $logger, $reputationManager, $requestStack);
  }

  // -------------------------------------------------------------------------
  // Allowlist (Stage 1)
  // -------------------------------------------------------------------------

  /**
   * Tests that an allowlisted IP bypasses flood and reputation checks entirely.
   *
   * @covers ::evaluate
   */
  public function testAllowlistedIpBypassesAllChecks(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->expects($this->never())->method('isAllowed');
    $flood->expects($this->never())->method('register');

    $reputationManager = $this->createMock(IpReputationManager::class);
    $reputationManager->expects($this->never())->method('createInstance');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['allowlist' => ['10.0.0.0/8']]),
      reputationManager: $reputationManager,
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '10.1.2.3', '');

    $this->assertTrue($decision->allowed);
    $this->assertSame('allowlist', $decision->reason);
    $this->assertSame('10.1.2.3', $decision->identifier);
  }

  /**
   * Tests that an allowlisted IPv6 loopback (::1) bypasses checks.
   *
   * @covers ::evaluate
   */
  public function testAllowlistedIpv6LoopbackBypasses(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->expects($this->never())->method('isAllowed');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['allowlist' => ['::1']]),
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '::1', '');
    $this->assertTrue($decision->allowed);
    $this->assertSame('allowlist', $decision->reason);
  }

  /**
   * Tests CIDR allowlist matching for /16 range.
   *
   * @covers ::evaluate
   */
  public function testCidrAllowlistMatchesIpWithinRange(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->expects($this->never())->method('isAllowed');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['allowlist' => ['192.168.0.0/16']]),
    );

    $decision = $manager->evaluate(Request::create('/oauth/token'), '192.168.100.5', '');
    $this->assertTrue($decision->allowed);
    $this->assertSame('allowlist', $decision->reason);
  }

  /**
   * Tests that an IP outside a CIDR range is NOT allowlisted.
   *
   * @covers ::evaluate
   */
  public function testCidrAllowlistDoesNotMatchIpOutsideRange(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);
    $flood->expects($this->atLeastOnce())->method('register');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['allowlist' => ['192.168.0.0/16']]),
    );

    // 10.0.0.1 is NOT within 192.168.0.0/16.
    $decision = $manager->evaluate(Request::create('/oauth/token'), '10.0.0.1', '');
    $this->assertTrue($decision->allowed);
    $this->assertSame('passed', $decision->reason);
  }

  /**
   * Tests that a malformed IP address is not allowlisted (fail-open).
   *
   * @covers ::evaluate
   */
  public function testMalformedIpIsNotAllowlisted(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['allowlist' => ['10.0.0.0/8']]),
    );

    // 'not-an-ip' cannot be parsed by inet_pton(), so it should not match.
    $decision = $manager->evaluate(Request::create('/user/login'), 'not-an-ip', '');
    // Should not be allowlisted; proceeds to flood checks.
    $this->assertNotSame('allowlist', $decision->reason);
  }

  /**
   * Tests that an exact-IP allowlist entry (no CIDR) matches correctly.
   *
   * @covers ::evaluate
   */
  public function testExactIpAllowlistMatch(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->expects($this->never())->method('isAllowed');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['allowlist' => ['127.0.0.1']]),
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '127.0.0.1', '');
    $this->assertTrue($decision->allowed);
    $this->assertSame('allowlist', $decision->reason);
  }

  /**
   * Tests debug logging fires when an allowlisted IP passes with debug_logging on.
   *
   * @covers ::evaluate
   */
  public function testDebugLoggingFiresForAllowlistedIp(): void {
    $flood = $this->createMock(FloodInterface::class);
    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('debug');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory([
        'allowlist' => ['127.0.0.1'],
        'debug_logging' => TRUE,
      ]),
      logger: $logger,
    );

    $manager->evaluate(Request::create('/user/login'), '127.0.0.1', '');
  }

  // -------------------------------------------------------------------------
  // Reputation check (Stage 2)
  // -------------------------------------------------------------------------

  /**
   * Tests that a blocked reputation result blocks the request immediately.
   *
   * @covers ::evaluate
   */
  public function testReputationBlockedImmediatelyBlocks(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->expects($this->never())->method('isAllowed');
    $flood->expects($this->never())->method('register');

    $provider = $this->createMock(IpReputationProviderInterface::class);
    $provider->method('isConfigured')->willReturn(TRUE);
    $provider->method('checkIp')
      ->willReturn(IpReputationResult::blocked(score: 95, providerName: 'abuseipdb'));

    $reputationManager = $this->createMock(IpReputationManager::class);
    $reputationManager->method('createInstance')->willReturn($provider);

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['reputation_providers.enabled_provider' => 'abuseipdb']),
      reputationManager: $reputationManager,
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '1.2.3.4', '');

    $this->assertFalse($decision->allowed);
    $this->assertSame('reputation', $decision->reason);
    $this->assertSame('1.2.3.4', $decision->identifier);
    $this->assertGreaterThan(0, $decision->retryAfter);
  }

  /**
   * Tests that a reputation provider error results in fail-open (proceed to flood checks).
   *
   * @covers ::evaluate
   */
  public function testReputationProviderErrorIsFailOpen(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);
    $flood->expects($this->atLeastOnce())->method('register');

    $provider = $this->createMock(IpReputationProviderInterface::class);
    $provider->method('isConfigured')->willReturn(TRUE);
    $provider->method('checkIp')
      ->willReturn(IpReputationResult::failOpen('abuseipdb'));

    $reputationManager = $this->createMock(IpReputationManager::class);
    $reputationManager->method('createInstance')->willReturn($provider);

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['reputation_providers.enabled_provider' => 'abuseipdb']),
      reputationManager: $reputationManager,
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '1.2.3.4', '');

    $this->assertTrue($decision->allowed);
    $this->assertSame('passed', $decision->reason);
  }

  /**
   * Tests that an unconfigured reputation plugin is skipped gracefully.
   *
   * @covers ::evaluate
   */
  public function testUnconfiguredReputationProviderIsSkipped(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);

    $provider = $this->createMock(IpReputationProviderInterface::class);
    $provider->method('isConfigured')->willReturn(FALSE);
    $provider->expects($this->never())->method('checkIp');

    $reputationManager = $this->createMock(IpReputationManager::class);
    $reputationManager->method('createInstance')->willReturn($provider);

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['reputation_providers.enabled_provider' => 'abuseipdb']),
      reputationManager: $reputationManager,
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '1.2.3.4', '');
    $this->assertTrue($decision->allowed);
  }

  /**
   * Tests that a reputation provider that throws an exception results in fail-open.
   *
   * @covers ::evaluate
   */
  public function testReputationProviderExceptionIsFailOpen(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);

    $provider = $this->createMock(IpReputationProviderInterface::class);
    $provider->method('isConfigured')->willReturn(TRUE);
    $provider->method('checkIp')->willThrowException(new \RuntimeException('Network error'));

    $reputationManager = $this->createMock(IpReputationManager::class);
    $reputationManager->method('createInstance')->willReturn($provider);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('warning');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['reputation_providers.enabled_provider' => 'abuseipdb']),
      logger: $logger,
      reputationManager: $reputationManager,
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '1.2.3.4', '');
    $this->assertTrue($decision->allowed);
    $this->assertSame('passed', $decision->reason);
  }

  /**
   * Tests that no reputation check runs when enabled_provider is empty.
   *
   * @covers ::evaluate
   */
  public function testNoReputationCheckWhenProviderIsEmpty(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);

    $reputationManager = $this->createMock(IpReputationManager::class);
    $reputationManager->expects($this->never())->method('createInstance');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['reputation_providers.enabled_provider' => '']),
      reputationManager: $reputationManager,
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '1.2.3.4', '');
    $this->assertTrue($decision->allowed);
  }

  /**
   * Tests that null_provider string skips reputation check.
   *
   * @covers ::evaluate
   */
  public function testNullProviderStringSkipsReputationCheck(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);

    $reputationManager = $this->createMock(IpReputationManager::class);
    $reputationManager->expects($this->never())->method('createInstance');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['reputation_providers.enabled_provider' => 'null_provider']),
      reputationManager: $reputationManager,
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '1.2.3.4', '');
    $this->assertTrue($decision->allowed);
  }

  // -------------------------------------------------------------------------
  // IP flood check (Stage 3)
  // -------------------------------------------------------------------------

  /**
   * Tests that per-IP flood block is returned when threshold is exceeded.
   *
   * @covers ::evaluate
   */
  public function testPerIpFloodBlockWhenThresholdExceeded(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')
      ->with('api_flood_guard.ip', $this->anything(), $this->anything(), '5.5.5.5')
      ->willReturn(FALSE);
    $flood->expects($this->never())->method('register');

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('warning');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(),
      logger: $logger,
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '5.5.5.5', '');

    $this->assertFalse($decision->allowed);
    $this->assertSame('ip', $decision->reason);
    $this->assertSame('5.5.5.5', $decision->identifier);
    $this->assertSame(3600, $decision->retryAfter); // Default ip_window.
  }

  /**
   * Tests that per-IP block uses the configured ip_window as retryAfter.
   *
   * @covers ::evaluate
   */
  public function testPerIpBlockUsesConfiguredWindowAsRetryAfter(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(FALSE);

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['ip_window' => 1800]),
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '5.5.5.5', '');

    $this->assertSame(1800, $decision->retryAfter);
  }

  // -------------------------------------------------------------------------
  // Username flood check (Stage 4)
  // -------------------------------------------------------------------------

  /**
   * Tests that per-username flood block is returned when user threshold exceeded.
   *
   * @covers ::evaluate
   */
  public function testPerUsernameFloodBlockWhenThresholdExceeded(): void {
    $usernameHash = hash('sha256', 'admin');

    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')
      ->willReturnCallback(static function (string $event): bool {
        return $event === 'api_flood_guard.ip'; // IP passes, user blocked.
      });
    $flood->expects($this->never())->method('register');

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('warning');

    $manager = $this->buildManager($flood, $this->buildConfigFactory(), logger: $logger);

    $decision = $manager->evaluate(Request::create('/user/login'), '1.1.1.1', $usernameHash);

    $this->assertFalse($decision->allowed);
    $this->assertSame('user', $decision->reason);
    $this->assertSame($usernameHash, $decision->identifier);
    $this->assertSame(900, $decision->retryAfter); // Default user_window.
  }

  /**
   * Tests that per-user block uses the configured user_window as retryAfter.
   *
   * @covers ::evaluate
   */
  public function testPerUserBlockUsesConfiguredWindowAsRetryAfter(): void {
    $usernameHash = hash('sha256', 'admin');

    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')
      ->willReturnCallback(static function (string $event): bool {
        return $event === 'api_flood_guard.ip';
      });

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['user_window' => 600]),
    );

    $decision = $manager->evaluate(Request::create('/user/login'), '1.1.1.1', $usernameHash);
    $this->assertSame(600, $decision->retryAfter);
  }

  /**
   * Tests that with an empty usernameHash the user flood check is skipped.
   *
   * @covers ::evaluate
   */
  public function testEmptyUsernameHashSkipsUserFloodCheck(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')
      ->with('api_flood_guard.ip', $this->anything(), $this->anything(), $this->anything())
      ->willReturn(TRUE);

    // Only the IP register call should happen (not the user register).
    $flood->expects($this->once())
      ->method('register')
      ->with('api_flood_guard.ip', $this->anything(), $this->anything());

    $manager = $this->buildManager($flood, $this->buildConfigFactory());

    $decision = $manager->evaluate(Request::create('/user/login'), '1.1.1.1', '');
    $this->assertTrue($decision->allowed);
    $this->assertSame('passed', $decision->reason);
  }

  // -------------------------------------------------------------------------
  // Flood registration (Stage 5)
  // -------------------------------------------------------------------------

  /**
   * Tests that passing all checks registers flood counters for both namespaces.
   *
   * @covers ::evaluate
   */
  public function testPassingRegistersIpAndUserFloodCounters(): void {
    $usernameHash = hash('sha256', 'admin');

    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);

    $registeredEvents = [];
    $flood->method('register')
      ->willReturnCallback(static function (string $event) use (&$registeredEvents): void {
        $registeredEvents[] = $event;
      });

    $manager = $this->buildManager($flood, $this->buildConfigFactory());

    $decision = $manager->evaluate(Request::create('/user/login'), '1.1.1.1', $usernameHash);

    $this->assertTrue($decision->allowed);
    $this->assertContains('api_flood_guard.ip', $registeredEvents);
    $this->assertContains('api_flood_guard.user', $registeredEvents);
    $this->assertCount(2, $registeredEvents);
  }

  /**
   * Tests that passing with empty username only registers IP counter.
   *
   * @covers ::evaluate
   */
  public function testPassingWithNoUsernameOnlyRegistersIpCounter(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);

    $registeredEvents = [];
    $flood->method('register')
      ->willReturnCallback(static function (string $event) use (&$registeredEvents): void {
        $registeredEvents[] = $event;
      });

    $manager = $this->buildManager($flood, $this->buildConfigFactory());

    $manager->evaluate(Request::create('/user/login'), '1.1.1.1', '');

    $this->assertContains('api_flood_guard.ip', $registeredEvents);
    $this->assertNotContains('api_flood_guard.user', $registeredEvents);
  }

  /**
   * Tests that debug logging fires for passing requests when enabled.
   *
   * @covers ::evaluate
   */
  public function testDebugLoggingFiresForPassingRequest(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('debug');

    $manager = $this->buildManager(
      $flood,
      $this->buildConfigFactory(['debug_logging' => TRUE]),
      logger: $logger,
    );

    $manager->evaluate(Request::create('/user/login'), '1.1.1.1', '');
  }

  // -------------------------------------------------------------------------
  // clearUserFlood() and clearIpFlood()
  // -------------------------------------------------------------------------

  /**
   * Tests that clearUserFlood() calls flood->clear with the right arguments.
   *
   * @covers ::clearUserFlood
   */
  public function testClearUserFloodCallsFloodClear(): void {
    $usernameHash = hash('sha256', 'admin');

    $flood = $this->createMock(FloodInterface::class);
    $flood->expects($this->once())
      ->method('clear')
      ->with('api_flood_guard.user', $usernameHash);

    $manager = $this->buildManager($flood, $this->buildConfigFactory());
    $manager->clearUserFlood($usernameHash);
  }

  /**
   * Tests that clearUserFlood() with empty hash does NOT call flood->clear.
   *
   * @covers ::clearUserFlood
   */
  public function testClearUserFloodWithEmptyHashDoesNothing(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->expects($this->never())->method('clear');

    $manager = $this->buildManager($flood, $this->buildConfigFactory());
    $manager->clearUserFlood('');
  }

  /**
   * Tests that clearIpFlood() calls flood->clear for the IP namespace.
   *
   * @covers ::clearIpFlood
   */
  public function testClearIpFloodCallsFloodClear(): void {
    $flood = $this->createMock(FloodInterface::class);
    $flood->expects($this->once())
      ->method('clear')
      ->with('api_flood_guard.ip', '1.2.3.4');

    $manager = $this->buildManager($flood, $this->buildConfigFactory());
    $manager->clearIpFlood('1.2.3.4');
  }

  // -------------------------------------------------------------------------
  // Full pass-through (happy path)
  // -------------------------------------------------------------------------

  /**
   * Tests the full happy-path: all checks pass, decision is 'passed'.
   *
   * @covers ::evaluate
   */
  public function testFullHappyPathReturnsPassedDecision(): void {
    $usernameHash = hash('sha256', 'regularuser');

    $flood = $this->createMock(FloodInterface::class);
    $flood->method('isAllowed')->willReturn(TRUE);
    $flood->method('register');

    $manager = $this->buildManager($flood, $this->buildConfigFactory());

    $decision = $manager->evaluate(
      Request::create('/user/login'),
      '203.0.113.5',
      $usernameHash,
    );

    $this->assertTrue($decision->allowed);
    $this->assertSame('passed', $decision->reason);
    $this->assertSame('203.0.113.5', $decision->identifier);
    $this->assertSame(0, $decision->retryAfter);
  }

}
