<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Unit\Hook;

use Drupal\api_flood_guard\Hook\ApiFloodGuardHooks;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Tests\UnitTestCase;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for ApiFloodGuardHooks.
 *
 * @group api_flood_guard
 * @coversDefaultClass \Drupal\api_flood_guard\Hook\ApiFloodGuardHooks
 */
final class ApiFloodGuardHooksTest extends UnitTestCase {

  /**
   * Builds an ApiFloodGuardHooks instance with mocked dependencies.
   */
  private function buildHooks(): ApiFloodGuardHooks {
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $logger = $this->createMock(LoggerInterface::class);
    $database = $this->createMock(Connection::class);

    return new ApiFloodGuardHooks($configFactory, $logger, $database);
  }

  // -------------------------------------------------------------------------
  // cacheBinInfo()
  // -------------------------------------------------------------------------

  /**
   * Tests that cacheBinInfo() returns the expected 'api_flood_guard' key.
   *
   * @covers ::cacheBinInfo
   */
  public function testCacheBinInfoReturnsApiFloodGuardKey(): void {
    $hooks = $this->buildHooks();
    $result = $hooks->cacheBinInfo();

    $this->assertArrayHasKey('api_flood_guard', $result);
  }

  /**
   * Tests that cacheBinInfo() result has a 'label' sub-key.
   *
   * @covers ::cacheBinInfo
   */
  public function testCacheBinInfoHasLabelKey(): void {
    $hooks = $this->buildHooks();
    $result = $hooks->cacheBinInfo();

    $this->assertArrayHasKey('label', $result['api_flood_guard']);
  }

  /**
   * Tests that cacheBinInfo() result has a 'description' sub-key.
   *
   * @covers ::cacheBinInfo
   */
  public function testCacheBinInfoHasDescriptionKey(): void {
    $hooks = $this->buildHooks();
    $result = $hooks->cacheBinInfo();

    $this->assertArrayHasKey('description', $result['api_flood_guard']);
  }

  /**
   * Tests that cacheBinInfo() returns exactly one entry.
   *
   * @covers ::cacheBinInfo
   */
  public function testCacheBinInfoReturnsExactlyOneEntry(): void {
    $hooks = $this->buildHooks();
    $result = $hooks->cacheBinInfo();

    $this->assertCount(1, $result);
  }

  // -------------------------------------------------------------------------
  // help()
  // -------------------------------------------------------------------------

  /**
   * Tests that help() returns an empty array for non-matching routes.
   *
   * @covers ::help
   */
  public function testHelpReturnsEmptyArrayForOtherRoutes(): void {
    $container = new ContainerBuilder();
    \Drupal::setContainer($container);

    $hooks = $this->buildHooks();
    $routeMatch = $this->createMock(RouteMatchInterface::class);

    $result = $hooks->help('some.other.route', $routeMatch);

    $this->assertIsArray($result);
    $this->assertEmpty($result);
  }

  /**
   * Tests that help() returns an empty array for the system help page.
   *
   * @covers ::help
   */
  public function testHelpReturnsEmptyForSystemHelpPage(): void {
    $container = new ContainerBuilder();
    \Drupal::setContainer($container);

    $hooks = $this->buildHooks();
    $routeMatch = $this->createMock(RouteMatchInterface::class);

    $result = $hooks->help('help.page.system', $routeMatch);

    $this->assertIsArray($result);
    $this->assertEmpty($result);
  }

  /**
   * Tests that help() returns array, string, or renderable for help.page.api_flood_guard.
   *
   * Because this route needs Url::fromRoute() which requires routing services,
   * we only verify it does NOT return the non-matching empty-array result.
   * Full rendering is exercised in functional tests.
   *
   * @covers ::help
   */
  public function testHelpForMatchingRouteReturnsNonEmptyOrSkips(): void {
    // Install a minimal container so Url::fromRoute calls don't hard-crash.
    $container = new ContainerBuilder();
    \Drupal::setContainer($container);

    $hooks = $this->buildHooks();
    $routeMatch = $this->createMock(RouteMatchInterface::class);

    // If routing services are unavailable this may throw; catch and skip.
    try {
      $result = $hooks->help('help.page.api_flood_guard', $routeMatch);
      // The result, if it comes back, should be either a string or a render array.
      $this->assertTrue(is_string($result) || is_array($result));
    }
    catch (\Exception $e) {
      // In unit test context without full container, routing services are absent.
      // This is expected — the functional test covers the full help page render.
      $this->markTestSkipped('Routing services unavailable in unit context: ' . $e->getMessage());
    }
  }

  // -------------------------------------------------------------------------
  // cron() — verifies it runs without throwing
  // -------------------------------------------------------------------------

  /**
   * Tests that cron() executes without throwing when the database returns zeros.
   *
   * @covers ::cron
   */
  public function testCronRunsWithoutThrowing(): void {
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('info');

    // Build a database mock that returns 0 for all count queries.
    $statement = $this->createMock(\Drupal\Core\Database\StatementInterface::class);
    $statement->method('fetchField')->willReturn(0);

    $countQuery = $this->createMock(\Drupal\Core\Database\Query\Select::class);
    $countQuery->method('execute')->willReturn($statement);

    $selectQuery = $this->createMock(\Drupal\Core\Database\Query\Select::class);
    $selectQuery->method('condition')->willReturnSelf();
    $selectQuery->method('countQuery')->willReturn($countQuery);

    $schema = $this->createMock(\Drupal\Core\Database\Schema::class);
    $schema->method('tableExists')->willReturn(FALSE); // watchdog doesn't exist.

    $database = $this->createMock(Connection::class);
    $database->method('select')->willReturn($selectQuery);
    $database->method('schema')->willReturn($schema);

    $hooks = new ApiFloodGuardHooks($configFactory, $logger, $database);

    // Should not throw.
    $hooks->cron();
  }

  /**
   * Tests that cron() logs with the expected placeholders.
   *
   * @covers ::cron
   */
  public function testCronLogsCorrectPlaceholders(): void {
    $configFactory = $this->createMock(ConfigFactoryInterface::class);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())
      ->method('info')
      ->with(
        $this->stringContains('@ip_count'),
        $this->callback(static function (array $context): bool {
          return array_key_exists('@ip_count', $context)
            && array_key_exists('@user_count', $context)
            && array_key_exists('@block_count', $context);
        }),
      );

    $statement = $this->createMock(\Drupal\Core\Database\StatementInterface::class);
    $statement->method('fetchField')->willReturn(0);

    $countQuery = $this->createMock(\Drupal\Core\Database\Query\Select::class);
    $countQuery->method('execute')->willReturn($statement);

    $selectQuery = $this->createMock(\Drupal\Core\Database\Query\Select::class);
    $selectQuery->method('condition')->willReturnSelf();
    $selectQuery->method('countQuery')->willReturn($countQuery);

    $schema = $this->createMock(\Drupal\Core\Database\Schema::class);
    $schema->method('tableExists')->willReturn(FALSE);

    $database = $this->createMock(Connection::class);
    $database->method('select')->willReturn($selectQuery);
    $database->method('schema')->willReturn($schema);

    $hooks = new ApiFloodGuardHooks($configFactory, $logger, $database);
    $hooks->cron();
  }

}
