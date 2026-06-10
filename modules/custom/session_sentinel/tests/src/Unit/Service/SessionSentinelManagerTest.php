<?php

declare(strict_types=1);

namespace Drupal\Tests\session_sentinel\Unit\Service;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Query\Delete;
use Drupal\Core\Database\Query\Merge;
use Drupal\Core\Database\Query\Select;
use Drupal\Core\Database\Query\Update;
use Drupal\Core\Database\Schema;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\session_sentinel\Service\SessionSentinelManager;
use Drupal\session_sentinel\Value\SessionRecord;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Unit tests for SessionSentinelManager.
 *
 * @group session_sentinel
 * @coversDefaultClass \Drupal\session_sentinel\Service\SessionSentinelManager
 */
final class SessionSentinelManagerTest extends UnitTestCase {

  /**
   * Builds a mock ConfigFactory returning a config with the given values.
   *
   * @param array $values Config key => value pairs.
   *
   * @return \Drupal\Core\Config\ConfigFactoryInterface&MockObject
   */
  private function buildConfigFactory(array $values = []): ConfigFactoryInterface {
    $defaults = [
      'idle_timeout'             => 1800,
      'warning_lead_time'        => 300,
      'role_timeouts'            => [],
      'max_concurrent_sessions'  => 3,
      'exempt_admins_from_limit' => TRUE,
      'enable_device_binding'    => TRUE,
      'kill_on_device_change'    => FALSE,
      'prune_age'                => 604800,
    ];
    $merged = array_merge($defaults, $values);

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
   * Builds a SessionSentinelManager with mocked dependencies.
   *
   * @param \Drupal\Core\Database\Connection|null         $db      Mock DB.
   * @param \Drupal\Core\Config\ConfigFactoryInterface|null $config Config factory.
   * @param \Psr\Log\LoggerInterface|null                 $logger  Mock logger.
   * @param \Symfony\Component\HttpFoundation\Session\SessionInterface|null $session Session mock.
   *
   * @return \Drupal\session_sentinel\Service\SessionSentinelManager
   */
  private function buildManager(
    ?Connection $db = NULL,
    ?ConfigFactoryInterface $config = NULL,
    ?LoggerInterface $logger = NULL,
    ?SessionInterface $session = NULL,
  ): SessionSentinelManager {
    $db     ??= $this->createMock(Connection::class);
    $config ??= $this->buildConfigFactory();
    $logger ??= $this->createMock(LoggerInterface::class);
    $session ??= $this->createMock(SessionInterface::class);
    $account = $this->createMock(AccountProxyInterface::class);

    return new SessionSentinelManager($db, $config, $logger, $session, $account);
  }

  // ---------------------------------------------------------------------------
  // currentSessionIdHash()
  // ---------------------------------------------------------------------------

  /**
   * Tests that currentSessionIdHash() returns SHA-256 of the session ID.
   *
   * @covers ::currentSessionIdHash
   */
  public function testCurrentSessionIdHashReturnsSha256(): void {
    $session = $this->createMock(SessionInterface::class);
    $session->method('isStarted')->willReturn(TRUE);
    $session->method('getId')->willReturn('my-session-id');

    $manager = $this->buildManager(session: $session);
    $this->assertSame(hash('sha256', 'my-session-id'), $manager->currentSessionIdHash());
  }

  /**
   * Tests that currentSessionIdHash() returns empty string when session not started.
   *
   * @covers ::currentSessionIdHash
   */
  public function testCurrentSessionIdHashReturnsEmptyWhenNotStarted(): void {
    $session = $this->createMock(SessionInterface::class);
    $session->method('isStarted')->willReturn(FALSE);

    $manager = $this->buildManager(session: $session);
    $this->assertSame('', $manager->currentSessionIdHash());
  }

  /**
   * Tests that currentSessionIdHash() returns empty string when session ID is empty.
   *
   * @covers ::currentSessionIdHash
   */
  public function testCurrentSessionIdHashReturnsEmptyWhenIdIsEmpty(): void {
    $session = $this->createMock(SessionInterface::class);
    $session->method('isStarted')->willReturn(TRUE);
    $session->method('getId')->willReturn('');

    $manager = $this->buildManager(session: $session);
    $this->assertSame('', $manager->currentSessionIdHash());
  }

  // ---------------------------------------------------------------------------
  // idleTimeoutForUser()
  // ---------------------------------------------------------------------------

  /**
   * Tests that idleTimeoutForUser() returns the global timeout when no role override.
   *
   * @covers ::idleTimeoutForUser
   */
  public function testIdleTimeoutForUserReturnsGlobalDefault(): void {
    $manager = $this->buildManager(config: $this->buildConfigFactory(['idle_timeout' => 900]));
    $user = $this->createMock(\Drupal\user\UserInterface::class);
    $user->method('getRoles')->willReturn([]);

    $this->assertSame(900, $manager->idleTimeoutForUser($user));
  }

  /**
   * Tests that idleTimeoutForUser() returns the smallest per-role override.
   *
   * @covers ::idleTimeoutForUser
   */
  public function testIdleTimeoutForUserReturnsTightestRoleOverride(): void {
    $manager = $this->buildManager(config: $this->buildConfigFactory([
      'idle_timeout'  => 1800,
      'role_timeouts' => ['editor' => 600, 'moderator' => 1200],
    ]));
    $user = $this->createMock(\Drupal\user\UserInterface::class);
    $user->method('getRoles')->willReturn(['editor', 'moderator']);

    $this->assertSame(600, $manager->idleTimeoutForUser($user));
  }

  /**
   * Tests that a role timeout of 0 falls back to the global setting.
   *
   * @covers ::idleTimeoutForUser
   */
  public function testIdleTimeoutForUserIgnoresZeroRoleOverride(): void {
    $manager = $this->buildManager(config: $this->buildConfigFactory([
      'idle_timeout'  => 1800,
      'role_timeouts' => ['editor' => 0],
    ]));
    $user = $this->createMock(\Drupal\user\UserInterface::class);
    $user->method('getRoles')->willReturn(['editor']);

    $this->assertSame(1800, $manager->idleTimeoutForUser($user));
  }

  // ---------------------------------------------------------------------------
  // isSessionIdle()
  // ---------------------------------------------------------------------------

  /**
   * Tests isSessionIdle() returns true when session exceeds configured timeout.
   *
   * @covers ::isSessionIdle
   */
  public function testIsSessionIdleReturnsTrueWhenExpired(): void {
    $manager = $this->buildManager(config: $this->buildConfigFactory(['idle_timeout' => 1800]));
    $user = $this->createMock(\Drupal\user\UserInterface::class);
    $user->method('getRoles')->willReturn([]);

    // Create a record with last_active 2000 seconds ago.
    $now    = time();
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', $now - 2000);
    $record = $record->withLastActive($now - 2000);

    $this->assertTrue($manager->isSessionIdle($record, $user, $now));
  }

  /**
   * Tests isSessionIdle() returns false when session is within timeout.
   *
   * @covers ::isSessionIdle
   */
  public function testIsSessionIdleReturnsFalseWhenActive(): void {
    $manager = $this->buildManager(config: $this->buildConfigFactory(['idle_timeout' => 1800]));
    $user = $this->createMock(\Drupal\user\UserInterface::class);
    $user->method('getRoles')->willReturn([]);

    $now    = time();
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', $now - 100);
    $record = $record->withLastActive($now - 100);

    $this->assertFalse($manager->isSessionIdle($record, $user, $now));
  }

  // ---------------------------------------------------------------------------
  // pruneStaleRecords()
  // ---------------------------------------------------------------------------

  /**
   * Tests pruneStaleRecords() executes a DELETE and returns the count.
   *
   * @covers ::pruneStaleRecords
   */
  public function testPruneStaleRecordsReturnsDeletedCount(): void {
    $delete = $this->createMock(Delete::class);
    $delete->method('condition')->willReturnSelf();
    $delete->method('execute')->willReturn(7);

    $db = $this->createMock(Connection::class);
    $db->method('delete')->willReturn($delete);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('info');

    $manager = $this->buildManager(db: $db, logger: $logger);
    $this->assertSame(7, $manager->pruneStaleRecords());
  }

  /**
   * Tests pruneStaleRecords() does not log when no records are deleted.
   *
   * @covers ::pruneStaleRecords
   */
  public function testPruneStaleRecordsDoesNotLogWhenNothingDeleted(): void {
    $delete = $this->createMock(Delete::class);
    $delete->method('condition')->willReturnSelf();
    $delete->method('execute')->willReturn(0);

    $db = $this->createMock(Connection::class);
    $db->method('delete')->willReturn($delete);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->never())->method('info');

    $manager = $this->buildManager(db: $db, logger: $logger);
    $this->assertSame(0, $manager->pruneStaleRecords());
  }

  // ---------------------------------------------------------------------------
  // touchSession()
  // ---------------------------------------------------------------------------

  /**
   * Tests that touchSession() calls UPDATE with correct fields.
   *
   * @covers ::touchSession
   */
  public function testTouchSessionUpdatesLastActive(): void {
    $update = $this->createMock(Update::class);
    $update->method('fields')->willReturnSelf();
    $update->method('condition')->willReturnSelf();
    $update->expects($this->once())->method('execute');

    $db = $this->createMock(Connection::class);
    $db->expects($this->once())
      ->method('update')
      ->with('session_sentinel_sessions')
      ->willReturn($update);

    $manager = $this->buildManager(db: $db);
    $manager->touchSession('abc123hash');
  }

  /**
   * Tests that touchSession() does nothing when hash is empty.
   *
   * @covers ::touchSession
   */
  public function testTouchSessionDoesNothingForEmptyHash(): void {
    $db = $this->createMock(Connection::class);
    $db->expects($this->never())->method('update');

    $manager = $this->buildManager(db: $db);
    $manager->touchSession('');
  }

  // ---------------------------------------------------------------------------
  // flagDeviceChange()
  // ---------------------------------------------------------------------------

  /**
   * Tests that flagDeviceChange() issues an UPDATE with the correct flag.
   *
   * @covers ::flagDeviceChange
   */
  public function testFlagDeviceChangeUpdatesRecord(): void {
    $update = $this->createMock(Update::class);
    $update->method('fields')->willReturnSelf();
    $update->method('condition')->willReturnSelf();
    $update->expects($this->once())->method('execute');

    $db = $this->createMock(Connection::class);
    $db->expects($this->once())->method('update')->willReturn($update);

    $manager = $this->buildManager(db: $db);
    $manager->flagDeviceChange('validhash');
  }

  /**
   * Tests that flagDeviceChange() does nothing for empty hash.
   *
   * @covers ::flagDeviceChange
   */
  public function testFlagDeviceChangeDoesNothingForEmptyHash(): void {
    $db = $this->createMock(Connection::class);
    $db->expects($this->never())->method('update');

    $manager = $this->buildManager(db: $db);
    $manager->flagDeviceChange('');
  }

  // ---------------------------------------------------------------------------
  // loadRecord()
  // ---------------------------------------------------------------------------

  /**
   * Tests that loadRecord() returns NULL for empty hash.
   *
   * @covers ::loadRecord
   */
  public function testLoadRecordReturnsNullForEmptyHash(): void {
    $db = $this->createMock(Connection::class);
    $db->expects($this->never())->method('select');

    $manager = $this->buildManager(db: $db);
    $this->assertNull($manager->loadRecord(''));
  }

}
