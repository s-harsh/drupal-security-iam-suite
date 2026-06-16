<?php

declare(strict_types=1);

namespace Drupal\Tests\zero_standing_privilege\Unit\Service;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\Query\QueryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\user\UserInterface;
use Drupal\zero_standing_privilege\Entity\ElevationRequestInterface;
use Drupal\zero_standing_privilege\Service\ElevationNotifier;
use Drupal\zero_standing_privilege\Service\PrivilegeManager;
use Drupal\zero_standing_privilege\Value\ElevationStatus;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for PrivilegeManager.
 *
 * @group zero_standing_privilege
 * @coversDefaultClass \Drupal\zero_standing_privilege\Service\PrivilegeManager
 */
final class PrivilegeManagerTest extends UnitTestCase {

  // ---------------------------------------------------------------------------
  // Factory helpers
  // ---------------------------------------------------------------------------

  /**
   * Builds a mock ConfigFactoryInterface backed by an array of settings.
   */
  private function buildConfigFactory(array $settings = []): ConfigFactoryInterface {
    $defaults = [
      'max_elevation_minutes'  => 240,
      'default_elevation_minutes' => 60,
      'allowed_target_roles'   => [],
      'auto_approve_roles'     => [],
      'revocation_token_enabled' => FALSE,
      'require_approval'       => TRUE,
    ];
    $merged = array_merge($defaults, $settings);

    $config = $this->createMock(Config::class);
    $config->method('get')->willReturnCallback(static fn(string $k) => $merged[$k] ?? NULL);

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturn($config);
    return $factory;
  }

  /**
   * Creates a PrivilegeManager with the supplied collaborators.
   */
  private function buildManager(
    EntityTypeManagerInterface $entityTypeManager,
    ConfigFactoryInterface $configFactory,
    ?LoggerInterface $logger = NULL,
    ?ElevationNotifier $notifier = NULL,
  ): PrivilegeManager {
    $logger   ??= $this->createMock(LoggerInterface::class);
    $notifier ??= $this->createMock(ElevationNotifier::class);
    $currentUser = $this->createMock(AccountInterface::class);
    $database    = $this->createMock(Connection::class);

    return new PrivilegeManager(
      $entityTypeManager,
      $configFactory,
      $logger,
      $currentUser,
      $database,
      $notifier,
    );
  }

  /**
   * Builds a minimal ElevationRequestInterface mock with the given status.
   */
  private function buildRequest(
    ElevationStatus $status = ElevationStatus::Pending,
    int $id = 1,
    int $requesterUid = 10,
    string $role = 'editor',
    int $durationMinutes = 60,
    int $expiresAt = 0,
  ): MockObject&ElevationRequestInterface {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn((string) $id);
    $request->method('getStatus')->willReturn($status);
    $request->method('getRequesterId')->willReturn($requesterUid);
    $request->method('getTargetRole')->willReturn($role);
    $request->method('getDurationMinutes')->willReturn($durationMinutes);
    $request->method('getGrantedAt')->willReturn(0);
    $request->method('getExpiresAt')->willReturn($expiresAt);
    $request->method('getApproverComment')->willReturn('');
    $request->method('getRevocationToken')->willReturn('');
    return $request;
  }

  // ---------------------------------------------------------------------------
  // createRequest — validation
  // ---------------------------------------------------------------------------

  /**
   * Tests that createRequest clamps duration to configured max.
   *
   * @covers ::createRequest
   */
  public function testCreateRequestClampsDurationToMax(): void {
    $savedDuration = NULL;

    $storage = $this->createMock(EntityStorageInterface::class);
    $query   = $this->createMock(QueryInterface::class);

    $entity = $this->createMock(ElevationRequestInterface::class);
    $entity->method('id')->willReturn('1');
    $entity->method('getStatus')->willReturn(ElevationStatus::Pending);
    $entity->method('save');

    $storage->method('create')->willReturnCallback(
      static function (array $values) use ($entity, &$savedDuration): ElevationRequestInterface {
        $savedDuration = $values['duration_minutes'];
        return $entity;
      }
    );

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($storage);

    $notifier = $this->createMock(ElevationNotifier::class);
    $notifier->expects($this->once())->method('notifyApproversOnRequest');

    $manager = $this->buildManager(
      $entityTypeManager,
      $this->buildConfigFactory(['max_elevation_minutes' => 120]),
      notifier: $notifier,
    );

    $manager->createRequest(10, 'editor', 'Need to publish content', 999);

    $this->assertSame(120, $savedDuration, 'Duration should be clamped to 120 minutes.');
  }

  /**
   * Tests that createRequest throws when targetRole is not in the allowed list.
   *
   * @covers ::createRequest
   */
  public function testCreateRequestThrowsForDisallowedRole(): void {
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);

    $manager = $this->buildManager(
      $entityTypeManager,
      $this->buildConfigFactory(['allowed_target_roles' => ['editor']]),
    );

    $this->expectException(\InvalidArgumentException::class);
    $manager->createRequest(10, 'administrator', 'test', 30);
  }

  /**
   * Tests that createRequest allows any role when allowed_target_roles is empty.
   *
   * @covers ::createRequest
   */
  public function testCreateRequestAllowsAnyRoleWhenAllowedListIsEmpty(): void {
    $entity = $this->createMock(ElevationRequestInterface::class);
    $entity->method('id')->willReturn('1');
    $entity->method('getStatus')->willReturn(ElevationStatus::Pending);

    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('create')->willReturn($entity);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($storage);

    $notifier = $this->createMock(ElevationNotifier::class);

    $manager = $this->buildManager(
      $entityTypeManager,
      $this->buildConfigFactory(['allowed_target_roles' => []]),
      notifier: $notifier,
    );

    // Should not throw.
    $result = $manager->createRequest(10, 'administrator', 'test', 30);
    $this->assertSame($entity, $result);
  }

  // ---------------------------------------------------------------------------
  // grantElevation
  // ---------------------------------------------------------------------------

  /**
   * Tests that grantElevation throws when request is not pending.
   *
   * @covers ::grantElevation
   */
  public function testGrantElevationThrowsForNonPendingRequest(): void {
    $request = $this->buildRequest(ElevationStatus::Approved);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory());

    $this->expectException(\LogicException::class);
    $manager->grantElevation($request, 1);
  }

  /**
   * Tests that grantElevation sets status to Approved, adds role, and notifies.
   *
   * @covers ::grantElevation
   */
  public function testGrantElevationSetsApprovedStatusAndAddsRole(): void {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn('5');
    $request->method('getStatus')->willReturn(ElevationStatus::Pending);
    $request->method('getRequesterId')->willReturn(42);
    $request->method('getTargetRole')->willReturn('editor');
    $request->method('getDurationMinutes')->willReturn(60);
    $request->method('getGrantedAt')->willReturn(0);
    $request->method('getExpiresAt')->willReturnCallback(static fn() => \time() + 3600);

    // Expect setStatus(Approved) to be called.
    $request->expects($this->once())
      ->method('setStatus')
      ->with(ElevationStatus::Approved)
      ->willReturnSelf();

    $request->expects($this->once())->method('save');

    // Mock user — should receive addRole and save.
    $user = $this->createMock(UserInterface::class);
    $user->expects($this->once())->method('addRole')->with('editor');
    $user->expects($this->once())->method('save');

    $userStorage = $this->createMock(EntityStorageInterface::class);
    $userStorage->method('load')->with(42)->willReturn($user);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturnCallback(
      static fn(string $type) => $userStorage
    );

    $notifier = $this->createMock(ElevationNotifier::class);
    $notifier->expects($this->once())->method('notifyRequesterOnGrant');

    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory(), notifier: $notifier);
    $manager->grantElevation($request, 1, 'Approved for deployment.');
  }

  // ---------------------------------------------------------------------------
  // denyRequest
  // ---------------------------------------------------------------------------

  /**
   * Tests that denyRequest throws for non-pending request.
   *
   * @covers ::denyRequest
   */
  public function testDenyRequestThrowsForNonPendingRequest(): void {
    $request = $this->buildRequest(ElevationStatus::Denied);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory());

    $this->expectException(\LogicException::class);
    $manager->denyRequest($request, 1, 'Already denied.');
  }

  /**
   * Tests that denyRequest sets Denied status and sends notification.
   *
   * @covers ::denyRequest
   */
  public function testDenyRequestSetsDeniedStatusAndNotifies(): void {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn('7');
    $request->method('getStatus')->willReturn(ElevationStatus::Pending);
    $request->method('getRequesterId')->willReturn(99);
    $request->method('getTargetRole')->willReturn('administrator');

    $request->expects($this->once())
      ->method('setStatus')
      ->with(ElevationStatus::Denied)
      ->willReturnSelf();

    $request->expects($this->once())->method('save');

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);

    $notifier = $this->createMock(ElevationNotifier::class);
    $notifier->expects($this->once())->method('notifyRequesterOnDeny');

    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory(), notifier: $notifier);
    $manager->denyRequest($request, 2, 'Outside change window.');
  }

  // ---------------------------------------------------------------------------
  // revokeElevation
  // ---------------------------------------------------------------------------

  /**
   * Tests that revokeElevation sets Revoked status and removes role.
   *
   * @covers ::revokeElevation
   */
  public function testRevokeElevationRemovesRole(): void {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn('8');
    $request->method('getStatus')->willReturn(ElevationStatus::Approved);
    $request->method('getRequesterId')->willReturn(55);
    $request->method('getTargetRole')->willReturn('editor');

    $request->expects($this->once())
      ->method('setStatus')
      ->with(ElevationStatus::Revoked)
      ->willReturnSelf();
    $request->expects($this->once())->method('save');

    $user = $this->createMock(UserInterface::class);
    $user->expects($this->once())->method('removeRole')->with('editor');
    $user->expects($this->once())->method('save');

    $userStorage = $this->createMock(EntityStorageInterface::class);
    $userStorage->method('load')->with(55)->willReturn($user);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($userStorage);

    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory());
    $manager->revokeElevation($request, 'manual');
  }

  /**
   * Tests that revokeElevation with 'expired' reason sends expiry notification.
   *
   * @covers ::revokeElevation
   */
  public function testRevokeElevationWithExpiredReasonSendsExpiryNotification(): void {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn('9');
    $request->method('getStatus')->willReturn(ElevationStatus::Approved);
    $request->method('getRequesterId')->willReturn(55);
    $request->method('getTargetRole')->willReturn('editor');
    $request->method('setStatus')->willReturnSelf();

    $user = $this->createMock(UserInterface::class);

    $userStorage = $this->createMock(EntityStorageInterface::class);
    $userStorage->method('load')->willReturn($user);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($userStorage);

    $notifier = $this->createMock(ElevationNotifier::class);
    $notifier->expects($this->once())->method('notifyRequesterOnExpiry');

    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory(), notifier: $notifier);
    $manager->revokeElevation($request, 'expired');
  }

  /**
   * Tests that revokeElevation skips when status is already terminal.
   *
   * @covers ::revokeElevation
   */
  public function testRevokeElevationSkipsNonActiveRequest(): void {
    $request = $this->buildRequest(ElevationStatus::Expired);
    $request->expects($this->never())->method('setStatus');
    $request->expects($this->never())->method('save');

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory());
    $manager->revokeElevation($request, 'manual');
  }

  // ---------------------------------------------------------------------------
  // revokeByToken
  // ---------------------------------------------------------------------------

  /**
   * Tests that revokeByToken returns FALSE for an empty token.
   *
   * @covers ::revokeByToken
   */
  public function testRevokeByTokenReturnsFalseForEmptyToken(): void {
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory());

    $this->assertFalse($manager->revokeByToken(''));
  }

  /**
   * Tests that revokeByToken returns FALSE when no matching request is found.
   *
   * @covers ::revokeByToken
   */
  public function testRevokeByTokenReturnsFalseWhenNoMatchFound(): void {
    $query = $this->createMock(QueryInterface::class);
    $query->method('accessCheck')->willReturnSelf();
    $query->method('condition')->willReturnSelf();
    $query->method('execute')->willReturn([]);

    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('getQuery')->willReturn($query);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($storage);

    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory());

    $this->assertFalse($manager->revokeByToken('invalid-token-abc123'));
  }

  // ---------------------------------------------------------------------------
  // revokeExpiredElevations
  // ---------------------------------------------------------------------------

  /**
   * Tests that revokeExpiredElevations returns 0 when there are no expired.
   *
   * @covers ::revokeExpiredElevations
   */
  public function testRevokeExpiredElevationsReturnsZeroWhenNoneFound(): void {
    $query = $this->createMock(QueryInterface::class);
    $query->method('accessCheck')->willReturnSelf();
    $query->method('condition')->willReturnSelf();
    $query->method('execute')->willReturn([]);

    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('getQuery')->willReturn($query);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($storage);

    $manager = $this->buildManager($entityTypeManager, $this->buildConfigFactory());

    $this->assertSame(0, $manager->revokeExpiredElevations());
  }

}
