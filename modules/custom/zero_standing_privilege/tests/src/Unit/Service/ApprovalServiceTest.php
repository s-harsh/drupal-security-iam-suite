<?php

declare(strict_types=1);

namespace Drupal\Tests\zero_standing_privilege\Unit\Service;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\user\UserInterface;
use Drupal\zero_standing_privilege\Entity\ElevationRequestInterface;
use Drupal\zero_standing_privilege\Service\ApprovalService;
use Drupal\zero_standing_privilege\Service\ElevationNotifier;
use Drupal\zero_standing_privilege\Service\PrivilegeManager;
use Drupal\zero_standing_privilege\Value\ElevationStatus;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for ApprovalService.
 *
 * @group zero_standing_privilege
 * @coversDefaultClass \Drupal\zero_standing_privilege\Service\ApprovalService
 */
final class ApprovalServiceTest extends UnitTestCase {

  // ---------------------------------------------------------------------------
  // Factory helpers
  // ---------------------------------------------------------------------------

  /**
   * Builds a mock ConfigFactoryInterface with given settings.
   */
  private function buildConfigFactory(array $settings = []): ConfigFactoryInterface {
    $defaults = [
      'approver_roles' => ['administrator'],
      'approver_uids'  => [],
    ];
    $merged = array_merge($defaults, $settings);

    $config = $this->createMock(Config::class);
    $config->method('get')->willReturnCallback(static fn(string $k) => $merged[$k] ?? NULL);

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturn($config);
    return $factory;
  }

  /**
   * Builds an ApprovalService with the given collaborators.
   */
  private function buildService(
    EntityTypeManagerInterface $entityTypeManager,
    ConfigFactoryInterface $configFactory,
    ?PrivilegeManager $privilegeManager = NULL,
    ?ElevationNotifier $notifier = NULL,
    ?LoggerInterface $logger = NULL,
  ): ApprovalService {
    $privilegeManager ??= $this->createMock(PrivilegeManager::class);
    $notifier         ??= $this->createMock(ElevationNotifier::class);
    $logger           ??= $this->createMock(LoggerInterface::class);

    return new ApprovalService(
      $entityTypeManager,
      $configFactory,
      $logger,
      $privilegeManager,
      $notifier,
    );
  }

  // ---------------------------------------------------------------------------
  // isApprover
  // ---------------------------------------------------------------------------

  /**
   * Tests that a UID in approver_uids is recognized as an approver.
   *
   * @covers ::isApprover
   */
  public function testIsApproverReturnsTrueForUidInApproverList(): void {
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(['approver_uids' => [42]]),
    );

    $this->assertTrue($service->isApprover(42));
  }

  /**
   * Tests that a user with an approver role is recognized as an approver.
   *
   * @covers ::isApprover
   */
  public function testIsApproverReturnsTrueForUserWithApproverRole(): void {
    $user = $this->createMock(UserInterface::class);
    $user->method('hasRole')->willReturnCallback(
      static fn(string $role) => $role === 'administrator'
    );

    $userStorage = $this->createMock(EntityStorageInterface::class);
    $userStorage->method('load')->with(5)->willReturn($user);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($userStorage);

    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(['approver_roles' => ['administrator']]),
    );

    $this->assertTrue($service->isApprover(5));
  }

  /**
   * Tests that a user without any approver role is NOT an approver.
   *
   * @covers ::isApprover
   */
  public function testIsApproverReturnsFalseForRegularUser(): void {
    $user = $this->createMock(UserInterface::class);
    $user->method('hasRole')->willReturn(FALSE);

    $userStorage = $this->createMock(EntityStorageInterface::class);
    $userStorage->method('load')->willReturn($user);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($userStorage);

    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(['approver_uids' => [], 'approver_roles' => ['administrator']]),
    );

    $this->assertFalse($service->isApprover(7));
  }

  /**
   * Tests that isApprover returns FALSE when the user does not exist.
   *
   * @covers ::isApprover
   */
  public function testIsApproverReturnsFalseWhenUserNotFound(): void {
    $userStorage = $this->createMock(EntityStorageInterface::class);
    $userStorage->method('load')->willReturn(NULL);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->willReturn($userStorage);

    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(['approver_uids' => [], 'approver_roles' => ['administrator']]),
    );

    $this->assertFalse($service->isApprover(9999));
  }

  // ---------------------------------------------------------------------------
  // approve
  // ---------------------------------------------------------------------------

  /**
   * Tests that approve calls privilegeManager->grantElevation with correct args.
   *
   * @covers ::approve
   */
  public function testApproveCallsGrantElevation(): void {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn('10');
    $request->method('getStatus')->willReturn(ElevationStatus::Pending);

    $privilegeManager = $this->createMock(PrivilegeManager::class);
    $privilegeManager->method('loadRequest')->with(10)->willReturn($request);
    $privilegeManager->expects($this->once())
      ->method('grantElevation')
      ->with($request, 1, 'Approved.');

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(),
      privilegeManager: $privilegeManager,
    );

    $result = $service->approve(10, 1, 'Approved.');
    $this->assertSame($request, $result);
  }

  /**
   * Tests that approve throws LogicException for a non-pending request.
   *
   * @covers ::approve
   */
  public function testApproveThrowsForNonPendingRequest(): void {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn('11');
    $request->method('getStatus')->willReturn(ElevationStatus::Approved);

    $privilegeManager = $this->createMock(PrivilegeManager::class);
    $privilegeManager->method('loadRequest')->with(11)->willReturn($request);
    $privilegeManager->expects($this->never())->method('grantElevation');

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(),
      privilegeManager: $privilegeManager,
    );

    $this->expectException(\LogicException::class);
    $service->approve(11, 1);
  }

  /**
   * Tests that approve throws InvalidArgumentException when request not found.
   *
   * @covers ::approve
   */
  public function testApproveThrowsInvalidArgumentExceptionWhenRequestNotFound(): void {
    $privilegeManager = $this->createMock(PrivilegeManager::class);
    $privilegeManager->method('loadRequest')->with(999)->willReturn(NULL);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(),
      privilegeManager: $privilegeManager,
    );

    $this->expectException(\InvalidArgumentException::class);
    $service->approve(999, 1);
  }

  // ---------------------------------------------------------------------------
  // deny
  // ---------------------------------------------------------------------------

  /**
   * Tests that deny calls privilegeManager->denyRequest with correct args.
   *
   * @covers ::deny
   */
  public function testDenyCallsDenyRequest(): void {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn('20');
    $request->method('getStatus')->willReturn(ElevationStatus::Pending);

    $privilegeManager = $this->createMock(PrivilegeManager::class);
    $privilegeManager->method('loadRequest')->with(20)->willReturn($request);
    $privilegeManager->expects($this->once())
      ->method('denyRequest')
      ->with($request, 3, 'Not in change window.');

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(),
      privilegeManager: $privilegeManager,
    );

    $result = $service->deny(20, 3, 'Not in change window.');
    $this->assertSame($request, $result);
  }

  /**
   * Tests that deny throws LogicException when request is already approved.
   *
   * @covers ::deny
   */
  public function testDenyThrowsForAlreadyApprovedRequest(): void {
    $request = $this->createMock(ElevationRequestInterface::class);
    $request->method('id')->willReturn('21');
    $request->method('getStatus')->willReturn(ElevationStatus::Approved);

    $privilegeManager = $this->createMock(PrivilegeManager::class);
    $privilegeManager->method('loadRequest')->with(21)->willReturn($request);
    $privilegeManager->expects($this->never())->method('denyRequest');

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(),
      privilegeManager: $privilegeManager,
    );

    $this->expectException(\LogicException::class);
    $service->deny(21, 3);
  }

  /**
   * Tests that deny throws InvalidArgumentException when request not found.
   *
   * @covers ::deny
   */
  public function testDenyThrowsInvalidArgumentExceptionWhenRequestNotFound(): void {
    $privilegeManager = $this->createMock(PrivilegeManager::class);
    $privilegeManager->method('loadRequest')->willReturn(NULL);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $service = $this->buildService(
      $entityTypeManager,
      $this->buildConfigFactory(),
      privilegeManager: $privilegeManager,
    );

    $this->expectException(\InvalidArgumentException::class);
    $service->deny(888, 2);
  }

}
