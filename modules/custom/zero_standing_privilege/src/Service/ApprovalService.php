<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\zero_standing_privilege\Entity\ElevationRequestInterface;
use Drupal\zero_standing_privilege\Value\ElevationStatus;
use Psr\Log\LoggerInterface;

/**
 * Handles the approval and denial side of the ZSP workflow.
 *
 * Separates approval-decision logic from the broader PrivilegeManager so
 * controllers and forms have a focused entry-point. Also enforces approver
 * authorization checks.
 */
final class ApprovalService {

  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly PrivilegeManager $privilegeManager,
    private readonly ElevationNotifier $notifier,
  ) {}

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Determines whether a given user ID may act as an approver.
   *
   * The user qualifies if:
   *  - They appear in the approver_uids list, OR
   *  - They have at least one role in the approver_roles list.
   *
   * @param int $uid
   *   The UID to check.
   *
   * @return bool
   *   TRUE if the user is authorized to approve/deny requests.
   */
  public function isApprover(int $uid): bool {
    $config = $this->configFactory->get('zero_standing_privilege.settings');

    $approverUids = array_map('intval', (array) ($config->get('approver_uids') ?? []));
    if (in_array($uid, $approverUids, TRUE)) {
      return TRUE;
    }

    $approverRoles = (array) ($config->get('approver_roles') ?? []);
    if (empty($approverRoles)) {
      return FALSE;
    }

    $user = $this->entityTypeManager->getStorage('user')->load($uid);
    if ($user === NULL) {
      return FALSE;
    }

    foreach ($approverRoles as $role) {
      if ($user->hasRole($role)) {
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Approves an elevation request on behalf of an approver.
   *
   * @param int $requestId
   *   The elevation request entity ID.
   * @param int $approverId
   *   UID of the approver performing this action.
   * @param string $comment
   *   Optional approver note.
   *
   * @return \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface
   *   The updated request entity.
   *
   * @throws \LogicException
   *   If the request is not in a pending state.
   * @throws \InvalidArgumentException
   *   If the request ID is invalid.
   */
  public function approve(int $requestId, int $approverId, string $comment = ''): ElevationRequestInterface {
    $request = $this->loadOrFail($requestId);

    if (!$request->getStatus()->isPending()) {
      throw new \LogicException(
        "Cannot approve elevation request #$requestId: current status is {$request->getStatus()->value}."
      );
    }

    $this->privilegeManager->grantElevation($request, $approverId, $comment);

    return $request;
  }

  /**
   * Denies an elevation request on behalf of an approver.
   *
   * @param int $requestId
   *   The elevation request entity ID.
   * @param int $approverId
   *   UID of the denier performing this action.
   * @param string $comment
   *   Reason for denial (shown to requester in email).
   *
   * @return \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface
   *   The updated request entity.
   *
   * @throws \LogicException
   *   If the request is not in a pending state.
   * @throws \InvalidArgumentException
   *   If the request ID is invalid.
   */
  public function deny(int $requestId, int $approverId, string $comment = ''): ElevationRequestInterface {
    $request = $this->loadOrFail($requestId);

    if (!$request->getStatus()->isPending()) {
      throw new \LogicException(
        "Cannot deny elevation request #$requestId: current status is {$request->getStatus()->value}."
      );
    }

    $this->privilegeManager->denyRequest($request, $approverId, $comment);

    return $request;
  }

  /**
   * Returns count of pending requests, for dashboard badges.
   */
  public function countPendingRequests(): int {
    return (int) $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('status', ElevationStatus::Pending->value)
      ->count()
      ->execute();
  }

  /**
   * Returns count of currently active (approved) elevations.
   */
  public function countActiveElevations(): int {
    $now = \time();
    return (int) $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('status', ElevationStatus::Approved->value)
      ->condition('expires_at', $now, '>')
      ->count()
      ->execute();
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Loads an ElevationRequest or throws \InvalidArgumentException.
   *
   * @throws \InvalidArgumentException
   */
  private function loadOrFail(int $requestId): ElevationRequestInterface {
    $request = $this->privilegeManager->loadRequest($requestId);
    if ($request === NULL) {
      throw new \InvalidArgumentException("Elevation request #$requestId not found.");
    }
    return $request;
  }

}
