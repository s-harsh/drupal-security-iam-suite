<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\user\UserInterface;
use Drupal\zero_standing_privilege\Entity\ElevationRequest;
use Drupal\zero_standing_privilege\Entity\ElevationRequestInterface;
use Drupal\zero_standing_privilege\Value\ElevationStatus;
use Psr\Log\LoggerInterface;

/**
 * Core service for managing privilege elevation lifecycle.
 *
 * Responsibilities:
 *  - Create new ElevationRequest entities (from form submission).
 *  - Grant a role when a request is approved (sets status + adds role).
 *  - Revoke a role when a request expires or is manually revoked.
 *  - Batch-revoke all expired active elevations (cron / Drush).
 *  - Load helpers: active requests, requests by token, etc.
 */
final class PrivilegeManager {

  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly AccountInterface $currentUser,
    private readonly Connection $database,
    private readonly ElevationNotifier $notifier,
  ) {}

  // ---------------------------------------------------------------------------
  // Request creation
  // ---------------------------------------------------------------------------

  /**
   * Creates and saves a new pending ElevationRequest.
   *
   * @param int $requesterId
   *   UID of the requesting user.
   * @param string $targetRole
   *   Machine name of the role to request.
   * @param string $reason
   *   Justification text.
   * @param int $durationMinutes
   *   Requested duration in minutes (clamped to configured max).
   *
   * @return \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface
   *   The saved (pending) elevation request.
   *
   * @throws \InvalidArgumentException
   *   If the target role is not allowed or duration exceeds the hard cap.
   */
  public function createRequest(
    int $requesterId,
    string $targetRole,
    string $reason,
    int $durationMinutes,
  ): ElevationRequestInterface {
    $config = $this->configFactory->get('zero_standing_privilege.settings');

    // Clamp duration to the configured maximum.
    $maxMinutes = (int) ($config->get('max_elevation_minutes') ?? 240);
    if ($durationMinutes > $maxMinutes) {
      $durationMinutes = $maxMinutes;
    }
    if ($durationMinutes < 1) {
      $durationMinutes = 1;
    }

    // Validate that the target role is in the allowed list (if restricted).
    $allowed = (array) ($config->get('allowed_target_roles') ?? []);
    if (!empty($allowed) && !in_array($targetRole, $allowed, TRUE)) {
      throw new \InvalidArgumentException("Role '$targetRole' is not in the allowed elevation targets.");
    }

    /** @var \Drupal\zero_standing_privilege\Entity\ElevationRequest $entity */
    $entity = $this->entityTypeManager->getStorage('elevation_request')->create([
      'requester_uid'    => $requesterId,
      'target_role'      => $targetRole,
      'reason'           => $reason,
      'duration_minutes' => $durationMinutes,
      'status'           => ElevationStatus::Pending->value,
    ]);

    $entity->save();

    $this->logger->info(
      'Elevation request @id created: UID @uid requested role @role for @min minutes.',
      [
        '@id'   => $entity->id(),
        '@uid'  => $requesterId,
        '@role' => $targetRole,
        '@min'  => $durationMinutes,
      ]
    );

    // Auto-approve if configured for this requester's roles.
    $autoApproveRoles = (array) ($config->get('auto_approve_roles') ?? []);
    if (!empty($autoApproveRoles)) {
      $requesterUser = $this->loadUser($requesterId);
      if ($requesterUser !== NULL) {
        foreach ($autoApproveRoles as $autoRole) {
          if ($requesterUser->hasRole($autoRole)) {
            $this->grantElevation($entity, 1, 'Auto-approved.');
            return $entity;
          }
        }
      }
    }

    // Notify approvers.
    $this->notifier->notifyApproversOnRequest($entity);

    return $entity;
  }

  // ---------------------------------------------------------------------------
  // Grant / Deny
  // ---------------------------------------------------------------------------

  /**
   * Approves and grants the elevation: sets status, adds role, sets timestamps.
   *
   * @param \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface $request
   *   The pending request to approve.
   * @param int $approverId
   *   UID of the approver (1 for auto-approve).
   * @param string $comment
   *   Optional approver note.
   */
  public function grantElevation(
    ElevationRequestInterface $request,
    int $approverId,
    string $comment = '',
  ): void {
    if (!$request->getStatus()->isPending()) {
      throw new \LogicException("Cannot approve request #{$request->id()} in status {$request->getStatus()->value}.");
    }

    $now = \time();
    $expiresAt = $now + ($request->getDurationMinutes() * 60);

    $request->set('approver_uid', $approverId);
    $request->set('approver_comment', $comment);
    $request->set('granted_at', $now);
    $request->set('expires_at', $expiresAt);
    $request->setStatus(ElevationStatus::Approved);

    // Generate revocation token if enabled.
    $config = $this->configFactory->get('zero_standing_privilege.settings');
    if ($config->get('revocation_token_enabled')) {
      $request->generateRevocationToken();
    }

    $request->save();

    // Add the role to the requester's user account.
    $user = $this->loadUser($request->getRequesterId());
    if ($user !== NULL) {
      $user->addRole($request->getTargetRole());
      $user->save();
    }

    $this->logger->notice(
      'Elevation @id granted: UID @uid received role @role until @exp (approver @approver).',
      [
        '@id'       => $request->id(),
        '@uid'      => $request->getRequesterId(),
        '@role'     => $request->getTargetRole(),
        '@exp'      => date('Y-m-d H:i:s', $expiresAt),
        '@approver' => $approverId,
      ]
    );

    $this->notifier->notifyRequesterOnGrant($request);
  }

  /**
   * Denies an elevation request.
   *
   * @param \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface $request
   *   The pending request to deny.
   * @param int $approverId
   *   UID of the denier.
   * @param string $comment
   *   Reason for denial.
   */
  public function denyRequest(
    ElevationRequestInterface $request,
    int $approverId,
    string $comment = '',
  ): void {
    if (!$request->getStatus()->isPending()) {
      throw new \LogicException("Cannot deny request #{$request->id()} in status {$request->getStatus()->value}.");
    }

    $request->set('approver_uid', $approverId);
    $request->set('approver_comment', $comment);
    $request->setStatus(ElevationStatus::Denied);
    $request->save();

    $this->logger->notice(
      'Elevation @id denied: UID @uid was denied role @role (denier @approver). Reason: @reason',
      [
        '@id'       => $request->id(),
        '@uid'      => $request->getRequesterId(),
        '@role'     => $request->getTargetRole(),
        '@approver' => $approverId,
        '@reason'   => $comment ?: '(no reason given)',
      ]
    );

    $this->notifier->notifyRequesterOnDeny($request);
  }

  // ---------------------------------------------------------------------------
  // Revocation
  // ---------------------------------------------------------------------------

  /**
   * Immediately revokes an active elevation, removing the role.
   *
   * @param \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface $request
   *   An approved (active) elevation request.
   * @param string $reason
   *   Audit note for the revocation ('manual', 'expired', 'token', etc.).
   */
  public function revokeElevation(
    ElevationRequestInterface $request,
    string $reason = 'manual',
  ): void {
    $status = $request->getStatus();
    if (!$status->isActive()) {
      // Already in a terminal or non-active state — nothing to revoke.
      $this->logger->info(
        'Skipping revocation of elevation @id: status is already @status.',
        ['@id' => $request->id(), '@status' => $status->value]
      );
      return;
    }

    $newStatus = ($reason === 'expired') ? ElevationStatus::Expired : ElevationStatus::Revoked;
    $request->setStatus($newStatus);
    $request->set('revocation_token', ''); // Invalidate token.
    $request->save();

    // Remove the role from the user account.
    $user = $this->loadUser($request->getRequesterId());
    if ($user !== NULL) {
      $user->removeRole($request->getTargetRole());
      $user->save();
    }

    $this->logger->notice(
      'Elevation @id @reason: UID @uid had role @role revoked.',
      [
        '@id'     => $request->id(),
        '@reason' => $reason,
        '@uid'    => $request->getRequesterId(),
        '@role'   => $request->getTargetRole(),
      ]
    );

    if ($reason === 'expired') {
      $this->notifier->notifyRequesterOnExpiry($request);
    }
  }

  /**
   * Revokes all approved elevations whose expiry time has passed.
   *
   * Intended to be called from hook_cron and the Drush command.
   *
   * @return int
   *   The number of elevations revoked.
   */
  public function revokeExpiredElevations(): int {
    $now = \time();

    $ids = $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('status', ElevationStatus::Approved->value)
      ->condition('expires_at', $now, '<=')
      ->condition('expires_at', 0, '>')
      ->execute();

    if (empty($ids)) {
      return 0;
    }

    $requests = $this->entityTypeManager->getStorage('elevation_request')
      ->loadMultiple($ids);

    $count = 0;
    foreach ($requests as $request) {
      if ($request instanceof ElevationRequestInterface) {
        try {
          $this->revokeElevation($request, 'expired');
          $count++;
        }
        catch (\Exception $e) {
          $this->logger->error(
            'ZSP: failed to revoke expired elevation @id: @msg',
            ['@id' => $request->id(), '@msg' => $e->getMessage()]
          );
        }
      }
    }

    if ($count > 0) {
      $this->logger->info('ZSP cron: revoked @count expired elevations.', ['@count' => $count]);
    }

    return $count;
  }

  /**
   * Looks up an approved elevation by its revocation token and revokes it.
   *
   * @param string $token
   *   The revocation token from the email link.
   *
   * @return bool
   *   TRUE if a matching active elevation was found and revoked, FALSE otherwise.
   */
  public function revokeByToken(string $token): bool {
    if (empty($token)) {
      return FALSE;
    }

    $ids = $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('revocation_token', $token)
      ->condition('status', ElevationStatus::Approved->value)
      ->execute();

    if (empty($ids)) {
      return FALSE;
    }

    $request = $this->entityTypeManager->getStorage('elevation_request')
      ->load(reset($ids));

    if (!($request instanceof ElevationRequestInterface)) {
      return FALSE;
    }

    $this->revokeElevation($request, 'token');
    return TRUE;
  }

  // ---------------------------------------------------------------------------
  // Query helpers
  // ---------------------------------------------------------------------------

  /**
   * Returns all pending elevation requests, newest first.
   *
   * @return \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface[]
   */
  public function getPendingRequests(): array {
    $ids = $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('status', ElevationStatus::Pending->value)
      ->sort('created', 'ASC')
      ->execute();

    return $this->loadRequests($ids);
  }

  /**
   * Returns all currently active (approved, not expired) elevations.
   *
   * @return \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface[]
   */
  public function getActiveElevations(): array {
    $now = \time();

    $ids = $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('status', ElevationStatus::Approved->value)
      ->condition('expires_at', $now, '>')
      ->sort('expires_at', 'ASC')
      ->execute();

    return $this->loadRequests($ids);
  }

  /**
   * Returns elevation requests for a specific user, newest first.
   *
   * @param int $uid
   *   The UID to load requests for.
   * @param int $limit
   *   Maximum number of requests to return.
   *
   * @return \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface[]
   */
  public function getRequestsForUser(int $uid, int $limit = 25): array {
    $ids = $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('requester_uid', $uid)
      ->sort('created', 'DESC')
      ->range(0, $limit)
      ->execute();

    return $this->loadRequests($ids);
  }

  /**
   * Returns the full audit log, newest first.
   *
   * @param int $limit
   *   Maximum number of records.
   * @param int $offset
   *   Pager offset.
   *
   * @return \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface[]
   */
  public function getAuditLog(int $limit = 50, int $offset = 0): array {
    $ids = $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->sort('created', 'DESC')
      ->range($offset, $limit)
      ->execute();

    return $this->loadRequests($ids);
  }

  /**
   * Returns a single ElevationRequest by ID or NULL if not found.
   */
  public function loadRequest(int $id): ?ElevationRequestInterface {
    $entity = $this->entityTypeManager->getStorage('elevation_request')->load($id);
    return ($entity instanceof ElevationRequestInterface) ? $entity : NULL;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Loads multiple ElevationRequest entities by an array of IDs.
   *
   * @param array<int|string> $ids
   *
   * @return \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface[]
   */
  private function loadRequests(array $ids): array {
    if (empty($ids)) {
      return [];
    }
    $entities = $this->entityTypeManager->getStorage('elevation_request')
      ->loadMultiple($ids);
    return array_filter($entities, static fn($e) => $e instanceof ElevationRequestInterface);
  }

  /**
   * Loads a user entity by UID, returning NULL on failure.
   */
  private function loadUser(int $uid): ?UserInterface {
    if ($uid === 0) {
      return NULL;
    }
    $user = $this->entityTypeManager->getStorage('user')->load($uid);
    return ($user instanceof UserInterface) ? $user : NULL;
  }

}
