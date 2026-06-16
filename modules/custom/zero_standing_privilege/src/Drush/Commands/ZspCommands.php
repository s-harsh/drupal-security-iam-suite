<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Drush\Commands;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\zero_standing_privilege\Service\ApprovalService;
use Drupal\zero_standing_privilege\Service\PrivilegeManager;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\zero_standing_privilege\Value\ElevationStatus;
use Drush\Attributes as CLI;
use Drush\Commands\DrushCommands;
use Psr\Log\LoggerInterface;

/**
 * Drush commands for Zero Standing Privilege.
 *
 * Commands:
 *  - zsp:revoke-expired   Revoke all expired active elevations.
 *  - zsp:grant            Directly grant an elevation to a user.
 *  - zsp:status           Show counts of pending requests and active elevations.
 *  - zsp:deny             Deny a specific pending request.
 *  - zsp:list             List requests filtered by status.
 */
final class ZspCommands extends DrushCommands {

  public function __construct(
    private readonly PrivilegeManager $privilegeManager,
    private readonly ApprovalService $approvalService,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {
    parent::__construct();
  }

  // ---------------------------------------------------------------------------
  // zsp:revoke-expired
  // ---------------------------------------------------------------------------

  /**
   * Revokes all active elevations that have passed their expiry time.
   */
  #[CLI\Command(name: 'zsp:revoke-expired', aliases: ['zsp:re'])]
  #[CLI\Usage(name: 'drush zsp:revoke-expired', description: 'Process all expired elevations immediately.')]
  public function revokeExpired(): void {
    $count = $this->privilegeManager->revokeExpiredElevations();

    if ($count === 0) {
      $this->io()->success('No expired elevations found.');
    }
    else {
      $this->io()->success("Revoked $count expired elevation(s).");
    }
  }

  // ---------------------------------------------------------------------------
  // zsp:grant
  // ---------------------------------------------------------------------------

  /**
   * Directly grants a temporary role elevation to a user (bypasses approval).
   *
   * @param string $uid
   *   The numeric user ID to grant the elevation to.
   * @param string $role
   *   The machine name of the role to grant.
   * @param string $minutes
   *   The elevation duration in minutes.
   */
  #[CLI\Command(name: 'zsp:grant', aliases: ['zsp:g'])]
  #[CLI\Argument(name: 'uid',     description: 'User ID to grant the elevation to.')]
  #[CLI\Argument(name: 'role',    description: 'Role machine name to grant.')]
  #[CLI\Argument(name: 'minutes', description: 'Duration in minutes.')]
  #[CLI\Option(name: 'reason', description: 'Audit reason (default: Drush direct grant).')]
  #[CLI\Usage(name: 'drush zsp:grant 5 editor 120', description: 'Grant UID 5 the editor role for 120 minutes.')]
  public function grant(string $uid, string $role, string $minutes, array $options = ['reason' => '']): void {
    $uidInt     = (int) $uid;
    $minutesInt = (int) $minutes;
    $reason     = $options['reason'] ?: 'Drush direct grant by operator.';

    if ($uidInt <= 0) {
      $this->io()->error("Invalid UID: $uid");
      return;
    }

    if ($minutesInt < 1) {
      $this->io()->error("Duration must be at least 1 minute.");
      return;
    }

    // Validate user exists.
    $user = $this->entityTypeManager->getStorage('user')->load($uidInt);
    if ($user === NULL) {
      $this->io()->error("User $uidInt not found.");
      return;
    }

    // Validate role exists.
    $roleEntity = $this->entityTypeManager->getStorage('user_role')->load($role);
    if ($roleEntity === NULL) {
      $this->io()->error("Role '$role' not found.");
      return;
    }

    // Enforce max duration.
    $config     = $this->configFactory->get('zero_standing_privilege.settings');
    $maxMinutes = (int) ($config->get('max_elevation_minutes') ?? 240);

    if ($minutesInt > $maxMinutes) {
      $this->io()->warning("Duration $minutesInt min exceeds configured maximum $maxMinutes min. Clamping.");
      $minutesInt = $maxMinutes;
    }

    try {
      $request = $this->privilegeManager->createRequest($uidInt, $role, $reason, $minutesInt);

      // If the request is still pending (require_approval), force-approve it.
      if ($request->getStatus()->isPending()) {
        $this->approvalService->approve((int) $request->id(), 1, 'Drush direct grant.');
      }

      $expiresAt = $request->getExpiresAt();
      $expStr    = $expiresAt > 0 ? date('Y-m-d H:i:s T', $expiresAt) : 'unknown';

      $this->io()->success("Granted: UID $uidInt now has role '$role' until $expStr.");
    }
    catch (\Exception $e) {
      $this->io()->error("Grant failed: " . $e->getMessage());
    }
  }

  // ---------------------------------------------------------------------------
  // zsp:status
  // ---------------------------------------------------------------------------

  /**
   * Shows counts of pending requests and active elevations.
   */
  #[CLI\Command(name: 'zsp:status', aliases: ['zsp:st'])]
  #[CLI\Usage(name: 'drush zsp:status', description: 'Show ZSP dashboard summary.')]
  public function status(): void {
    $pending = $this->approvalService->countPendingRequests();
    $active  = $this->approvalService->countActiveElevations();

    $this->io()->table(
      ['Metric', 'Count'],
      [
        ['Pending approval requests', $pending],
        ['Active (approved) elevations', $active],
      ]
    );
  }

  // ---------------------------------------------------------------------------
  // zsp:deny
  // ---------------------------------------------------------------------------

  /**
   * Denies a specific pending elevation request.
   *
   * @param string $requestId
   *   The numeric elevation request entity ID.
   */
  #[CLI\Command(name: 'zsp:deny', aliases: ['zsp:d'])]
  #[CLI\Argument(name: 'requestId', description: 'Elevation request entity ID to deny.')]
  #[CLI\Option(name: 'reason', description: 'Reason for denial.')]
  #[CLI\Usage(name: 'drush zsp:deny 42 --reason="Not within change window"', description: 'Deny elevation request #42.')]
  public function deny(string $requestId, array $options = ['reason' => '']): void {
    $id     = (int) $requestId;
    $reason = $options['reason'] ?: 'Denied via Drush.';

    try {
      $this->approvalService->deny($id, 1, $reason);
      $this->io()->success("Elevation request #$id has been denied.");
    }
    catch (\Exception $e) {
      $this->io()->error("Deny failed: " . $e->getMessage());
    }
  }

  // ---------------------------------------------------------------------------
  // zsp:list
  // ---------------------------------------------------------------------------

  /**
   * Lists elevation requests filtered by status.
   */
  #[CLI\Command(name: 'zsp:list', aliases: ['zsp:ls'])]
  #[CLI\Option(name: 'status', description: 'Filter by status: pending, approved, denied, expired, revoked (default: pending).')]
  #[CLI\Option(name: 'limit', description: 'Maximum number of rows to show (default: 25).')]
  #[CLI\Usage(name: 'drush zsp:list', description: 'List pending elevation requests.')]
  #[CLI\Usage(name: 'drush zsp:list --status=approved', description: 'List active (approved) elevations.')]
  public function list(array $options = ['status' => 'pending', 'limit' => 25]): void {
    $statusStr = (string) $options['status'];
    $limit     = max(1, (int) $options['limit']);

    try {
      $statusEnum = ElevationStatus::from($statusStr);
    }
    catch (\ValueError $e) {
      $this->io()->error("Invalid status '$statusStr'. Valid values: " . implode(', ', array_column(ElevationStatus::cases(), 'value')));
      return;
    }

    $ids = $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('status', $statusEnum->value)
      ->sort('created', 'DESC')
      ->range(0, $limit)
      ->execute();

    if (empty($ids)) {
      $this->io()->note("No elevation requests with status '$statusStr'.");
      return;
    }

    $entities = $this->entityTypeManager->getStorage('elevation_request')->loadMultiple($ids);

    $rows = [];
    foreach ($entities as $request) {
      $rows[] = [
        $request->id(),
        $request->getRequesterId(),
        $request->getTargetRole(),
        $request->getDurationMinutes() . ' min',
        $request->getStatus()->label(),
        date('Y-m-d H:i', (int) $request->get('created')->value),
        $request->getExpiresAt() > 0 ? date('Y-m-d H:i', $request->getExpiresAt()) : '—',
      ];
    }

    $this->io()->table(
      ['ID', 'UID', 'Role', 'Duration', 'Status', 'Submitted', 'Expires'],
      $rows
    );
  }

}
