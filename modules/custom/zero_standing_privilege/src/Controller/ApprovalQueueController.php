<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\zero_standing_privilege\Entity\ElevationRequestInterface;
use Drupal\zero_standing_privilege\Service\ApprovalService;
use Drupal\zero_standing_privilege\Service\PrivilegeManager;
use Drupal\zero_standing_privilege\Value\ElevationStatus;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Admin controller for the approval queue, active elevations, and audit log.
 *
 * Routes:
 *  - zero_standing_privilege.approval_queue   → queue()
 *  - zero_standing_privilege.approve          → approve()  [POST]
 *  - zero_standing_privilege.deny             → deny()     [POST]
 *  - zero_standing_privilege.active_elevations → activeElevations()
 *  - zero_standing_privilege.audit_log         → auditLog()
 */
final class ApprovalQueueController extends ControllerBase {

  public function __construct(
    private readonly PrivilegeManager $privilegeManager,
    private readonly ApprovalService $approvalService,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('zero_standing_privilege.privilege_manager'),
      $container->get('zero_standing_privilege.approval_service'),
    );
  }

  // ---------------------------------------------------------------------------
  // Approval queue page
  // ---------------------------------------------------------------------------

  /**
   * Renders the pending elevation request queue.
   *
   * @return array<string, mixed>
   */
  public function queue(): array {
    $pending = $this->privilegeManager->getPendingRequests();
    $pendingCount  = $this->approvalService->countPendingRequests();
    $activeCount   = $this->approvalService->countActiveElevations();

    $build = [];

    // Summary badges.
    $build['summary'] = [
      '#markup' => '<p>'
        . $this->t('Pending requests: <strong>@pending</strong> | Active elevations: <strong>@active</strong>', [
          '@pending' => $pendingCount,
          '@active'  => $activeCount,
        ])
        . '</p>',
    ];

    if (empty($pending)) {
      $build['empty'] = ['#markup' => '<p>' . $this->t('No pending elevation requests.') . '</p>'];
      return $build;
    }

    $header = [
      $this->t('ID'),
      $this->t('Requester (UID)'),
      $this->t('Target Role'),
      $this->t('Duration'),
      $this->t('Reason'),
      $this->t('Submitted'),
      $this->t('Actions'),
    ];

    $rows = [];
    foreach ($pending as $request) {
      $approveUrl = Url::fromRoute('zero_standing_privilege.approve', ['elevation_request' => $request->id()]);
      $denyUrl    = Url::fromRoute('zero_standing_privilege.deny',    ['elevation_request' => $request->id()]);

      $actions = [
        '#type'  => 'inline_template',
        '#template' => '
          <form method="post" action="{{ approve_url }}" style="display:inline">
            <input type="hidden" name="token" value="{{ approve_token }}">
            <button type="submit" class="button button--primary button--small">{{ approve_label }}</button>
          </form>
          &nbsp;
          <form method="post" action="{{ deny_url }}" style="display:inline">
            <input type="hidden" name="token" value="{{ deny_token }}">
            <button type="submit" class="button button--danger button--small">{{ deny_label }}</button>
          </form>',
        '#context' => [
          'approve_url'   => $approveUrl->toString(),
          'approve_token' => \Drupal::csrfToken()->get('zsp_approve_' . $request->id()),
          'approve_label' => $this->t('Approve'),
          'deny_url'      => $denyUrl->toString(),
          'deny_token'    => \Drupal::csrfToken()->get('zsp_deny_' . $request->id()),
          'deny_label'    => $this->t('Deny'),
        ],
      ];

      $rows[] = [
        $request->id(),
        $request->getRequesterId(),
        $request->getTargetRole(),
        $request->getDurationMinutes() . ' min',
        $this->truncate($request->getReason(), 80),
        $this->formatTimestamp((int) $request->get('created')->value),
        ['data' => $actions],
      ];
    }

    $build['table'] = [
      '#type'    => 'table',
      '#header'  => $header,
      '#rows'    => $rows,
      '#caption' => $this->t('Pending Elevation Requests'),
    ];

    return $build;
  }

  // ---------------------------------------------------------------------------
  // Approve action (POST)
  // ---------------------------------------------------------------------------

  /**
   * Approves a pending elevation request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $httpRequest
   *   The HTTP request (contains CSRF token and optional comment).
   * @param int $elevation_request
   *   The elevation request entity ID.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function approve(Request $httpRequest, int $elevation_request): RedirectResponse {
    $csrfToken = $httpRequest->request->get('token', '');
    if (!\Drupal::csrfToken()->validate($csrfToken, 'zsp_approve_' . $elevation_request)) {
      $this->messenger()->addError($this->t('Invalid security token.'));
      return new RedirectResponse(Url::fromRoute('zero_standing_privilege.approval_queue')->toString());
    }

    $approverId = (int) $this->currentUser()->id();
    $comment    = trim((string) $httpRequest->request->get('comment', ''));

    try {
      $request = $this->approvalService->approve($elevation_request, $approverId, $comment);
      $this->messenger()->addStatus(
        $this->t('Elevation request #@id approved. @role granted to UID @uid until @exp.', [
          '@id'  => $elevation_request,
          '@role' => $request->getTargetRole(),
          '@uid'  => $request->getRequesterId(),
          '@exp'  => $this->formatTimestamp($request->getExpiresAt()),
        ])
      );
    }
    catch (\Exception $e) {
      $this->messenger()->addError($this->t('Could not approve request: @msg', ['@msg' => $e->getMessage()]));
    }

    return new RedirectResponse(Url::fromRoute('zero_standing_privilege.approval_queue')->toString());
  }

  // ---------------------------------------------------------------------------
  // Deny action (POST)
  // ---------------------------------------------------------------------------

  /**
   * Denies a pending elevation request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $httpRequest
   *   The HTTP request.
   * @param int $elevation_request
   *   The elevation request entity ID.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function deny(Request $httpRequest, int $elevation_request): RedirectResponse {
    $csrfToken = $httpRequest->request->get('token', '');
    if (!\Drupal::csrfToken()->validate($csrfToken, 'zsp_deny_' . $elevation_request)) {
      $this->messenger()->addError($this->t('Invalid security token.'));
      return new RedirectResponse(Url::fromRoute('zero_standing_privilege.approval_queue')->toString());
    }

    $approverId = (int) $this->currentUser()->id();
    $comment    = trim((string) $httpRequest->request->get('comment', ''));

    try {
      $this->approvalService->deny($elevation_request, $approverId, $comment);
      $this->messenger()->addStatus(
        $this->t('Elevation request #@id has been denied.', ['@id' => $elevation_request])
      );
    }
    catch (\Exception $e) {
      $this->messenger()->addError($this->t('Could not deny request: @msg', ['@msg' => $e->getMessage()]));
    }

    return new RedirectResponse(Url::fromRoute('zero_standing_privilege.approval_queue')->toString());
  }

  // ---------------------------------------------------------------------------
  // Active elevations page
  // ---------------------------------------------------------------------------

  /**
   * Renders the active elevations dashboard.
   *
   * @return array<string, mixed>
   */
  public function activeElevations(): array {
    $active = $this->privilegeManager->getActiveElevations();

    $header = [
      $this->t('ID'),
      $this->t('Requester (UID)'),
      $this->t('Role'),
      $this->t('Granted'),
      $this->t('Expires'),
      $this->t('Remaining'),
      $this->t('Actions'),
    ];

    $rows = [];
    $now  = \time();

    foreach ($active as $request) {
      $expiresAt  = $request->getExpiresAt();
      $remaining  = $expiresAt - $now;
      $remainStr  = $remaining > 0
        ? gmdate('H:i:s', $remaining)
        : $this->t('Expiring...');

      $revokeUrl = Url::fromRoute('zero_standing_privilege.revoke', ['elevation_request' => $request->id()]);

      $revokeAction = [
        '#type'  => 'inline_template',
        '#template' => '<form method="post" action="{{ url }}" style="display:inline"><input type="hidden" name="token" value="{{ token }}"><button type="submit" class="button button--danger button--small">{{ label }}</button></form>',
        '#context' => [
          'url'   => $revokeUrl->toString(),
          'token' => \Drupal::csrfToken()->get('zsp_revoke_' . $request->id()),
          'label' => $this->t('Revoke'),
        ],
      ];

      $rows[] = [
        $request->id(),
        $request->getRequesterId(),
        $request->getTargetRole(),
        $this->formatTimestamp($request->getGrantedAt()),
        $this->formatTimestamp($expiresAt),
        $remainStr,
        ['data' => $revokeAction],
      ];
    }

    $build = [];

    $build['table'] = [
      '#type'    => 'table',
      '#header'  => $header,
      '#rows'    => $rows,
      '#empty'   => $this->t('No active elevations at this time.'),
      '#caption' => $this->t('Currently Active Elevations'),
    ];

    // Auto-refresh hint.
    $build['refresh_note'] = [
      '#markup' => '<p><em>' . $this->t('Elevations are automatically revoked by cron. Refresh this page to see current state.') . '</em></p>',
    ];

    return $build;
  }

  // ---------------------------------------------------------------------------
  // Audit log page
  // ---------------------------------------------------------------------------

  /**
   * Renders the full audit log.
   *
   * @return array<string, mixed>
   */
  public function auditLog(): array {
    $page    = \Drupal::request()->query->getInt('page', 0);
    $perPage = 50;
    $offset  = $page * $perPage;

    $records = $this->privilegeManager->getAuditLog($perPage, $offset);

    $header = [
      $this->t('ID'),
      $this->t('Requester (UID)'),
      $this->t('Target Role'),
      $this->t('Status'),
      $this->t('Duration'),
      $this->t('Reason'),
      $this->t('Submitted'),
      $this->t('Approved/Denied By'),
      $this->t('Expires/Expired At'),
    ];

    $rows = [];
    foreach ($records as $request) {
      $approverId = $request->getApproverId();
      $approverStr = $approverId > 0 ? (string) $approverId : $this->t('—');

      $rows[] = [
        $request->id(),
        $request->getRequesterId(),
        $request->getTargetRole(),
        $request->getStatus()->label(),
        $request->getDurationMinutes() . ' min',
        $this->truncate($request->getReason(), 60),
        $this->formatTimestamp((int) $request->get('created')->value),
        $approverStr,
        $request->getExpiresAt() > 0 ? $this->formatTimestamp($request->getExpiresAt()) : $this->t('—'),
      ];
    }

    $build = [];

    $build['table'] = [
      '#type'    => 'table',
      '#header'  => $header,
      '#rows'    => $rows,
      '#empty'   => $this->t('No audit log entries found.'),
      '#caption' => $this->t('Privilege Elevation Audit Log'),
    ];

    // Simple pager navigation.
    if (count($records) === $perPage) {
      $build['next'] = [
        '#type'  => 'link',
        '#title' => $this->t('Next page →'),
        '#url'   => Url::fromRoute('zero_standing_privilege.audit_log', [], ['query' => ['page' => $page + 1]]),
        '#prefix' => '<p>',
        '#suffix' => '</p>',
      ];
    }
    if ($page > 0) {
      $build['prev'] = [
        '#type'  => 'link',
        '#title' => $this->t('← Previous page'),
        '#url'   => Url::fromRoute('zero_standing_privilege.audit_log', [], ['query' => ['page' => $page - 1]]),
        '#prefix' => '<p>',
        '#suffix' => '</p>',
      ];
    }

    return $build;
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Formats a Unix timestamp for display.
   */
  private function formatTimestamp(int $timestamp): string {
    if ($timestamp === 0) {
      return '';
    }
    return \Drupal::service('date.formatter')->format($timestamp, 'short');
  }

  /**
   * Truncates a string to max length with ellipsis.
   */
  private function truncate(string $text, int $maxLength): string {
    if (mb_strlen($text) <= $maxLength) {
      return $text;
    }
    return mb_substr($text, 0, $maxLength - 1) . '…';
  }

}
