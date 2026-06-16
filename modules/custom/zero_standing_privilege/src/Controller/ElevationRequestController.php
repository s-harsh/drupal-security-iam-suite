<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Url;
use Drupal\zero_standing_privilege\Entity\ElevationRequestInterface;
use Drupal\zero_standing_privilege\Service\PrivilegeManager;
use Drupal\zero_standing_privilege\Value\ElevationStatus;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller for user-facing elevation request pages.
 *
 * Routes:
 *  - zero_standing_privilege.my_requests  → myRequests()
 *  - zero_standing_privilege.view         → view()
 *  - zero_standing_privilege.revoke       → revoke()  [POST]
 */
final class ElevationRequestController extends ControllerBase {

  public function __construct(
    private readonly PrivilegeManager $privilegeManager,
    private readonly AccountInterface $currentUser,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('zero_standing_privilege.privilege_manager'),
      $container->get('current_user'),
    );
  }

  // ---------------------------------------------------------------------------
  // Pages
  // ---------------------------------------------------------------------------

  /**
   * Renders the current user's elevation request history.
   *
   * @return array<string, mixed>
   *   Render array.
   */
  public function myRequests(): array {
    $uid = (int) $this->currentUser->id();
    $requests = $this->privilegeManager->getRequestsForUser($uid, 50);

    $rows = [];
    foreach ($requests as $request) {
      $rows[] = $this->buildRequestRow($request, FALSE);
    }

    $build = [];

    $build['new_request'] = [
      '#type'  => 'link',
      '#title' => $this->t('Request new elevation'),
      '#url'   => Url::fromRoute('zero_standing_privilege.request'),
      '#attributes' => ['class' => ['button', 'button--primary']],
      '#prefix' => '<p>',
      '#suffix' => '</p>',
    ];

    $build['table'] = [
      '#type'    => 'table',
      '#header'  => [
        $this->t('ID'),
        $this->t('Role'),
        $this->t('Status'),
        $this->t('Duration'),
        $this->t('Requested'),
        $this->t('Expires'),
        $this->t('Actions'),
      ],
      '#rows'    => $rows,
      '#empty'   => $this->t('You have no elevation requests.'),
      '#caption' => $this->t('Your privilege elevation requests'),
    ];

    return $build;
  }

  /**
   * Renders a single elevation request detail page.
   *
   * @param int $elevation_request
   *   The elevation request entity ID (from the URL).
   *
   * @return array<string, mixed>|RedirectResponse
   */
  public function view(int $elevation_request): array|RedirectResponse {
    $request = $this->privilegeManager->loadRequest($elevation_request);

    if ($request === NULL) {
      $this->messenger()->addError($this->t('Elevation request not found.'));
      return new RedirectResponse(Url::fromRoute('zero_standing_privilege.my_requests')->toString());
    }

    $uid = (int) $this->currentUser->id();
    $canAdminister = $this->currentUser->hasPermission('administer zero standing privilege');

    if ($request->getRequesterId() !== $uid && !$canAdminister) {
      $this->messenger()->addError($this->t('Access denied.'));
      return new RedirectResponse(Url::fromRoute('zero_standing_privilege.my_requests')->toString());
    }

    $status = $request->getStatus();

    $rows = [
      [$this->t('Request ID'),    $request->id()],
      [$this->t('Target Role'),   $request->getTargetRole()],
      [$this->t('Status'),        $status->label()],
      [$this->t('Duration'),      $this->t('@min minutes', ['@min' => $request->getDurationMinutes()])],
      [$this->t('Reason'),        $request->getReason()],
      [$this->t('Submitted'),     $this->formatTimestamp((int) $request->get('created')->value)],
    ];

    if ($request->getGrantedAt() > 0) {
      $rows[] = [$this->t('Granted at'),  $this->formatTimestamp($request->getGrantedAt())];
      $rows[] = [$this->t('Expires at'),  $this->formatTimestamp($request->getExpiresAt())];
    }

    if ($request->getApproverId() > 0) {
      $approver = $this->entityTypeManager()->getStorage('user')->load($request->getApproverId());
      $approverName = $approver ? $approver->getDisplayName() : $this->t('Unknown');
      $rows[] = [$this->t('Reviewed by'), $approverName];
    }

    if (!empty($request->getApproverComment())) {
      $rows[] = [$this->t('Approver comment'), $request->getApproverComment()];
    }

    $build = [];

    $build['details'] = [
      '#type'   => 'table',
      '#header' => [$this->t('Field'), $this->t('Value')],
      '#rows'   => $rows,
      '#caption' => $this->t('Elevation Request #@id', ['@id' => $request->id()]),
    ];

    // Revoke button for active elevations owned by the current user.
    if ($status->isActive() && ($request->getRequesterId() === $uid || $canAdminister)) {
      $build['revoke_form'] = [
        '#type'   => 'html_tag',
        '#tag'    => 'form',
        '#attributes' => [
          'method' => 'post',
          'action' => Url::fromRoute('zero_standing_privilege.revoke', ['elevation_request' => $request->id()])->toString(),
        ],
        'csrf' => [
          '#type'  => 'html_tag',
          '#tag'   => 'input',
          '#attributes' => [
            'type'  => 'hidden',
            'name'  => 'token',
            'value' => \Drupal::csrfToken()->get('zsp_revoke_' . $request->id()),
          ],
        ],
        'submit' => [
          '#type'  => 'html_tag',
          '#tag'   => 'button',
          '#value' => $this->t('Revoke this elevation now'),
          '#attributes' => ['type' => 'submit', 'class' => ['button', 'button--danger']],
        ],
      ];
    }

    $build['back'] = [
      '#type'  => 'link',
      '#title' => $this->t('Back to my requests'),
      '#url'   => Url::fromRoute('zero_standing_privilege.my_requests'),
      '#prefix' => '<p>',
      '#suffix' => '</p>',
    ];

    return $build;
  }

  /**
   * Handles an immediate manual revocation POST.
   *
   * Accepts either a CSRF token (manual form) or a revocation token (email link).
   *
   * @param \Symfony\Component\HttpFoundation\Request $httpRequest
   *   The HTTP request.
   * @param int $elevation_request
   *   The elevation request entity ID.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function revoke(Request $httpRequest, int $elevation_request): RedirectResponse {
    $request = $this->privilegeManager->loadRequest($elevation_request);
    $uid     = (int) $this->currentUser->id();

    if ($request === NULL) {
      $this->messenger()->addError($this->t('Elevation request not found.'));
      return new RedirectResponse(Url::fromRoute('zero_standing_privilege.my_requests')->toString());
    }

    // Validate either CSRF token (logged-in user) or revocation token (from email).
    $emailToken = $httpRequest->query->get('token', '');
    if (!empty($emailToken)) {
      // Token-based revocation from email link.
      if ($request->getRevocationToken() !== $emailToken) {
        $this->messenger()->addError($this->t('Invalid or expired revocation token.'));
        return new RedirectResponse(Url::fromRoute('zero_standing_privilege.my_requests')->toString());
      }
    }
    else {
      // CSRF-based revocation from on-page form.
      $csrfToken = $httpRequest->request->get('token', '');
      if (!\Drupal::csrfToken()->validate($csrfToken, 'zsp_revoke_' . $elevation_request)) {
        $this->messenger()->addError($this->t('Invalid security token. Please try again.'));
        return new RedirectResponse(Url::fromRoute('zero_standing_privilege.my_requests')->toString());
      }

      // Verify ownership or admin.
      $canAdminister = $this->currentUser->hasPermission('administer zero standing privilege');
      if ($request->getRequesterId() !== $uid && !$canAdminister) {
        $this->messenger()->addError($this->t('Access denied.'));
        return new RedirectResponse(Url::fromRoute('zero_standing_privilege.my_requests')->toString());
      }
    }

    if (!$request->getStatus()->isActive()) {
      $this->messenger()->addWarning($this->t('This elevation is not currently active.'));
      return new RedirectResponse(Url::fromRoute('zero_standing_privilege.my_requests')->toString());
    }

    $this->privilegeManager->revokeElevation($request, 'manual');

    $this->messenger()->addStatus(
      $this->t('Elevation #@id has been revoked.', ['@id' => $elevation_request])
    );

    return new RedirectResponse(Url::fromRoute('zero_standing_privilege.my_requests')->toString());
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Builds a table row array for an elevation request.
   *
   * @param bool $showRequester
   *   Whether to include the requester column (for admin tables).
   *
   * @return array<int, mixed>
   */
  private function buildRequestRow(ElevationRequestInterface $request, bool $showRequester): array {
    $status = $request->getStatus();
    $expiresAt = $request->getExpiresAt();

    $actions = [
      '#type'  => 'link',
      '#title' => $this->t('View'),
      '#url'   => Url::fromRoute('zero_standing_privilege.view', ['elevation_request' => $request->id()]),
    ];

    $row = [
      $request->id(),
      $request->getTargetRole(),
      $status->label(),
      $request->getDurationMinutes() . ' min',
      $this->formatTimestamp((int) $request->get('created')->value),
      $expiresAt > 0 ? $this->formatTimestamp($expiresAt) : $this->t('N/A'),
      ['data' => $actions],
    ];

    if ($showRequester) {
      array_unshift($row, $request->getRequesterId());
    }

    return $row;
  }

  /**
   * Formats a Unix timestamp for display.
   */
  private function formatTimestamp(int $timestamp): string {
    if ($timestamp === 0) {
      return '';
    }
    return \Drupal::service('date.formatter')->format($timestamp, 'short');
  }

}
