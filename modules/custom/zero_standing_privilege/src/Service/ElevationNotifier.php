<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Mail\MailManagerInterface;
use Drupal\Core\Url;
use Drupal\user\UserInterface;
use Drupal\zero_standing_privilege\Entity\ElevationRequestInterface;
use Drupal\zero_standing_privilege\Value\ElevationStatus;
use Psr\Log\LoggerInterface;

/**
 * Sends email notifications for elevation lifecycle events.
 *
 * Notification events:
 *  - request_submitted  → approvers
 *  - request_approved   → requester
 *  - request_denied     → requester
 *  - elevation_expired  → requester
 *  - elevation_revoked  → requester (optional)
 */
final class ElevationNotifier {

  public function __construct(
    private readonly MailManagerInterface $mailManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly LoggerInterface $logger,
    private readonly LanguageManagerInterface $languageManager,
  ) {}

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Notifies configured approvers that a new elevation request was submitted.
   */
  public function notifyApproversOnRequest(ElevationRequestInterface $request): void {
    $config = $this->configFactory->get('zero_standing_privilege.settings');
    if (!$config->get('notify_approvers_on_request')) {
      return;
    }

    $approvers = $this->resolveApprovers($config);
    if (empty($approvers)) {
      return;
    }

    $requester = $this->loadUser($request->getRequesterId());
    if ($requester === NULL) {
      return;
    }

    $params = [
      'request'   => $request,
      'requester' => $requester,
      'type'      => 'request_submitted',
    ];

    foreach ($approvers as $approver) {
      $this->send($approver, 'request_submitted', $params);
    }
  }

  /**
   * Notifies the requester that their elevation was approved.
   */
  public function notifyRequesterOnGrant(ElevationRequestInterface $request): void {
    $config = $this->configFactory->get('zero_standing_privilege.settings');
    if (!$config->get('notify_requester_on_grant')) {
      return;
    }

    $requester = $this->loadUser($request->getRequesterId());
    if ($requester === NULL) {
      return;
    }

    $params = [
      'request'   => $request,
      'requester' => $requester,
      'type'      => 'request_approved',
    ];

    $this->send($requester, 'request_approved', $params);
  }

  /**
   * Notifies the requester that their elevation was denied.
   */
  public function notifyRequesterOnDeny(ElevationRequestInterface $request): void {
    $config = $this->configFactory->get('zero_standing_privilege.settings');
    if (!$config->get('notify_requester_on_deny')) {
      return;
    }

    $requester = $this->loadUser($request->getRequesterId());
    if ($requester === NULL) {
      return;
    }

    $params = [
      'request'   => $request,
      'requester' => $requester,
      'type'      => 'request_denied',
    ];

    $this->send($requester, 'request_denied', $params);
  }

  /**
   * Notifies the requester that their elevation has expired.
   */
  public function notifyRequesterOnExpiry(ElevationRequestInterface $request): void {
    $config = $this->configFactory->get('zero_standing_privilege.settings');
    if (!$config->get('notify_requester_on_expiry')) {
      return;
    }

    $requester = $this->loadUser($request->getRequesterId());
    if ($requester === NULL) {
      return;
    }

    $params = [
      'request'   => $request,
      'requester' => $requester,
      'type'      => 'elevation_expired',
    ];

    $this->send($requester, 'elevation_expired', $params);
  }

  // ---------------------------------------------------------------------------
  // Mail key dispatch
  // ---------------------------------------------------------------------------

  /**
   * Sends a single email message.
   *
   * @param \Drupal\user\UserInterface $recipient
   *   The recipient user entity.
   * @param string $key
   *   The mail key (maps to hook_mail sub-key).
   * @param array<string, mixed> $params
   *   Parameters passed to hook_mail and the mail body builder.
   */
  private function send(UserInterface $recipient, string $key, array $params): void {
    $to = $recipient->getEmail();
    if (empty($to)) {
      return;
    }

    $langcode = $recipient->getPreferredLangcode();
    $result = $this->mailManager->mail(
      'zero_standing_privilege',
      $key,
      $to,
      $langcode,
      $params,
      NULL,
      TRUE
    );

    if (!$result['result']) {
      $this->logger->warning(
        'Failed to send ZSP email @key to @email for elevation request @id.',
        [
          '@key'   => $key,
          '@email' => $to,
          '@id'    => $request->id() ?? '(new)',
        ]
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Mail body construction (called by hook_mail via ZeroStandingPrivilegeHooks)
  // ---------------------------------------------------------------------------

  /**
   * Builds the subject and body for a given mail key and params.
   *
   * Called from ZeroStandingPrivilegeHooks::mail().
   *
   * @param string $key
   *   Mail key.
   * @param array<string, mixed> $params
   *   Parameters array containing 'request', 'requester', 'type'.
   * @param array<string, mixed> &$message
   *   The message array to populate subject and body on.
   */
  public function buildMailMessage(string $key, array $params, array &$message): void {
    /** @var \Drupal\zero_standing_privilege\Entity\ElevationRequestInterface $request */
    $request = $params['request'];
    /** @var \Drupal\user\UserInterface $requester */
    $requester = $params['requester'];

    $config = $this->configFactory->get('zero_standing_privilege.settings');
    $siteName = $config->get('site_name_in_email')
      ? ('[' . \Drupal::config('system.site')->get('name') . '] ')
      : '';

    $role = $request->getTargetRole();
    $duration = $request->getDurationMinutes();
    $requesterName = $requester->getDisplayName();

    switch ($key) {
      case 'request_submitted':
        $message['subject'] = $siteName . 'Privilege elevation request from ' . $requesterName;
        $body = [];
        $body[] = 'A new privilege elevation request has been submitted.';
        $body[] = '';
        $body[] = 'Requester: ' . $requesterName . ' (UID ' . $request->getRequesterId() . ')';
        $body[] = 'Target Role: ' . $role;
        $body[] = 'Duration: ' . $duration . ' minutes';
        $body[] = 'Reason: ' . $request->getReason();
        $body[] = '';
        $body[] = 'Review the queue at: ' . Url::fromRoute('zero_standing_privilege.approval_queue', [], ['absolute' => TRUE])->toString();
        $message['body'] = $body;
        break;

      case 'request_approved':
        $expiresAt = date('Y-m-d H:i:s T', $request->getExpiresAt());
        $message['subject'] = $siteName . 'Your elevation request has been approved';
        $body = [];
        $body[] = 'Your privilege elevation request has been approved.';
        $body[] = '';
        $body[] = 'Role Granted: ' . $role;
        $body[] = 'Duration: ' . $duration . ' minutes';
        $body[] = 'Expires At: ' . $expiresAt;
        $token = $request->getRevocationToken();
        if (!empty($token)) {
          $revokeUrl = Url::fromRoute('zero_standing_privilege.revoke', ['elevation_request' => $request->id()], ['absolute' => TRUE, 'query' => ['token' => $token]])->toString();
          $body[] = '';
          $body[] = 'To revoke early: ' . $revokeUrl;
        }
        $message['body'] = $body;
        break;

      case 'request_denied':
        $message['subject'] = $siteName . 'Your elevation request has been denied';
        $body = [];
        $body[] = 'Your privilege elevation request has been denied.';
        $body[] = '';
        $body[] = 'Requested Role: ' . $role;
        $comment = $request->getApproverComment();
        if (!empty($comment)) {
          $body[] = 'Reason: ' . $comment;
        }
        $message['body'] = $body;
        break;

      case 'elevation_expired':
        $message['subject'] = $siteName . 'Your temporary elevation has expired';
        $body = [];
        $body[] = 'Your temporary privilege elevation has expired and the role has been revoked.';
        $body[] = '';
        $body[] = 'Role: ' . $role;
        $body[] = 'Duration was: ' . $duration . ' minutes';
        $message['body'] = $body;
        break;
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Loads a user entity by UID, returning NULL if not found or not active.
   */
  private function loadUser(int $uid): ?UserInterface {
    if ($uid === 0) {
      return NULL;
    }
    try {
      $user = $this->entityTypeManager->getStorage('user')->load($uid);
      return ($user instanceof UserInterface && $user->isActive()) ? $user : NULL;
    }
    catch (\Exception $e) {
      $this->logger->warning('ZSP ElevationNotifier: could not load user @uid: @msg', [
        '@uid' => $uid,
        '@msg' => $e->getMessage(),
      ]);
      return NULL;
    }
  }

  /**
   * Resolves the list of approver user entities from config.
   *
   * Collects UIDs from approver_uids plus all members of approver_roles.
   *
   * @return \Drupal\user\UserInterface[]
   */
  private function resolveApprovers($config): array {
    $uids = array_map('intval', (array) ($config->get('approver_uids') ?? []));

    $approverRoles = (array) ($config->get('approver_roles') ?? []);
    if (!empty($approverRoles)) {
      $roleUids = $this->entityTypeManager->getStorage('user')
        ->getQuery()
        ->accessCheck(FALSE)
        ->condition('roles', $approverRoles, 'IN')
        ->condition('status', 1)
        ->execute();
      $uids = array_unique(array_merge($uids, array_map('intval', $roleUids)));
    }

    if (empty($uids)) {
      return [];
    }

    $users = $this->entityTypeManager->getStorage('user')->loadMultiple($uids);
    return array_filter($users, static fn($u) => $u instanceof UserInterface && $u->isActive());
  }

}
