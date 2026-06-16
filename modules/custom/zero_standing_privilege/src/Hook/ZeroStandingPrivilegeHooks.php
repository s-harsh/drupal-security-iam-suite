<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Link;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\zero_standing_privilege\Service\ElevationNotifier;
use Drupal\zero_standing_privilege\Service\PrivilegeManager;
use Psr\Log\LoggerInterface;

/**
 * OOP hook implementations for Zero Standing Privilege.
 *
 * Registered in zero_standing_privilege.services.yml with the drupal.hook tag.
 */
final class ZeroStandingPrivilegeHooks {

  use StringTranslationTrait;

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly PrivilegeManager $privilegeManager,
    private readonly AccountInterface $currentUser,
  ) {}

  // ---------------------------------------------------------------------------
  // hook_help
  // ---------------------------------------------------------------------------

  /**
   * Implements hook_help().
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): string|array {
    if ($route_name !== 'help.page.zero_standing_privilege') {
      return [];
    }

    $settingsUrl  = Url::fromRoute('zero_standing_privilege.settings');
    $queueUrl     = Url::fromRoute('zero_standing_privilege.approval_queue');
    $activeUrl    = Url::fromRoute('zero_standing_privilege.active_elevations');
    $auditUrl     = Url::fromRoute('zero_standing_privilege.audit_log');
    $requestUrl   = Url::fromRoute('zero_standing_privilege.request');

    $settingsLink = Link::fromTextAndUrl($this->t('ZSP Settings'), $settingsUrl)->toString();
    $queueLink    = Link::fromTextAndUrl($this->t('Approval Queue'), $queueUrl)->toString();
    $activeLink   = Link::fromTextAndUrl($this->t('Active Elevations'), $activeUrl)->toString();
    $auditLink    = Link::fromTextAndUrl($this->t('Audit Log'), $auditUrl)->toString();
    $requestLink  = Link::fromTextAndUrl($this->t('Request Elevation'), $requestUrl)->toString();

    $output  = '<h2>' . $this->t('About') . '</h2>';
    $output .= '<p>' . $this->t('Zero Standing Privilege (ZSP) is a Just-In-Time Privileged Access Management module for Drupal. It eliminates standing administrator accounts by allowing users to request temporary elevation to a higher role, subject to an optional approval workflow. Grants expire automatically, are revocable at any time, and every action is recorded in a tamper-evident audit log.') . '</p>';
    $output .= '<h2>' . $this->t('How it works') . '</h2>';
    $output .= '<ol>';
    $output .= '<li>' . $this->t('A user with the <em>request privilege elevation</em> permission submits a request via @link, specifying the target role, duration, and a business justification.', ['@link' => $requestLink]) . '</li>';
    $output .= '<li>' . $this->t('If auto-approve is configured for the requester\'s roles, the grant is immediate. Otherwise, designated approvers are emailed and the request appears in @link.', ['@link' => $queueLink]) . '</li>';
    $output .= '<li>' . $this->t('When approved, the target role is added to the user account and a countdown begins. On expiry, the role is removed automatically by cron (<code>drush cron</code>) or immediately via the revocation link in the approval email.') . '</li>';
    $output .= '</ol>';
    $output .= '<h2>' . $this->t('Administration') . '</h2>';
    $output .= '<ul>';
    $output .= '<li>' . $this->t('@link — Configure approval workflow, allowed roles, maximum elevation duration, and notification settings.', ['@link' => $settingsLink]) . '</li>';
    $output .= '<li>' . $this->t('@link — Review and action pending elevation requests.', ['@link' => $queueLink]) . '</li>';
    $output .= '<li>' . $this->t('@link — Monitor currently live role grants and revoke any on demand.', ['@link' => $activeLink]) . '</li>';
    $output .= '<li>' . $this->t('@link — Full audit trail of every request, approval, denial, and revocation.', ['@link' => $auditLink]) . '</li>';
    $output .= '</ul>';
    $output .= '<h2>' . $this->t('Drush') . '</h2>';
    $output .= '<ul>';
    $output .= '<li><code>drush zsp:revoke-expired</code> — ' . $this->t('Immediately revoke all elevations past their expiry time.') . '</li>';
    $output .= '<li><code>drush zsp:grant {uid} {role} {minutes}</code> — ' . $this->t('Directly grant an elevation (bypasses approval).') . '</li>';
    $output .= '<li><code>drush zsp:status</code> — ' . $this->t('Show counts of pending requests and active elevations.') . '</li>';
    $output .= '</ul>';

    return ['#markup' => $output];
  }

  // ---------------------------------------------------------------------------
  // hook_cron
  // ---------------------------------------------------------------------------

  /**
   * Implements hook_cron().
   *
   * Revokes all elevation requests whose expiry time has passed.
   */
  #[Hook('cron')]
  public function cron(): void {
    try {
      $count = $this->privilegeManager->revokeExpiredElevations();
      if ($count > 0) {
        $this->logger->info(
          'ZSP cron: @count expired elevation(s) revoked.',
          ['@count' => $count]
        );
      }
    }
    catch (\Exception $e) {
      $this->logger->error(
        'ZSP cron error during expired elevation revocation: @msg',
        ['@msg' => $e->getMessage()]
      );
    }
  }

  // ---------------------------------------------------------------------------
  // hook_mail
  // ---------------------------------------------------------------------------

  /**
   * Implements hook_mail().
   *
   * Delegates body/subject construction to ElevationNotifier::buildMailMessage().
   */
  #[Hook('mail')]
  public function mail(string $key, array &$message, array $params): void {
    // Resolve ElevationNotifier from the container lazily to avoid a circular
    // dependency: hooks → notifier → hooks is not possible, but this keeps
    // the constructor lean for tests.
    /** @var \Drupal\zero_standing_privilege\Service\ElevationNotifier $notifier */
    $notifier = \Drupal::service('zero_standing_privilege.elevation_notifier');
    $notifier->buildMailMessage($key, $params, $message);
  }

  // ---------------------------------------------------------------------------
  // hook_user_cancel
  // ---------------------------------------------------------------------------

  /**
   * Implements hook_user_cancel().
   *
   * When a user account is cancelled, revoke any active elevations.
   */
  #[Hook('user_cancel')]
  public function userCancel(array $edit, $account, string $method): void {
    if (!($account instanceof \Drupal\Core\Session\AccountInterface)) {
      return;
    }
    $uid = (int) $account->id();
    $activeRequests = $this->privilegeManager->getRequestsForUser($uid, 100);
    foreach ($activeRequests as $request) {
      if ($request->getStatus()->isActive()) {
        try {
          $this->privilegeManager->revokeElevation($request, 'account_cancel');
        }
        catch (\Exception $e) {
          $this->logger->warning(
            'ZSP: failed to revoke elevation @id on account cancel: @msg',
            ['@id' => $request->id(), '@msg' => $e->getMessage()]
          );
        }
      }
    }
  }

}
