<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Link;
use Drupal\Core\Url;
use Drupal\passkey_forge\Service\PasskeyStorage;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Provides the admin interface for managing passkey credentials.
 *
 * Exposes two endpoints:
 *   - GET  /admin/config/security/passkey-forge/users/{user}/keys
 *       Lists all credentials (including revoked) for a given user.
 *   - POST /admin/config/security/passkey-forge/keys/{credential_id}/revoke
 *       Revokes an individual credential by its database primary key.
 *
 * Both routes require the 'administer passkey forge' permission.
 */
final class PasskeyAdminController extends ControllerBase {

  /**
   * Constructs a PasskeyAdminController.
   *
   * @param \Drupal\passkey_forge\Service\PasskeyStorage $storage
   *   The passkey credential storage.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Psr\Log\LoggerInterface $logger
   *   The passkey_forge logger channel.
   */
  public function __construct(
    private readonly PasskeyStorage $storage,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('passkey_forge.storage'),
      $container->get('entity_type.manager'),
      $container->get('logger.channel.passkey_forge'),
    );
  }

  /**
   * Renders the credential list table for a given user.
   *
   * Shows all credentials including revoked ones so administrators have a full
   * audit trail. Active credentials have a Revoke action button.
   *
   * @param int $user
   *   Drupal user ID from the route parameter.
   *
   * @return array<string, mixed>
   *   A Drupal render array containing a table of credentials.
   */
  public function userKeys(int $user): array {
    $account = $this->entityTypeManager->getStorage('user')->load($user);

    if ($account === null) {
      return [
        '#markup' => $this->t('User not found.'),
      ];
    }

    $credentials = $this->storage->loadAllByUid($user);

    $header = [
      $this->t('ID'),
      $this->t('Label'),
      $this->t('AAGUID'),
      $this->t('Attestation'),
      $this->t('Transports'),
      $this->t('Sign Count'),
      $this->t('Created'),
      $this->t('Last Used'),
      $this->t('Status'),
      $this->t('Actions'),
    ];

    $rows = [];
    foreach ($credentials as $credential) {
      $statusLabel = $credential->revoked
        ? '<span class="passkey-revoked">' . $this->t('Revoked') . '</span>'
        : '<span class="passkey-active">' . $this->t('Active') . '</span>';

      $actions = [];
      if (!$credential->revoked) {
        $revokeUrl = Url::fromRoute('passkey_forge.admin.revoke', [
          'credential_id' => $credential->id,
        ]);
        $actions[] = Link::fromTextAndUrl($this->t('Revoke'), $revokeUrl)->toString();
      }

      $rows[] = [
        'data' => [
          $credential->id,
          $credential->label ?? $this->t('(unlabelled)'),
          $credential->aaguid ?? $this->t('N/A'),
          $credential->attestationType->value,
          implode(', ', $credential->transports) ?: $this->t('unknown'),
          $credential->signCount,
          $credential->created > 0 ? date('Y-m-d H:i', $credential->created) : $this->t('unknown'),
          $credential->lastUsed ? date('Y-m-d H:i', $credential->lastUsed) : $this->t('Never'),
          ['data' => ['#markup' => $statusLabel]],
          ['data' => ['#markup' => implode(' | ', $actions)]],
        ],
      ];
    }

    $build = [];

    $build['heading'] = [
      '#markup' => '<h2>' . $this->t('Passkeys for @user', ['@user' => $account->getAccountName()]) . '</h2>',
    ];

    $build['table'] = [
      '#type' => 'table',
      '#header' => $header,
      '#rows' => $rows,
      '#empty' => $this->t('No passkeys registered for this user.'),
      '#attributes' => ['class' => ['passkey-forge-admin-table']],
    ];

    $build['back'] = [
      '#type' => 'link',
      '#title' => $this->t('Back to settings'),
      '#url' => Url::fromRoute('passkey_forge.settings'),
    ];

    return $build;
  }

  /**
   * Revokes an individual passkey credential.
   *
   * Accepts POST requests. Returns JSON to allow both AJAX and form-based
   * revocation flows. On success the credential's revoked flag is set to 1.
   *
   * @param string $credential_id
   *   The database surrogate key of the credential (from the route parameter).
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current HTTP request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   200 JSON response on success, 404 if not found.
   */
  public function revoke(string $credential_id, Request $request): JsonResponse {
    $credentialDbId = (int) $credential_id;

    if ($credentialDbId <= 0) {
      return new JsonResponse(['error' => 'Invalid credential ID.'], 400);
    }

    $adminUid = (int) $this->currentUser()->id();

    $revoked = $this->storage->revoke($credentialDbId, $adminUid);

    if (!$revoked) {
      return new JsonResponse(['error' => 'Credential not found or already revoked.'], 404);
    }

    return new JsonResponse([
      'success' => true,
      'message' => (string) $this->t('Passkey credential #@id has been revoked.', ['@id' => $credentialDbId]),
    ]);
  }

}
