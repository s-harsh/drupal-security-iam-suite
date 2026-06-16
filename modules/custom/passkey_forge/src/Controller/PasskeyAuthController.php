<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Session\SessionManagerInterface;
use Drupal\passkey_forge\Service\PasskeyStorage;
use Drupal\passkey_forge\Service\WebAuthnService;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Handles FIDO2/WebAuthn passkey authentication ceremonies.
 *
 * Exposes two JSON endpoints:
 *   - GET  /passkey-forge/auth/challenge  — issue authentication options
 *   - POST /passkey-forge/auth/complete   — verify assertion and log in
 *
 * These routes are publicly accessible (_access: TRUE) so that unauthenticated
 * users can initiate a passkey login. Username may optionally be passed as a
 * query parameter on the challenge endpoint to restrict the allowCredentials
 * list; without it an empty list is returned for discoverable-key (resident
 * key) flows.
 */
final class PasskeyAuthController extends ControllerBase {

  /**
   * Session key used to store the pending passkey-login uid before completion.
   */
  private const PENDING_UID_KEY = 'passkey_forge_pending_uid';

  /**
   * Constructs a PasskeyAuthController.
   *
   * @param \Drupal\passkey_forge\Service\WebAuthnService $webAuthn
   *   The WebAuthn ceremony service.
   * @param \Drupal\passkey_forge\Service\PasskeyStorage $storage
   *   The passkey credential storage.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Psr\Log\LoggerInterface $logger
   *   The passkey_forge logger channel.
   */
  public function __construct(
    private readonly WebAuthnService $webAuthn,
    private readonly PasskeyStorage $storage,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('passkey_forge.webauthn'),
      $container->get('passkey_forge.storage'),
      $container->get('entity_type.manager'),
      $container->get('logger.channel.passkey_forge'),
    );
  }

  /**
   * Issues PublicKeyCredentialRequestOptions for an authentication ceremony.
   *
   * Accepts an optional 'username' query parameter. If provided, the user's
   * registered credential IDs are included in the allowCredentials list.
   * Without it, an empty allowCredentials list triggers the browser's
   * discoverable-key (resident key) selection UI.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current HTTP request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON-encoded PublicKeyCredentialRequestOptions.
   */
  public function challenge(Request $request): JsonResponse {
    $config = $this->config('passkey_forge.settings');
    if (!(bool) $config->get('enabled')) {
      return new JsonResponse(['error' => 'Passkey authentication is disabled.'], 503);
    }

    $allowedCredentials = [];
    $pendingUid = 0;

    $username = trim((string) $request->query->get('username', ''));
    if ($username !== '') {
      $users = $this->entityTypeManager
        ->getStorage('user')
        ->loadByProperties(['name' => $username, 'status' => 1]);

      if (!empty($users)) {
        $user = reset($users);
        $pendingUid = (int) $user->id();
        $allowedCredentials = $this->storage->loadActiveByUid($pendingUid);
      }
    }

    try {
      $options = $this->webAuthn->buildAuthenticationOptions($allowedCredentials);
    }
    catch (\Throwable $e) {
      $this->logger->error('Failed to build authentication options: @msg', ['@msg' => $e->getMessage()]);
      return new JsonResponse(['error' => 'Could not generate authentication options.'], 500);
    }

    $session = $request->getSession();
    $session->set(WebAuthnService::CHALLENGE_SESSION_KEY, $options['challenge']);
    if ($pendingUid > 0) {
      $session->set(self::PENDING_UID_KEY, $pendingUid);
    } else {
      $session->remove(self::PENDING_UID_KEY);
    }

    return new JsonResponse($options);
  }

  /**
   * Verifies an authentication assertion and logs the user in.
   *
   * Expects a JSON body containing the navigator.credentials.get() response
   * with ArrayBuffer fields base64url-encoded. On success, the user is logged
   * in via Drupal's standard session mechanism and a 200 response is returned
   * containing the redirect destination.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current HTTP request (must be POST with JSON body).
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   200 with redirect URL on success, or a 4xx/5xx error.
   */
  public function complete(Request $request): JsonResponse {
    $config = $this->config('passkey_forge.settings');
    if (!(bool) $config->get('enabled')) {
      return new JsonResponse(['error' => 'Passkey authentication is disabled.'], 503);
    }

    $session = $request->getSession();
    $expectedChallenge = $session->get(WebAuthnService::CHALLENGE_SESSION_KEY);

    if (empty($expectedChallenge)) {
      return new JsonResponse(['error' => 'No active authentication challenge.'], 400);
    }

    $body = $request->getContent();
    if (empty($body)) {
      return new JsonResponse(['error' => 'Request body is empty.'], 400);
    }

    try {
      $responseData = json_decode($body, associative: true, flags: JSON_THROW_ON_ERROR);
    }
    catch (\JsonException $e) {
      return new JsonResponse(['error' => 'Invalid JSON in request body.'], 400);
    }

    // Clear session state (challenges are single-use).
    $session->remove(WebAuthnService::CHALLENGE_SESSION_KEY);
    $pendingUid = (int) $session->get(self::PENDING_UID_KEY, 0);
    $session->remove(self::PENDING_UID_KEY);

    // Locate the credential by ID.
    $rawId = $responseData['rawId'] ?? $responseData['id'] ?? '';
    if (empty($rawId)) {
      return new JsonResponse(['error' => 'Missing credential ID in response.'], 400);
    }

    $credential = $this->storage->loadByCredentialId($rawId);

    if ($credential === null) {
      $this->logger->notice('Authentication failed: credential not found (prefix @pfx).', [
        '@pfx' => substr((string) $rawId, 0, 8),
      ]);
      return new JsonResponse(['error' => 'Credential not recognised.'], 401);
    }

    // Cross-check: if the challenge was issued for a specific user, the
    // resolved credential must belong to that user.
    if ($pendingUid > 0 && $credential->uid !== $pendingUid) {
      $this->logger->warning('Credential uid mismatch: expected @expected, got @actual.', [
        '@expected' => $pendingUid,
        '@actual' => $credential->uid,
      ]);
      return new JsonResponse(['error' => 'Credential does not match the challenged user.'], 403);
    }

    try {
      $newSignCount = $this->webAuthn->verifyAuthenticationResponse(
        responseData: $responseData,
        expectedChallenge: $expectedChallenge,
        credential: $credential,
      );
    }
    catch (\InvalidArgumentException $e) {
      $this->logger->notice('Authentication verification failed for uid @uid: @msg', [
        '@uid' => $credential->uid,
        '@msg' => $e->getMessage(),
      ]);
      return new JsonResponse(['error' => $e->getMessage()], 401);
    }
    catch (\Throwable $e) {
      $this->logger->error('Unexpected error during authentication for uid @uid: @msg', [
        '@uid' => $credential->uid,
        '@msg' => $e->getMessage(),
      ]);
      return new JsonResponse(['error' => 'Authentication failed due to a server error.'], 500);
    }

    // Persist the updated signature counter.
    $this->storage->updateSignCount($credential->id, $newSignCount);

    // Load and log in the Drupal user.
    $account = $this->entityTypeManager->getStorage('user')->load($credential->uid);
    if ($account === null || !$account->isActive()) {
      $this->logger->warning('Passkey authentication succeeded but user @uid is not active.', [
        '@uid' => $credential->uid,
      ]);
      return new JsonResponse(['error' => 'User account is not active.'], 403);
    }

    user_login_finalize($account);

    $this->logger->info('User @uid logged in via passkey.', ['@uid' => $credential->uid]);

    $destination = $request->query->get('destination', '/user/' . $credential->uid);

    return new JsonResponse([
      'success' => true,
      'uid' => $credential->uid,
      'redirect' => $destination,
    ]);
  }

}
