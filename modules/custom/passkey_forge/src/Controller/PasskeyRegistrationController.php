<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\passkey_forge\Service\AttestationValidator;
use Drupal\passkey_forge\Service\PasskeyStorage;
use Drupal\passkey_forge\Service\WebAuthnService;
use Drupal\passkey_forge\Value\AttestationPolicy;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Handles FIDO2/WebAuthn passkey registration ceremonies.
 *
 * Exposes two JSON endpoints:
 *   - GET  /passkey-forge/register/challenge  — issue registration options
 *   - POST /passkey-forge/register/complete   — verify and store credential
 *
 * Both endpoints require the user to be authenticated (enforced via routing
 * requirement _user_is_logged_in: TRUE). The challenge is stored in the PHP
 * session between the two requests to prevent replay attacks.
 */
final class PasskeyRegistrationController extends ControllerBase {

  /**
   * Constructs a PasskeyRegistrationController.
   *
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user proxy.
   * @param \Drupal\passkey_forge\Service\WebAuthnService $webAuthn
   *   The WebAuthn ceremony service.
   * @param \Drupal\passkey_forge\Service\PasskeyStorage $storage
   *   The passkey credential storage.
   * @param \Drupal\passkey_forge\Service\AttestationValidator $attestationValidator
   *   The attestation policy validator.
   * @param \Psr\Log\LoggerInterface $logger
   *   The passkey_forge logger channel.
   */
  public function __construct(
    private readonly AccountProxyInterface $currentUser,
    private readonly WebAuthnService $webAuthn,
    private readonly PasskeyStorage $storage,
    private readonly AttestationValidator $attestationValidator,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('current_user'),
      $container->get('passkey_forge.webauthn'),
      $container->get('passkey_forge.storage'),
      $container->get('passkey_forge.attestation_validator'),
      $container->get('logger.channel.passkey_forge'),
    );
  }

  /**
   * Issues PublicKeyCredentialCreationOptions for a registration ceremony.
   *
   * Generates a fresh challenge, stores it in the session, and returns the
   * complete options object as JSON. The browser's JavaScript layer passes
   * this directly to navigator.credentials.create().
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current HTTP request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON-encoded PublicKeyCredentialCreationOptions on success, or a 4xx
   *   error response.
   */
  public function challenge(Request $request): JsonResponse {
    $uid = (int) $this->currentUser->id();

    if ($uid === 0) {
      return new JsonResponse(['error' => 'Authentication required.'], 401);
    }

    $config = $this->config('passkey_forge.settings');
    if (!(bool) $config->get('enabled')) {
      return new JsonResponse(['error' => 'Passkey authentication is disabled.'], 503);
    }

    $account = $this->entityTypeManager()->getStorage('user')->load($uid);
    if ($account === null) {
      return new JsonResponse(['error' => 'User not found.'], 404);
    }

    $existingCredentials = $this->storage->loadActiveByUid($uid);

    try {
      $options = $this->webAuthn->buildRegistrationOptions(
        uid: $uid,
        username: (string) $account->getAccountName(),
        displayName: (string) ($account->getDisplayName() ?: $account->getAccountName()),
        existingCredentials: $existingCredentials,
      );
    }
    catch (\Throwable $e) {
      $this->logger->error('Failed to build registration options for uid @uid: @msg', [
        '@uid' => $uid,
        '@msg' => $e->getMessage(),
      ]);
      return new JsonResponse(['error' => 'Could not generate registration options.'], 500);
    }

    $session = $request->getSession();
    $session->set(WebAuthnService::CHALLENGE_SESSION_KEY, $options['challenge']);
    $session->set(WebAuthnService::USER_HANDLE_SESSION_KEY, $options['user']['id']);

    return new JsonResponse($options);
  }

  /**
   * Verifies a registration response and stores the new credential.
   *
   * Expects a JSON body containing the output of navigator.credentials.create()
   * serialised to JSON with ArrayBuffer fields base64url-encoded by the JS
   * layer. Returns 201 Created on success.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current HTTP request (must be POST with JSON body).
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   201 with credential metadata on success, or a 4xx/5xx error.
   */
  public function complete(Request $request): JsonResponse {
    $uid = (int) $this->currentUser->id();

    if ($uid === 0) {
      return new JsonResponse(['error' => 'Authentication required.'], 401);
    }

    $config = $this->config('passkey_forge.settings');
    if (!(bool) $config->get('enabled')) {
      return new JsonResponse(['error' => 'Passkey authentication is disabled.'], 503);
    }

    $session = $request->getSession();
    $expectedChallenge = $session->get(WebAuthnService::CHALLENGE_SESSION_KEY);

    if (empty($expectedChallenge)) {
      return new JsonResponse(['error' => 'No active registration challenge. Start the ceremony first.'], 400);
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

    // Clear the session challenge immediately (one-time use).
    $session->remove(WebAuthnService::CHALLENGE_SESSION_KEY);
    $session->remove(WebAuthnService::USER_HANDLE_SESSION_KEY);

    try {
      $verified = $this->webAuthn->verifyRegistrationResponse($responseData, $expectedChallenge);
    }
    catch (\InvalidArgumentException $e) {
      $this->logger->notice('Registration verification failed for uid @uid: @msg', [
        '@uid' => $uid,
        '@msg' => $e->getMessage(),
      ]);
      return new JsonResponse(['error' => $e->getMessage()], 400);
    }
    catch (\Throwable $e) {
      $this->logger->error('Unexpected error during registration for uid @uid: @msg', [
        '@uid' => $uid,
        '@msg' => $e->getMessage(),
      ]);
      return new JsonResponse(['error' => 'Registration failed due to a server error.'], 500);
    }

    // Validate attestation against site policy.
    $policyValid = $this->attestationValidator->validate(
      attestationFormat: $verified['attestation_format'],
      certChain: $verified['cert_chain'],
    );

    if (!$policyValid) {
      $this->logger->notice(
        'Attestation policy violation for uid @uid: format @fmt rejected.',
        ['@uid' => $uid, '@fmt' => $verified['attestation_format']],
      );
      return new JsonResponse([
        'error' => sprintf(
          'Attestation format "%s" does not satisfy the configured attestation policy.',
          $verified['attestation_format'],
        ),
      ], 422);
    }

    // Derive label from request if provided.
    $label = isset($responseData['label']) ? substr((string) $responseData['label'], 0, 255) : null;

    try {
      $dbId = $this->storage->save(
        uid: $uid,
        credentialId: $verified['credential_id'],
        publicKey: $verified['public_key'],
        signCount: $verified['sign_count'],
        attestationType: AttestationPolicy::fromStringWithDefault($verified['attestation_format'] === 'none' ? 'none' : (string) $config->get('attestation_policy')),
        transports: $verified['transports'],
        aaguid: $verified['aaguid'],
        label: $label,
      );
    }
    catch (\Throwable $e) {
      $this->logger->error('Failed to persist passkey for uid @uid: @msg', [
        '@uid' => $uid,
        '@msg' => $e->getMessage(),
      ]);
      return new JsonResponse(['error' => 'Could not save credential.'], 500);
    }

    return new JsonResponse([
      'success' => true,
      'credential_db_id' => $dbId,
      'credential_id_prefix' => substr($verified['credential_id'], 0, 8),
      'aaguid' => $verified['aaguid'],
      'transports' => $verified['transports'],
    ], 201);
  }

}
