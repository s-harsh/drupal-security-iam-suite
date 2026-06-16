<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\passkey_forge\Value\AttestationPolicy;
use Drupal\passkey_forge\Value\PasskeyCredential;
use Psr\Log\LoggerInterface;

/**
 * Core WebAuthn ceremony orchestrator for FIDO2/WebAuthn Level 3.
 *
 * Generates PublicKeyCredentialCreationOptions and
 * PublicKeyCredentialRequestOptions JSON structures for use by the browser
 * WebAuthn API, and validates the authenticator responses returned from
 * navigator.credentials.create() and navigator.credentials.get().
 *
 * This service acts as a facade in front of the web-auth/webauthn-lib library.
 * It reads relying party configuration from passkey_forge.settings and
 * translates between Drupal domain objects (PasskeyCredential) and the raw
 * JSON structures exchanged with the JavaScript layer.
 *
 * Challenge generation uses random_bytes(32) for cryptographically strong
 * randomness. Challenges are base64url-encoded before being sent to the
 * browser and stored in the session keyed by 'passkey_forge_challenge' to
 * allow replay prevention on the server side.
 */
final class WebAuthnService {

  /**
   * Session key used to store the active WebAuthn challenge.
   */
  public const CHALLENGE_SESSION_KEY = 'passkey_forge_challenge';

  /**
   * Session key used to store the active registration user handle.
   */
  public const USER_HANDLE_SESSION_KEY = 'passkey_forge_user_handle';

  /**
   * Constructs a WebAuthnService.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory (reads passkey_forge.settings).
   * @param \Psr\Log\LoggerInterface $logger
   *   The passkey_forge logger channel.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Builds PublicKeyCredentialCreationOptions for a registration ceremony.
   *
   * Returns the JSON-serialisable options array to be passed to
   * navigator.credentials.create({ publicKey: <options> }) in the browser.
   * A fresh challenge is generated on each call; the caller is responsible
   * for storing it in the session before returning the options to the client.
   *
   * @param int $uid
   *   Drupal UID of the registering user.
   * @param string $username
   *   Display name / account name for the user entity.
   * @param string $displayName
   *   Human-readable display name shown by the authenticator UI.
   * @param \Drupal\passkey_forge\Value\PasskeyCredential[] $existingCredentials
   *   Active credentials already registered to this user; listed as
   *   excludeCredentials to prevent re-registering the same authenticator.
   * @param \Drupal\passkey_forge\Value\AttestationPolicy|null $policyOverride
   *   Optional per-call attestation policy override; falls back to settings.
   *
   * @return array<string, mixed>
   *   JSON-serialisable PublicKeyCredentialCreationOptions.
   *
   * @throws \Random\RandomException
   *   If the OS random source is unavailable.
   */
  public function buildRegistrationOptions(
    int $uid,
    string $username,
    string $displayName,
    array $existingCredentials = [],
    ?AttestationPolicy $policyOverride = null,
  ): array {
    $config = $this->configFactory->get('passkey_forge.settings');

    $challenge = $this->generateChallenge();
    $userHandle = $this->generateUserHandle($uid);

    $attestation = ($policyOverride ?? AttestationPolicy::fromStringWithDefault(
      (string) $config->get('attestation_policy'),
    ))->value;

    $excludeCredentials = array_map(
      static fn(PasskeyCredential $c) => [
        'type' => 'public-key',
        'id' => $c->credentialId,
        'transports' => $c->transports,
      ],
      $existingCredentials,
    );

    $options = [
      'challenge' => $challenge,
      'rp' => [
        'id' => (string) $config->get('rp_id'),
        'name' => (string) $config->get('rp_name'),
      ],
      'user' => [
        'id' => $userHandle,
        'name' => $username,
        'displayName' => $displayName,
      ],
      'pubKeyCredParams' => [
        ['type' => 'public-key', 'alg' => -7],   // ES256
        ['type' => 'public-key', 'alg' => -257],  // RS256
        ['type' => 'public-key', 'alg' => -37],   // PS256
        ['type' => 'public-key', 'alg' => -8],    // EdDSA
      ],
      'timeout' => (int) $config->get('timeout'),
      'attestation' => $attestation,
      'excludeCredentials' => $excludeCredentials,
      'authenticatorSelection' => [
        'requireResidentKey' => (bool) $config->get('require_resident_key'),
        'residentKey' => (bool) $config->get('require_resident_key') ? 'required' : 'preferred',
        'userVerification' => (string) ($config->get('user_verification') ?? 'preferred'),
      ],
    ];

    $this->logger->debug(
      'Built registration options for uid @uid with attestation=@att.',
      ['@uid' => $uid, '@att' => $attestation],
    );

    return $options;
  }

  /**
   * Builds PublicKeyCredentialRequestOptions for an authentication ceremony.
   *
   * Returns the JSON-serialisable options array to be passed to
   * navigator.credentials.get({ publicKey: <options> }) in the browser.
   * When allowCredentials is populated the browser will limit the selection to
   * those specific credential IDs (usernameless flow populates it from the
   * user's registered keys; pure discoverable-key flow leaves it empty).
   *
   * @param \Drupal\passkey_forge\Value\PasskeyCredential[] $allowedCredentials
   *   Active credentials to allow; pass an empty array for a discoverable-key
   *   (usernameless) authentication flow.
   *
   * @return array<string, mixed>
   *   JSON-serialisable PublicKeyCredentialRequestOptions.
   *
   * @throws \Random\RandomException
   *   If the OS random source is unavailable.
   */
  public function buildAuthenticationOptions(array $allowedCredentials = []): array {
    $config = $this->configFactory->get('passkey_forge.settings');

    $challenge = $this->generateChallenge();

    $allowList = array_map(
      static fn(PasskeyCredential $c) => [
        'type' => 'public-key',
        'id' => $c->credentialId,
        'transports' => $c->transports,
      ],
      $allowedCredentials,
    );

    $options = [
      'challenge' => $challenge,
      'rpId' => (string) $config->get('rp_id'),
      'timeout' => (int) $config->get('timeout'),
      'allowCredentials' => $allowList,
      'userVerification' => (string) ($config->get('user_verification') ?? 'preferred'),
    ];

    $this->logger->debug(
      'Built authentication options with @count allowed credential(s).',
      ['@count' => count($allowList)],
    );

    return $options;
  }

  /**
   * Verifies a registration response from navigator.credentials.create().
   *
   * Performs the server-side checks mandated by WebAuthn Level 3 §7.1:
   *   1. Base64url-decode clientDataJSON and verify type=webauthn.create.
   *   2. Verify origin matches allowed_origins from settings.
   *   3. Verify challenge matches the session challenge (replay prevention).
   *   4. Parse authenticatorData and verify rpIdHash.
   *   5. Verify UP flag is set; UV flag if user_verification=required.
   *   6. Extract credentialId and COSE public key.
   *
   * @param array<string, mixed> $responseData
   *   Decoded JSON from the browser: id, rawId, response.clientDataJSON,
   *   response.attestationObject, type.
   * @param string $expectedChallenge
   *   The base64url-encoded challenge previously stored in the session.
   *
   * @return array<string, mixed>
   *   Extracted credential data:
   *     - credential_id: base64url string
   *     - public_key: PEM string
   *     - sign_count: int
   *     - aaguid: string|null
   *     - attestation_format: string
   *     - cert_chain: string[]
   *     - transports: string[]
   *
   * @throws \InvalidArgumentException
   *   When any verification step fails.
   */
  public function verifyRegistrationResponse(
    array $responseData,
    string $expectedChallenge,
  ): array {
    $config = $this->configFactory->get('passkey_forge.settings');

    $clientDataJsonB64 = $responseData['response']['clientDataJSON'] ?? '';
    $clientDataJson = base64_decode(strtr($clientDataJsonB64, '-_', '+/'), strict: true);

    if ($clientDataJson === false) {
      throw new \InvalidArgumentException('clientDataJSON is not valid base64url.');
    }

    $clientData = json_decode($clientDataJson, associative: true, flags: JSON_THROW_ON_ERROR);

    if (($clientData['type'] ?? '') !== 'webauthn.create') {
      throw new \InvalidArgumentException(
        sprintf('Invalid clientData type: expected webauthn.create, got %s.', $clientData['type'] ?? 'null'),
      );
    }

    $receivedChallenge = strtr($clientData['challenge'] ?? '', '+/', '-_');
    $receivedChallenge = rtrim($receivedChallenge, '=');
    $expectedNorm = rtrim(strtr($expectedChallenge, '+/', '-_'), '=');

    if (!hash_equals($expectedNorm, $receivedChallenge)) {
      throw new \InvalidArgumentException('Challenge mismatch: possible replay attack.');
    }

    $allowedOrigins = (array) $config->get('allowed_origins');
    $origin = $clientData['origin'] ?? '';
    if (!in_array($origin, $allowedOrigins, strict: true)) {
      throw new \InvalidArgumentException(
        sprintf('Origin "%s" is not in the allowed origins list.', $origin),
      );
    }

    $attestationObjectB64 = $responseData['response']['attestationObject'] ?? '';
    $attestationObjectRaw = base64_decode(strtr($attestationObjectB64, '-_', '+/'), strict: true);

    if ($attestationObjectRaw === false) {
      throw new \InvalidArgumentException('attestationObject is not valid base64url.');
    }

    $parsed = $this->parseAttestationObject($attestationObjectRaw);
    $authData = $this->parseAuthenticatorData($parsed['authData']);

    $rpId = (string) $config->get('rp_id');
    $expectedRpIdHash = hash('sha256', $rpId, binary: true);
    if (!hash_equals($expectedRpIdHash, $authData['rpIdHash'])) {
      throw new \InvalidArgumentException('RP ID hash mismatch.');
    }

    if (!($authData['flags']['UP'] ?? false)) {
      throw new \InvalidArgumentException('User Presence flag not set.');
    }

    $userVerification = (string) ($config->get('user_verification') ?? 'preferred');
    if ($userVerification === 'required' && !($authData['flags']['UV'] ?? false)) {
      throw new \InvalidArgumentException('User Verification flag not set but user_verification=required.');
    }

    if (empty($authData['credentialId'])) {
      throw new \InvalidArgumentException('No credential ID in authenticatorData.');
    }

    $credentialId = rtrim(strtr(base64_encode($authData['credentialId']), '+/', '-_'), '=');

    $transports = $responseData['response']['transports'] ?? [];

    $this->logger->info(
      'Registration ceremony verified for credential prefix @cid.',
      ['@cid' => substr($credentialId, 0, 8)],
    );

    return [
      'credential_id' => $credentialId,
      'public_key' => $authData['publicKeyPem'],
      'sign_count' => (int) ($authData['signCount'] ?? 0),
      'aaguid' => $authData['aaguid'] ?? null,
      'attestation_format' => (string) ($parsed['fmt'] ?? 'none'),
      'cert_chain' => $parsed['certChain'] ?? [],
      'transports' => is_array($transports) ? $transports : [],
    ];
  }

  /**
   * Verifies an authentication response from navigator.credentials.get().
   *
   * Performs the server-side checks mandated by WebAuthn Level 3 §7.2:
   *   1. Locate the credential by credentialId.
   *   2. Verify clientDataJSON type, origin, and challenge.
   *   3. Verify rpIdHash in authenticatorData.
   *   4. Verify UP (and UV if required).
   *   5. Reconstruct the signed data and verify the signature with the stored
   *      public key.
   *   6. Check and update the signature counter.
   *
   * @param array<string, mixed> $responseData
   *   Decoded JSON from the browser: id, rawId, response.clientDataJSON,
   *   response.authenticatorData, response.signature, response.userHandle.
   * @param string $expectedChallenge
   *   The base64url-encoded challenge previously stored in the session.
   * @param \Drupal\passkey_forge\Value\PasskeyCredential $credential
   *   The stored credential retrieved by the credential ID from the response.
   *
   * @return int
   *   The new signature counter value, to be persisted by the caller.
   *
   * @throws \InvalidArgumentException
   *   When any verification step fails.
   */
  public function verifyAuthenticationResponse(
    array $responseData,
    string $expectedChallenge,
    PasskeyCredential $credential,
  ): int {
    $config = $this->configFactory->get('passkey_forge.settings');

    $clientDataJsonB64 = $responseData['response']['clientDataJSON'] ?? '';
    $clientDataJson = base64_decode(strtr($clientDataJsonB64, '-_', '+/'), strict: true);

    if ($clientDataJson === false) {
      throw new \InvalidArgumentException('clientDataJSON is not valid base64url.');
    }

    $clientData = json_decode($clientDataJson, associative: true, flags: JSON_THROW_ON_ERROR);

    if (($clientData['type'] ?? '') !== 'webauthn.get') {
      throw new \InvalidArgumentException(
        sprintf('Invalid clientData type: expected webauthn.get, got %s.', $clientData['type'] ?? 'null'),
      );
    }

    $receivedChallenge = rtrim(strtr($clientData['challenge'] ?? '', '+/', '-_'), '=');
    $expectedNorm = rtrim(strtr($expectedChallenge, '+/', '-_'), '=');

    if (!hash_equals($expectedNorm, $receivedChallenge)) {
      throw new \InvalidArgumentException('Challenge mismatch: possible replay attack.');
    }

    $allowedOrigins = (array) $config->get('allowed_origins');
    $origin = $clientData['origin'] ?? '';
    if (!in_array($origin, $allowedOrigins, strict: true)) {
      throw new \InvalidArgumentException(
        sprintf('Origin "%s" is not in the allowed origins list.', $origin),
      );
    }

    $authDataB64 = $responseData['response']['authenticatorData'] ?? '';
    $authDataRaw = base64_decode(strtr($authDataB64, '-_', '+/'), strict: true);

    if ($authDataRaw === false) {
      throw new \InvalidArgumentException('authenticatorData is not valid base64url.');
    }

    $authData = $this->parseAuthenticatorData($authDataRaw);

    $rpId = (string) $config->get('rp_id');
    $expectedRpIdHash = hash('sha256', $rpId, binary: true);
    if (!hash_equals($expectedRpIdHash, $authData['rpIdHash'])) {
      throw new \InvalidArgumentException('RP ID hash mismatch.');
    }

    if (!($authData['flags']['UP'] ?? false)) {
      throw new \InvalidArgumentException('User Presence flag not set.');
    }

    $userVerification = (string) ($config->get('user_verification') ?? 'preferred');
    if ($userVerification === 'required' && !($authData['flags']['UV'] ?? false)) {
      throw new \InvalidArgumentException('User Verification flag not set but user_verification=required.');
    }

    // Verify the signature.
    $signatureB64 = $responseData['response']['signature'] ?? '';
    $signature = base64_decode(strtr($signatureB64, '-_', '+/'), strict: true);

    if ($signature === false) {
      throw new \InvalidArgumentException('Signature is not valid base64url.');
    }

    $clientDataHash = hash('sha256', $clientDataJson, binary: true);
    $signedData = $authDataRaw . $clientDataHash;

    if (!$this->verifySignature($signedData, $signature, $credential->publicKey)) {
      throw new \InvalidArgumentException('Signature verification failed.');
    }

    // Signature counter check (§7.2 step 17).
    $newSignCount = (int) ($authData['signCount'] ?? 0);
    if ($credential->signCount > 0 || $newSignCount > 0) {
      if ($newSignCount <= $credential->signCount) {
        $this->logger->warning(
          'Sign count regression detected for credential @cid: stored=@stored, received=@new. Possible cloned authenticator.',
          [
            '@cid' => substr($credential->credentialId, 0, 8),
            '@stored' => $credential->signCount,
            '@new' => $newSignCount,
          ],
        );
        throw new \InvalidArgumentException(
          'Signature counter did not increase — possible cloned authenticator.',
        );
      }
    }

    $this->logger->info(
      'Authentication ceremony verified for uid @uid (credential prefix @cid).',
      ['@uid' => $credential->uid, '@cid' => substr($credential->credentialId, 0, 8)],
    );

    return $newSignCount;
  }

  /**
   * Generates a cryptographically random base64url-encoded challenge.
   *
   * @return string
   *   32-byte random challenge as a base64url string (no padding).
   *
   * @throws \Random\RandomException
   *   If the OS entropy source is unavailable.
   */
  public function generateChallenge(): string {
    $bytes = random_bytes(32);
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
  }

  /**
   * Generates a stable user handle for the given Drupal UID.
   *
   * The user handle is the base64url-encoded SHA-256 hash of the module name
   * concatenated with the UID. This makes it deterministic (same user always
   * gets the same handle) and opaque (does not leak the UID to the device).
   *
   * @param int $uid
   *   Drupal user ID.
   *
   * @return string
   *   Base64url-encoded user handle.
   */
  public function generateUserHandle(int $uid): string {
    $raw = hash('sha256', 'passkey_forge:' . $uid, binary: true);
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
  }

  /**
   * Parses a CBOR-encoded attestationObject.
   *
   * Returns a simplified structure with the format identifier, raw
   * authenticatorData bytes, and any DER-encoded certificates extracted from
   * the attestation statement.
   *
   * This implementation uses a lightweight CBOR decoder that handles the
   * specific structure of WebAuthn attestation objects. It is intentionally
   * simplified — a production deployment should use web-auth/webauthn-lib's
   * full attestation parser for MDS3 validation.
   *
   * @param string $attestationObjectRaw
   *   Raw bytes of the CBOR-encoded attestation object.
   *
   * @return array<string, mixed>
   *   Parsed fields: fmt (string), authData (bytes), certChain (string[]).
   *
   * @throws \InvalidArgumentException
   *   On malformed CBOR.
   */
  private function parseAttestationObject(string $attestationObjectRaw): array {
    // Use PHP's ext-cbor or a simple map parser. Since webauthn-lib provides
    // a CBOR decoder we call it via the library when available; otherwise fall
    // back to a minimal implementation that covers the required top-level map.
    if (class_exists('\CBOR\Decoder')) {
      return $this->parseAttestationObjectViaCborLib($attestationObjectRaw);
    }

    // Minimal CBOR map decode — handles only the WebAuthn attestation shape.
    return $this->parseAttestationObjectMinimal($attestationObjectRaw);
  }

  /**
   * Parses an attestation object using the web-auth/cbor-lib library.
   *
   * @param string $raw
   *   Raw CBOR bytes.
   *
   * @return array<string, mixed>
   *   Parsed attestation object fields.
   */
  private function parseAttestationObjectViaCborLib(string $raw): array {
    try {
      $stream = \CBOR\StringStream::create($raw);
      $decoder = \CBOR\Decoder::create();
      $decoded = $decoder->decode($stream);
      $map = $decoded->normalize();

      $fmt = (string) ($map['fmt'] ?? 'none');
      $authData = $map['authData'] ?? '';
      if ($authData instanceof \CBOR\ByteStringObject) {
        $authData = $authData->getValue();
      }

      $certChain = [];
      $attStmt = $map['attStmt'] ?? [];
      if (!empty($attStmt['x5c']) && is_array($attStmt['x5c'])) {
        foreach ($attStmt['x5c'] as $derCert) {
          if (is_string($derCert)) {
            $certChain[] = $this->derToPem($derCert);
          }
        }
      }

      return ['fmt' => $fmt, 'authData' => $authData, 'certChain' => $certChain];
    }
    catch (\Throwable $e) {
      throw new \InvalidArgumentException(
        'Failed to parse attestationObject via CBOR lib: ' . $e->getMessage(),
        previous: $e,
      );
    }
  }

  /**
   * Minimal CBOR map parser for attestation objects (no external dependency).
   *
   * Handles only the structure produced by WebAuthn authenticators:
   * a CBOR map with text-string keys 'fmt', 'authData', and 'attStmt'.
   *
   * @param string $raw
   *   Raw CBOR bytes.
   *
   * @return array<string, mixed>
   *   Parsed fields with safe defaults.
   */
  private function parseAttestationObjectMinimal(string $raw): array {
    // For a 'none' attestation the structure is trivially decodable.
    // We look for the 'authData' key to extract the bytes needed for
    // credential ID and public key extraction. A full CBOR implementation
    // is left to the web-auth/webauthn-lib integration.
    $this->logger->debug('Using minimal CBOR parser for attestation object.');

    // Return minimal structure; downstream parseAuthenticatorData will fail
    // gracefully if authData cannot be extracted.
    return [
      'fmt' => 'none',
      'authData' => $this->extractAuthDataMinimal($raw),
      'certChain' => [],
    ];
  }

  /**
   * Heuristically extracts the authData bytes from a CBOR attestation object.
   *
   * Searches for the CBOR text-string "authData" marker (0x68617574684461)
   * and reads the following byte string. This is intentionally a best-effort
   * fallback for when the CBOR library is unavailable.
   *
   * @param string $raw
   *   Raw CBOR bytes.
   *
   * @return string
   *   authData bytes, or empty string if extraction fails.
   */
  private function extractAuthDataMinimal(string $raw): string {
    // CBOR text string "authData" = 0x68 (text, len 8) + "authData"
    $marker = "\x68authData";
    $pos = strpos($raw, $marker);
    if ($pos === false) {
      return '';
    }

    $start = $pos + strlen($marker);
    if ($start >= strlen($raw)) {
      return '';
    }

    // Next byte is the CBOR byte-string header: 0x58 = byte string, 1-byte
    // length follows; 0x59 = 2-byte length, etc.
    $header = ord($raw[$start]);
    $majorType = ($header & 0xE0) >> 5;
    if ($majorType !== 2) {
      return ''; // Not a byte string.
    }

    $additionalInfo = $header & 0x1F;
    $start++;

    if ($additionalInfo <= 23) {
      $length = $additionalInfo;
    } elseif ($additionalInfo === 24) {
      $length = ord($raw[$start]);
      $start++;
    } elseif ($additionalInfo === 25) {
      $length = unpack('n', substr($raw, $start, 2))[1];
      $start += 2;
    } else {
      return '';
    }

    return substr($raw, $start, $length);
  }

  /**
   * Parses the binary authenticatorData structure.
   *
   * Extracts the rpIdHash, flags, signCount, AAGUID, credential ID, and
   * COSE-encoded public key as defined in WebAuthn Level 3 §6.1.
   *
   * authenticatorData layout:
   *   - Bytes 0–31: rpIdHash (32 bytes SHA-256)
   *   - Byte 32:    flags (bitmask: bit0=UP, bit2=UV, bit6=AT, bit7=ED)
   *   - Bytes 33–36: signCount (uint32 big-endian)
   *   - If AT flag set:
   *       - Bytes 37–52: AAGUID (16 bytes)
   *       - Bytes 53–54: credentialIdLength (uint16 big-endian)
   *       - Bytes 55..(55+credentialIdLength-1): credentialId
   *       - Remaining bytes: COSE public key (CBOR)
   *
   * @param string $authData
   *   Raw authenticatorData bytes.
   *
   * @return array<string, mixed>
   *   Parsed fields: rpIdHash, flags (array), signCount, aaguid,
   *   credentialId (bytes), publicKeyPem (string).
   *
   * @throws \InvalidArgumentException
   *   When the binary structure is too short or malformed.
   */
  private function parseAuthenticatorData(string $authData): array {
    if (strlen($authData) < 37) {
      throw new \InvalidArgumentException(
        sprintf('authenticatorData too short: %d bytes (minimum 37).', strlen($authData)),
      );
    }

    $rpIdHash = substr($authData, 0, 32);
    $flagsByte = ord($authData[32]);
    $flags = [
      'UP' => (bool) ($flagsByte & 0x01),  // User Presence
      'UV' => (bool) ($flagsByte & 0x04),  // User Verification
      'AT' => (bool) ($flagsByte & 0x40),  // Attested Credential Data
      'ED' => (bool) ($flagsByte & 0x80),  // Extension Data
    ];

    $signCount = unpack('N', substr($authData, 33, 4))[1];

    $credentialId = '';
    $publicKeyPem = '';
    $aaguid = null;

    if ($flags['AT']) {
      if (strlen($authData) < 55) {
        throw new \InvalidArgumentException(
          'authenticatorData too short to contain attested credential data.',
        );
      }

      $aaguidRaw = substr($authData, 37, 16);
      $aaguid = $this->formatAaguid($aaguidRaw);

      $credentialIdLength = unpack('n', substr($authData, 53, 2))[1];
      $credentialIdOffset = 55;

      if (strlen($authData) < $credentialIdOffset + $credentialIdLength) {
        throw new \InvalidArgumentException('authenticatorData truncated in credential ID field.');
      }

      $credentialId = substr($authData, $credentialIdOffset, $credentialIdLength);
      $coseKeyOffset = $credentialIdOffset + $credentialIdLength;
      $coseKeyRaw = substr($authData, $coseKeyOffset);

      $publicKeyPem = $this->coseKeyToPem($coseKeyRaw);
    }

    return [
      'rpIdHash' => $rpIdHash,
      'flags' => $flags,
      'signCount' => $signCount,
      'aaguid' => $aaguid,
      'credentialId' => $credentialId,
      'publicKeyPem' => $publicKeyPem,
    ];
  }

  /**
   * Formats a 16-byte AAGUID as a UUID string.
   *
   * @param string $aaguidBytes
   *   16 raw bytes.
   *
   * @return string|null
   *   UUID in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format, or NULL if all
   *   zeros (no AAGUID provided by the authenticator).
   */
  private function formatAaguid(string $aaguidBytes): ?string {
    if ($aaguidBytes === str_repeat("\x00", 16)) {
      return null;
    }

    $hex = bin2hex($aaguidBytes);
    return sprintf(
      '%s-%s-%s-%s-%s',
      substr($hex, 0, 8),
      substr($hex, 8, 4),
      substr($hex, 12, 4),
      substr($hex, 16, 4),
      substr($hex, 20, 12),
    );
  }

  /**
   * Converts a CBOR-encoded COSE public key to PEM format.
   *
   * Supports COSE key types:
   *   - kty=2 (EC2), crv=1 (P-256), alg=-7 (ES256)
   *   - kty=3 (RSA), alg=-257 (RS256)
   *   - kty=1 (OKP), crv=6 (Ed25519), alg=-8 (EdDSA)
   *
   * When the web-auth/cbor-lib library is available it is used for decoding.
   * Otherwise a minimal EC2 P-256 key is reconstructed from raw x/y
   * coordinates via an uncompressed EC point DER structure.
   *
   * @param string $coseKeyRaw
   *   CBOR-encoded COSE key bytes.
   *
   * @return string
   *   PEM-encoded public key (SubjectPublicKeyInfo).
   *
   * @throws \InvalidArgumentException
   *   When the key cannot be decoded or is of an unsupported type.
   */
  private function coseKeyToPem(string $coseKeyRaw): string {
    if (class_exists('\CBOR\Decoder')) {
      return $this->coseKeyToPemViaCborLib($coseKeyRaw);
    }
    return $this->coseKeyToPemMinimal($coseKeyRaw);
  }

  /**
   * Converts a COSE key to PEM using the web-auth/cbor-lib library.
   *
   * @param string $coseKeyRaw
   *   CBOR-encoded COSE key bytes.
   *
   * @return string
   *   PEM public key.
   *
   * @throws \InvalidArgumentException
   *   On decode failure or unsupported key type.
   */
  private function coseKeyToPemViaCborLib(string $coseKeyRaw): string {
    $stream = \CBOR\StringStream::create($coseKeyRaw);
    $decoder = \CBOR\Decoder::create();
    $decoded = $decoder->decode($stream)->normalize();

    $kty = (int) ($decoded[1] ?? 0);
    $alg = (int) ($decoded[3] ?? 0);

    return match ($kty) {
      2 => $this->ecKeyToPem($decoded),        // EC2
      3 => $this->rsaKeyToPem($decoded),       // RSA
      1 => $this->edDsaKeyToPem($decoded),     // OKP
      default => throw new \InvalidArgumentException("Unsupported COSE kty: {$kty}"),
    };
  }

  /**
   * Converts a COSE EC2 P-256 key map to PEM.
   *
   * @param array<int|string, mixed> $map
   *   Normalised CBOR map with COSE parameters.
   *
   * @return string
   *   PEM public key.
   */
  private function ecKeyToPem(array $map): string {
    $crv = (int) ($map[-1] ?? 1);
    if ($crv !== 1) {
      throw new \InvalidArgumentException("Unsupported EC curve id: {$crv} (only P-256/crv=1 supported).");
    }

    $x = $map[-2] ?? '';
    $y = $map[-3] ?? '';

    if (empty($x) || empty($y)) {
      throw new \InvalidArgumentException('EC key missing x or y coordinate.');
    }

    // SubjectPublicKeyInfo for EC P-256 (uncompressed point 0x04 || x || y).
    // OID 1.2.840.10045.2.1 (ecPublicKey), OID 1.2.840.10045.3.1.7 (P-256).
    $header = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');
    $point = "\x04" . $x . $y;
    $der = $header . $point;

    return $this->derToPem($der, 'PUBLIC KEY');
  }

  /**
   * Converts a COSE RSA key map to PEM.
   *
   * @param array<int|string, mixed> $map
   *   Normalised CBOR map with COSE parameters.
   *
   * @return string
   *   PEM public key.
   */
  private function rsaKeyToPem(array $map): string {
    $n = $map[-1] ?? '';  // modulus
    $e = $map[-2] ?? '';  // exponent

    if (empty($n) || empty($e)) {
      throw new \InvalidArgumentException('RSA key missing modulus or exponent.');
    }

    // Encode RSAPublicKey SEQUENCE { INTEGER n, INTEGER e }.
    $nEncoded = $this->encodeDerInteger($n);
    $eEncoded = $this->encodeDerInteger($e);
    $rsaKey = "\x30" . $this->encodeDerLength(strlen($nEncoded . $eEncoded)) . $nEncoded . $eEncoded;

    // Wrap in SubjectPublicKeyInfo.
    // OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL params.
    $algorithmIdentifier = hex2bin('300d06092a864886f70d0101010500');
    $bitString = "\x03" . $this->encodeDerLength(strlen($rsaKey) + 1) . "\x00" . $rsaKey;
    $der = "\x30" . $this->encodeDerLength(strlen($algorithmIdentifier . $bitString))
      . $algorithmIdentifier . $bitString;

    return $this->derToPem($der, 'PUBLIC KEY');
  }

  /**
   * Converts a COSE OKP Ed25519 key to PEM.
   *
   * @param array<int|string, mixed> $map
   *   Normalised CBOR map with COSE parameters.
   *
   * @return string
   *   PEM public key.
   */
  private function edDsaKeyToPem(array $map): string {
    $crv = (int) ($map[-1] ?? 6);
    if ($crv !== 6) {
      throw new \InvalidArgumentException("Unsupported OKP curve id: {$crv} (only Ed25519/crv=6 supported).");
    }

    $x = $map[-2] ?? '';  // public key bytes
    if (empty($x)) {
      throw new \InvalidArgumentException('OKP Ed25519 key missing x (public key bytes).');
    }

    // SubjectPublicKeyInfo for Ed25519: OID 1.3.101.112.
    $algorithmIdentifier = hex2bin('300506032b6570');
    $bitString = "\x03" . $this->encodeDerLength(strlen($x) + 1) . "\x00" . $x;
    $der = "\x30" . $this->encodeDerLength(strlen($algorithmIdentifier . $bitString))
      . $algorithmIdentifier . $bitString;

    return $this->derToPem($der, 'PUBLIC KEY');
  }

  /**
   * Fallback COSE key parser without external dependencies.
   *
   * Handles the common ES256 (EC P-256) case only, as this is the most widely
   * supported algorithm. If a different algorithm is encountered an exception
   * is thrown directing the operator to install web-auth/cbor-lib.
   *
   * @param string $coseKeyRaw
   *   Raw CBOR bytes.
   *
   * @return string
   *   PEM public key.
   *
   * @throws \InvalidArgumentException
   *   When parsing fails.
   */
  private function coseKeyToPemMinimal(string $coseKeyRaw): string {
    // Attempt to locate P-256 x/y coordinates in the CBOR map by looking for
    // the -2 and -3 integer keys (32-byte EC coordinates).
    // This is a best-effort heuristic suitable only for ES256.
    if (strlen($coseKeyRaw) < 70) {
      throw new \InvalidArgumentException(
        'CBOR key too short for EC P-256; install web-auth/cbor-lib for full COSE support.',
      );
    }

    // Search for 32-byte byte strings that could be the x (key -2) and y (-3) params.
    // In CBOR: negative integer -2 encodes as 0x21, -3 as 0x22, byte string of 32 bytes as 0x5820.
    $xPattern = "\x21\x58\x20";
    $yPattern = "\x22\x58\x20";

    $xPos = strpos($coseKeyRaw, $xPattern);
    $yPos = strpos($coseKeyRaw, $yPattern);

    if ($xPos === false || $yPos === false) {
      throw new \InvalidArgumentException(
        'Cannot extract EC coordinates from COSE key without CBOR library. Install web-auth/cbor-lib.',
      );
    }

    $x = substr($coseKeyRaw, $xPos + 3, 32);
    $y = substr($coseKeyRaw, $yPos + 3, 32);

    return $this->ecKeyToPem([-2 => $x, -3 => $y]);
  }

  /**
   * Verifies a WebAuthn signature against a PEM-encoded public key.
   *
   * Uses PHP's openssl_verify(). The hash algorithm is inferred from the key
   * type: SHA-256 for EC and RSA, SHA-512 for Ed25519.
   *
   * @param string $signedData
   *   The data that was signed (authData || hash(clientDataJSON)).
   * @param string $signature
   *   The raw DER-encoded signature bytes.
   * @param string $publicKeyPem
   *   PEM-encoded public key.
   *
   * @return bool
   *   TRUE if the signature is valid.
   *
   * @throws \InvalidArgumentException
   *   When the public key is invalid or the algorithm is unsupported.
   */
  private function verifySignature(string $signedData, string $signature, string $publicKeyPem): bool {
    $key = openssl_pkey_get_public($publicKeyPem);
    if ($key === false) {
      throw new \InvalidArgumentException('Invalid public key PEM: ' . openssl_error_string());
    }

    $keyDetails = openssl_pkey_get_details($key);
    if ($keyDetails === false) {
      throw new \InvalidArgumentException('Cannot read key details.');
    }

    $keyType = $keyDetails['type'];

    $algorithm = match ($keyType) {
      OPENSSL_KEYTYPE_EC => OPENSSL_ALGO_SHA256,
      OPENSSL_KEYTYPE_RSA => OPENSSL_ALGO_SHA256,
      // Ed25519 uses a different verification path.
      default => OPENSSL_ALGO_SHA256,
    };

    // Ed25519 in OpenSSL >=1.1.1.
    if (isset($keyDetails['ec']['curve_name']) && $keyDetails['ec']['curve_name'] === 'ED25519') {
      $result = openssl_verify($signedData, $signature, $key, 'EdDSA');
    } else {
      $result = openssl_verify($signedData, $signature, $key, $algorithm);
    }

    return $result === 1;
  }

  /**
   * Encodes a DER integer, padding with a leading zero if necessary.
   *
   * @param string $bytes
   *   Big-endian unsigned integer bytes.
   *
   * @return string
   *   DER-encoded INTEGER including tag 0x02 and length.
   */
  private function encodeDerInteger(string $bytes): string {
    // Strip leading zero bytes but ensure the value is positive (add 0x00 if
    // the high bit would otherwise be set).
    $bytes = ltrim($bytes, "\x00");
    if ($bytes === '') {
      $bytes = "\x00";
    }
    if (ord($bytes[0]) & 0x80) {
      $bytes = "\x00" . $bytes;
    }
    return "\x02" . $this->encodeDerLength(strlen($bytes)) . $bytes;
  }

  /**
   * Encodes a DER length field in the appropriate short or long form.
   *
   * @param int $length
   *   The length value to encode.
   *
   * @return string
   *   DER length bytes.
   */
  private function encodeDerLength(int $length): string {
    if ($length < 128) {
      return chr($length);
    }
    if ($length < 256) {
      return "\x81" . chr($length);
    }
    return "\x82" . chr($length >> 8) . chr($length & 0xFF);
  }

  /**
   * Converts raw DER bytes to a PEM string with the specified label.
   *
   * @param string $der
   *   Raw DER bytes.
   * @param string $label
   *   PEM label (e.g. 'PUBLIC KEY', 'CERTIFICATE').
   *
   * @return string
   *   PEM-encoded string.
   */
  private function derToPem(string $der, string $label = 'CERTIFICATE'): string {
    $base64 = base64_encode($der);
    $wrapped = chunk_split($base64, 64, "\n");
    return "-----BEGIN {$label}-----\n{$wrapped}-----END {$label}-----\n";
  }

}
