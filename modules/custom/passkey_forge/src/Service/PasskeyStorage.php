<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Service;

use Drupal\Core\Database\Connection;
use Drupal\passkey_forge\Value\AttestationPolicy;
use Drupal\passkey_forge\Value\PasskeyCredential;
use Psr\Log\LoggerInterface;

/**
 * Database-backed storage layer for FIDO2/WebAuthn passkey credentials.
 *
 * All reads and writes operate on the passkey_forge_credentials table defined
 * in passkey_forge.install. This service is the single point of truth for
 * credential persistence — no other class should query that table directly.
 */
final class PasskeyStorage {

  /**
   * The database table that backs this storage.
   */
  private const TABLE = 'passkey_forge_credentials';

  /**
   * Constructs a PasskeyStorage.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The active database connection.
   * @param \Psr\Log\LoggerInterface $logger
   *   The passkey_forge logger channel.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Persists a newly registered credential to the database.
   *
   * @param int $uid
   *   Drupal UID of the credential owner.
   * @param string $credentialId
   *   Base64url-encoded credential ID.
   * @param string $publicKey
   *   PEM-encoded COSE public key.
   * @param int $signCount
   *   Initial signature counter (typically 0).
   * @param AttestationPolicy $attestationType
   *   The attestation policy used during registration.
   * @param string[] $transports
   *   Authenticator transport hints.
   * @param string|null $aaguid
   *   Authenticator AAGUID or NULL.
   * @param string|null $label
   *   User-provided passkey label or NULL.
   *
   * @return int
   *   The surrogate primary key of the newly inserted row.
   *
   * @throws \Exception
   *   Re-throws any database exception after logging.
   */
  public function save(
    int $uid,
    string $credentialId,
    string $publicKey,
    int $signCount,
    AttestationPolicy $attestationType,
    array $transports,
    ?string $aaguid = null,
    ?string $label = null,
  ): int {
    try {
      $id = $this->database->insert(self::TABLE)
        ->fields([
          'uid' => $uid,
          'credential_id' => $credentialId,
          'public_key' => $publicKey,
          'sign_count' => $signCount,
          'attestation_type' => $attestationType->value,
          'transports' => json_encode($transports, JSON_THROW_ON_ERROR),
          'aaguid' => $aaguid,
          'label' => $label,
          'revoked' => 0,
          'created' => time(),
          'last_used' => null,
        ])
        ->execute();

      $this->logger->info(
        'Registered passkey for uid @uid (credential_id prefix @cid_prefix).',
        [
          '@uid' => $uid,
          '@cid_prefix' => substr($credentialId, 0, 8),
        ],
      );

      return (int) $id;
    }
    catch (\Exception $e) {
      $this->logger->error(
        'Failed to save passkey for uid @uid: @message',
        ['@uid' => $uid, '@message' => $e->getMessage()],
      );
      throw $e;
    }
  }

  /**
   * Loads a single credential by its base64url-encoded credential ID.
   *
   * Only returns non-revoked credentials. Revoked credentials are excluded
   * so that authentication cannot proceed with an administratively disabled
   * key.
   *
   * @param string $credentialId
   *   Base64url-encoded credential ID.
   *
   * @return \Drupal\passkey_forge\Value\PasskeyCredential|null
   *   The credential, or NULL if not found or revoked.
   */
  public function loadByCredentialId(string $credentialId): ?PasskeyCredential {
    $row = $this->database->select(self::TABLE, 'pf')
      ->fields('pf')
      ->condition('pf.credential_id', $credentialId)
      ->condition('pf.revoked', 0)
      ->execute()
      ->fetchAssoc();

    if ($row === FALSE || $row === null) {
      return null;
    }

    return PasskeyCredential::fromDatabaseRow($row);
  }

  /**
   * Loads all active (non-revoked) credentials for a given user.
   *
   * @param int $uid
   *   Drupal user ID.
   *
   * @return \Drupal\passkey_forge\Value\PasskeyCredential[]
   *   Array of credential objects, possibly empty.
   */
  public function loadActiveByUid(int $uid): array {
    $rows = $this->database->select(self::TABLE, 'pf')
      ->fields('pf')
      ->condition('pf.uid', $uid)
      ->condition('pf.revoked', 0)
      ->orderBy('pf.created', 'ASC')
      ->execute()
      ->fetchAllAssoc('id', \PDO::FETCH_ASSOC);

    return array_map(
      static fn(array $row) => PasskeyCredential::fromDatabaseRow($row),
      $rows,
    );
  }

  /**
   * Loads all credentials (including revoked) for a given user.
   *
   * Used by the admin interface to display full credential history.
   *
   * @param int $uid
   *   Drupal user ID.
   *
   * @return \Drupal\passkey_forge\Value\PasskeyCredential[]
   *   Array of all credential objects including revoked ones.
   */
  public function loadAllByUid(int $uid): array {
    $rows = $this->database->select(self::TABLE, 'pf')
      ->fields('pf')
      ->condition('pf.uid', $uid)
      ->orderBy('pf.created', 'ASC')
      ->execute()
      ->fetchAllAssoc('id', \PDO::FETCH_ASSOC);

    return array_map(
      static fn(array $row) => PasskeyCredential::fromDatabaseRow($row),
      $rows,
    );
  }

  /**
   * Returns whether a user has at least one active passkey registered.
   *
   * @param int $uid
   *   Drupal user ID.
   *
   * @return bool
   *   TRUE if one or more active credentials exist for the user.
   */
  public function userHasPasskey(int $uid): bool {
    $count = (int) $this->database->select(self::TABLE, 'pf')
      ->condition('pf.uid', $uid)
      ->condition('pf.revoked', 0)
      ->countQuery()
      ->execute()
      ->fetchField();

    return $count > 0;
  }

  /**
   * Updates the signature counter and last_used timestamp after authentication.
   *
   * @param int $credentialDbId
   *   The surrogate primary key of the credential row.
   * @param int $newSignCount
   *   The new signature counter value received from the authenticator.
   */
  public function updateSignCount(int $credentialDbId, int $newSignCount): void {
    $this->database->update(self::TABLE)
      ->fields([
        'sign_count' => $newSignCount,
        'last_used' => time(),
      ])
      ->condition('id', $credentialDbId)
      ->execute();
  }

  /**
   * Administratively revokes a credential by its database ID.
   *
   * Sets the revoked flag to 1. The row is kept for audit purposes.
   *
   * @param int $credentialDbId
   *   The surrogate primary key of the credential row.
   * @param int $revokedByUid
   *   UID of the administrator performing the revocation (for logging).
   *
   * @return bool
   *   TRUE if a row was updated, FALSE if the credential was not found.
   */
  public function revoke(int $credentialDbId, int $revokedByUid): bool {
    $updated = (int) $this->database->update(self::TABLE)
      ->fields(['revoked' => 1])
      ->condition('id', $credentialDbId)
      ->execute();

    if ($updated > 0) {
      $this->logger->info(
        'Passkey credential @id revoked by uid @admin.',
        ['@id' => $credentialDbId, '@admin' => $revokedByUid],
      );
      return true;
    }

    return false;
  }

  /**
   * Deletes all credentials for a given user.
   *
   * Called when a user account is deleted (via hook_user_delete).
   *
   * @param int $uid
   *   Drupal user ID.
   */
  public function deleteByUid(int $uid): void {
    $this->database->delete(self::TABLE)
      ->condition('uid', $uid)
      ->execute();

    $this->logger->info(
      'Deleted all passkey credentials for uid @uid.',
      ['@uid' => $uid],
    );
  }

  /**
   * Updates the user-provided label for a credential.
   *
   * @param int $credentialDbId
   *   Surrogate primary key of the credential row.
   * @param int $uid
   *   UID of the credential owner (used to scope the update to prevent IDOR).
   * @param string $label
   *   New label string (max 255 characters).
   *
   * @return bool
   *   TRUE if the row was updated.
   */
  public function updateLabel(int $credentialDbId, int $uid, string $label): bool {
    $updated = (int) $this->database->update(self::TABLE)
      ->fields(['label' => substr($label, 0, 255)])
      ->condition('id', $credentialDbId)
      ->condition('uid', $uid)
      ->execute();

    return $updated > 0;
  }

}
