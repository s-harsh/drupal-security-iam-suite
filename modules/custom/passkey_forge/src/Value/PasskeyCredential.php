<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Value;

/**
 * Immutable value object representing a registered FIDO2/WebAuthn passkey.
 *
 * Encapsulates all credential metadata stored in the passkey_forge_credentials
 * table. Constructed by PasskeyStorage when reading rows from the database and
 * passed to service layer methods for attestation validation, sign-count
 * verification, and authentication assertion checks.
 *
 * All properties are readonly to enforce immutability — any state change (e.g.
 * incrementing sign_count after authentication) requires creating a new
 * instance via withSignCount().
 */
final readonly class PasskeyCredential {

  /**
   * Constructs a PasskeyCredential.
   *
   * @param int $id
   *   Surrogate database primary key (0 for credentials not yet persisted).
   * @param int $uid
   *   Drupal user ID of the credential owner.
   * @param string $credentialId
   *   Base64url-encoded credential ID as returned by the authenticator.
   * @param string $publicKey
   *   PEM-encoded COSE public key.
   * @param string|null $aaguid
   *   Authenticator Attestation GUID (UUID) identifying the authenticator
   *   model, or NULL when attestation is 'none'.
   * @param int $signCount
   *   Current signature counter. Must be greater than the previously stored
   *   value on each authentication (except when both are 0).
   * @param AttestationPolicy $attestationType
   *   The attestation conveyance policy that was in effect at registration.
   * @param string[] $transports
   *   Array of authenticator transport hints (e.g. ['internal', 'hybrid']).
   * @param string|null $label
   *   Human-readable label chosen by the user, or NULL if not set.
   * @param bool $revoked
   *   TRUE if an administrator has revoked this credential.
   * @param int $created
   *   Unix timestamp when the credential was registered.
   * @param int|null $lastUsed
   *   Unix timestamp of the most recent successful authentication, or NULL if
   *   the credential has never been used for authentication after registration.
   */
  public function __construct(
    public readonly int $id,
    public readonly int $uid,
    public readonly string $credentialId,
    public readonly string $publicKey,
    public readonly ?string $aaguid,
    public readonly int $signCount,
    public readonly AttestationPolicy $attestationType,
    public readonly array $transports,
    public readonly ?string $label,
    public readonly bool $revoked,
    public readonly int $created,
    public readonly ?int $lastUsed,
  ) {}

  /**
   * Returns a new instance with an updated signature counter.
   *
   * Called after each successful authentication assertion to record the new
   * counter value received from the authenticator. All other fields are
   * carried over unchanged.
   *
   * @param int $newSignCount
   *   The signature counter value from the latest authentication response.
   *
   * @return self
   *   New credential instance with the updated counter and lastUsed timestamp.
   */
  public function withSignCount(int $newSignCount): self {
    return new self(
      id: $this->id,
      uid: $this->uid,
      credentialId: $this->credentialId,
      publicKey: $this->publicKey,
      aaguid: $this->aaguid,
      signCount: $newSignCount,
      attestationType: $this->attestationType,
      transports: $this->transports,
      label: $this->label,
      revoked: $this->revoked,
      created: $this->created,
      lastUsed: time(),
    );
  }

  /**
   * Returns a new instance marked as revoked.
   *
   * @return self
   *   New credential instance with revoked=true.
   */
  public function revoke(): self {
    return new self(
      id: $this->id,
      uid: $this->uid,
      credentialId: $this->credentialId,
      publicKey: $this->publicKey,
      aaguid: $this->aaguid,
      signCount: $this->signCount,
      attestationType: $this->attestationType,
      transports: $this->transports,
      label: $this->label,
      revoked: true,
      created: $this->created,
      lastUsed: $this->lastUsed,
    );
  }

  /**
   * Returns whether this credential is currently usable.
   *
   * A credential is usable when it has not been revoked.
   *
   * @return bool
   *   TRUE if the credential may be used for authentication.
   */
  public function isActive(): bool {
    return !$this->revoked;
  }

  /**
   * Returns the transport hints as a JSON string for database storage.
   *
   * @return string
   *   JSON-encoded transport array (e.g. '["internal","hybrid"]').
   */
  public function transportsJson(): string {
    return json_encode($this->transports, JSON_THROW_ON_ERROR);
  }

  /**
   * Creates a PasskeyCredential from a raw database row array.
   *
   * @param array<string, mixed> $row
   *   Associative array of column name to value as returned by a database
   *   query on the passkey_forge_credentials table.
   *
   * @return self
   *   Hydrated credential instance.
   */
  public static function fromDatabaseRow(array $row): self {
    $transports = [];
    if (!empty($row['transports'])) {
      $decoded = json_decode((string) $row['transports'], true);
      $transports = is_array($decoded) ? $decoded : [];
    }

    return new self(
      id: (int) $row['id'],
      uid: (int) $row['uid'],
      credentialId: (string) $row['credential_id'],
      publicKey: (string) $row['public_key'],
      aaguid: isset($row['aaguid']) && $row['aaguid'] !== '' ? (string) $row['aaguid'] : null,
      signCount: (int) ($row['sign_count'] ?? 0),
      attestationType: AttestationPolicy::fromStringWithDefault((string) ($row['attestation_type'] ?? 'none')),
      transports: $transports,
      label: isset($row['label']) && $row['label'] !== '' ? (string) $row['label'] : null,
      revoked: (bool) ($row['revoked'] ?? false),
      created: (int) ($row['created'] ?? 0),
      lastUsed: isset($row['last_used']) && $row['last_used'] !== null ? (int) $row['last_used'] : null,
    );
  }

}
