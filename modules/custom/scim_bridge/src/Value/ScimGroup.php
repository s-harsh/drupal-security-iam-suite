<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Value;

/**
 * Immutable value object representing a SCIM 2.0 Group resource.
 *
 * Groups in SCIM correspond to Drupal roles. The 'id' is the Drupal role
 * machine name and 'displayName' is the human-readable role label. Members
 * are represented as user IDs that hold this role.
 */
final readonly class ScimGroup {

  /**
   * Constructs a ScimGroup value object.
   *
   * @param string $id
   *   The Drupal role machine name (used as SCIM id).
   * @param string $externalId
   *   The externalId provided by the IdP.
   * @param string $displayName
   *   The SCIM displayName (maps to Drupal role label).
   * @param array<int, array{value: string, display?: string}> $members
   *   Array of member references. Each entry has at least a 'value' key
   *   containing the Drupal user ID (as a string).
   * @param array<string, mixed> $rawPayload
   *   The full raw decoded JSON payload.
   */
  public function __construct(
    public string $id = '',
    public string $externalId = '',
    public string $displayName = '',
    public array $members = [],
    public array $rawPayload = [],
  ) {}

  /**
   * Creates a ScimGroup from a decoded JSON payload array.
   *
   * @param array<string, mixed> $data
   *   Decoded JSON body from the SCIM request.
   *
   * @return self
   *   A populated ScimGroup instance.
   */
  public static function fromArray(array $data): self {
    return new self(
      id:          (string) ($data['id'] ?? ''),
      externalId:  (string) ($data['externalId'] ?? ''),
      displayName: (string) ($data['displayName'] ?? ''),
      members:     array_values(array_filter(
        (array) ($data['members'] ?? []),
        static fn(mixed $m): bool => is_array($m) && isset($m['value']),
      )),
      rawPayload:  $data,
    );
  }

  /**
   * Returns a new instance with the given id set.
   *
   * @param string $id
   *   The Drupal role machine name.
   *
   * @return self
   *   A copy of this object with the updated id.
   */
  public function withId(string $id): self {
    return new self(
      id:          $id,
      externalId:  $this->externalId,
      displayName: $this->displayName,
      members:     $this->members,
      rawPayload:  $this->rawPayload,
    );
  }

  /**
   * Serialises this value object to a SCIM-compliant array.
   *
   * @return array<string, mixed>
   *   SCIM-compliant group representation.
   */
  public function toScimArray(): array {
    return [
      'schemas'     => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      'id'          => $this->id,
      'externalId'  => $this->externalId,
      'displayName' => $this->displayName,
      'members'     => $this->members,
      'meta' => [
        'resourceType' => 'Group',
        'location'     => '/scim/v2/Groups/' . $this->id,
      ],
    ];
  }

  /**
   * Returns an array of member user IDs as strings.
   *
   * @return string[]
   *   Flat array of Drupal user IDs.
   */
  public function memberIds(): array {
    return array_map(
      static fn(array $m): string => (string) $m['value'],
      $this->members,
    );
  }

}
