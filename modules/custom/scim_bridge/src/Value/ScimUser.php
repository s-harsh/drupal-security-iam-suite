<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Value;

/**
 * Immutable value object representing a SCIM 2.0 User resource.
 *
 * All properties directly correspond to the SCIM User schema defined in
 * RFC 7643 §4.1. This object is constructed from the incoming JSON payload
 * and passed to ScimUserMapper for hydration into a Drupal user entity.
 */
final readonly class ScimUser {

  /**
   * Constructs a ScimUser value object.
   *
   * @param string $id
   *   The Drupal user ID (set after creation; empty string before).
   * @param string $externalId
   *   The externalId supplied by the IdP.
   * @param string $userName
   *   The unique username (maps to Drupal 'name' field).
   * @param string $displayName
   *   The displayName (maps to field_display_name if configured).
   * @param string $givenName
   *   The given (first) name.
   * @param string $familyName
   *   The family (last) name.
   * @param string $primaryEmail
   *   The primary email address.
   * @param string $phoneNumber
   *   The primary phone number.
   * @param string $title
   *   Job title.
   * @param string $city
   *   Primary address city.
   * @param string $country
   *   Primary address country (ISO 3166-1 alpha-2 recommended).
   * @param bool $active
   *   Whether the account should be active (maps to Drupal 'status').
   * @param string $locale
   *   IETF locale tag (e.g. en-US).
   * @param string $timezone
   *   IANA timezone name (e.g. America/New_York).
   * @param array<string, mixed> $rawPayload
   *   The full raw decoded JSON payload for pass-through attribute support.
   */
  public function __construct(
    public string $id = '',
    public string $externalId = '',
    public string $userName = '',
    public string $displayName = '',
    public string $givenName = '',
    public string $familyName = '',
    public string $primaryEmail = '',
    public string $phoneNumber = '',
    public string $title = '',
    public string $city = '',
    public string $country = '',
    public bool $active = true,
    public string $locale = '',
    public string $timezone = '',
    public array $rawPayload = [],
  ) {}

  /**
   * Creates a ScimUser from a decoded JSON payload array.
   *
   * Handles both flat and nested SCIM attribute structures as defined by
   * RFC 7643. Multi-valued attributes (emails, phoneNumbers, addresses) are
   * dereferenced by selecting the first entry with type=work or type=primary,
   * falling back to the first entry in the array.
   *
   * @param array<string, mixed> $data
   *   Decoded JSON body from the SCIM request.
   *
   * @return self
   *   A populated ScimUser instance.
   */
  public static function fromArray(array $data): self {
    $name = $data['name'] ?? [];

    return new self(
      id:           (string) ($data['id'] ?? ''),
      externalId:   (string) ($data['externalId'] ?? ''),
      userName:     (string) ($data['userName'] ?? ''),
      displayName:  (string) ($data['displayName'] ?? ''),
      givenName:    (string) ($name['givenName'] ?? ''),
      familyName:   (string) ($name['familyName'] ?? ''),
      primaryEmail: self::firstMultiValue($data['emails'] ?? [], 'value'),
      phoneNumber:  self::firstMultiValue($data['phoneNumbers'] ?? [], 'value'),
      title:        (string) ($data['title'] ?? ''),
      city:         self::firstMultiValue($data['addresses'] ?? [], 'locality'),
      country:      self::firstMultiValue($data['addresses'] ?? [], 'country'),
      active:       isset($data['active']) ? (bool) $data['active'] : true,
      locale:       (string) ($data['locale'] ?? ''),
      timezone:     (string) ($data['timezone'] ?? ''),
      rawPayload:   $data,
    );
  }

  /**
   * Returns a new instance with the given id set.
   *
   * @param string $id
   *   The Drupal user ID to assign.
   *
   * @return self
   *   A copy of this object with the updated id.
   */
  public function withId(string $id): self {
    return new self(
      id:           $id,
      externalId:   $this->externalId,
      userName:     $this->userName,
      displayName:  $this->displayName,
      givenName:    $this->givenName,
      familyName:   $this->familyName,
      primaryEmail: $this->primaryEmail,
      phoneNumber:  $this->phoneNumber,
      title:        $this->title,
      city:         $this->city,
      country:      $this->country,
      active:       $this->active,
      locale:       $this->locale,
      timezone:     $this->timezone,
      rawPayload:   $this->rawPayload,
    );
  }

  /**
   * Serialises this value object to a SCIM-compliant array.
   *
   * The returned array conforms to the User schema in RFC 7643 §4.1 and is
   * safe to JSON-encode and return as a SCIM API response body.
   *
   * @return array<string, mixed>
   *   SCIM-compliant user representation.
   */
  public function toScimArray(): array {
    $repr = [
      'schemas'     => ['urn:ietf:params:scim:schemas:core:2.0:User'],
      'id'          => $this->id,
      'externalId'  => $this->externalId,
      'userName'    => $this->userName,
      'displayName' => $this->displayName,
      'name'        => [
        'givenName'  => $this->givenName,
        'familyName' => $this->familyName,
        'formatted'  => trim($this->givenName . ' ' . $this->familyName),
      ],
      'active'      => $this->active,
      'meta' => [
        'resourceType' => 'User',
        'location'     => '/scim/v2/Users/' . $this->id,
      ],
    ];

    if ($this->primaryEmail !== '') {
      $repr['emails'] = [['value' => $this->primaryEmail, 'primary' => true, 'type' => 'work']];
    }
    if ($this->phoneNumber !== '') {
      $repr['phoneNumbers'] = [['value' => $this->phoneNumber, 'primary' => true, 'type' => 'work']];
    }
    if ($this->title !== '') {
      $repr['title'] = $this->title;
    }
    if ($this->city !== '' || $this->country !== '') {
      $repr['addresses'] = [['locality' => $this->city, 'country' => $this->country, 'primary' => true, 'type' => 'work']];
    }
    if ($this->locale !== '') {
      $repr['locale'] = $this->locale;
    }
    if ($this->timezone !== '') {
      $repr['timezone'] = $this->timezone;
    }

    return $repr;
  }

  /**
   * Extracts a named field from the first entry of a SCIM multi-value array.
   *
   * Prefers entries with type=work or primary=true; falls back to the first
   * element.
   *
   * @param array<int, array<string, mixed>> $items
   *   The multi-valued SCIM array (e.g. emails, phoneNumbers).
   * @param string $field
   *   The field name to extract from each entry (e.g. 'value', 'locality').
   *
   * @return string
   *   The extracted string, or empty string if not present.
   */
  private static function firstMultiValue(array $items, string $field): string {
    if (empty($items)) {
      return '';
    }

    // Prefer primary=true entry.
    foreach ($items as $item) {
      if (!empty($item['primary'])) {
        return (string) ($item[$field] ?? '');
      }
    }
    // Prefer type=work entry.
    foreach ($items as $item) {
      if (($item['type'] ?? '') === 'work') {
        return (string) ($item[$field] ?? '');
      }
    }
    // Fall back to first entry.
    return (string) ($items[0][$field] ?? '');
  }

}
