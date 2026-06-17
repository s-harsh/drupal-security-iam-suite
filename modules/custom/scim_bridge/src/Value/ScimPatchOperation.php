<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Value;

/**
 * Immutable value object representing a single SCIM PATCH operation.
 *
 * Corresponds to one entry in the 'Operations' array of a SCIM PATCH request
 * as defined by RFC 7644 §3.5.2.
 *
 * A PATCH request body looks like:
 * @code
 * {
 *   "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
 *   "Operations": [
 *     {"op": "replace", "path": "active", "value": false},
 *     {"op": "add",     "path": "emails[type eq \"work\"].value",
 *      "value": "new@example.com"}
 *   ]
 * }
 * @endcode
 */
final readonly class ScimPatchOperation {

  /**
   * Valid operation types defined by RFC 7644 §3.5.2.
   */
  public const OP_ADD     = 'add';
  public const OP_REMOVE  = 'remove';
  public const OP_REPLACE = 'replace';

  /**
   * Constructs a ScimPatchOperation.
   *
   * @param string $op
   *   The operation: 'add', 'remove', or 'replace'.
   * @param string $path
   *   The attribute path to operate on (e.g. 'active', 'name.givenName',
   *   'emails[type eq "work"].value'). Empty string means the entire resource.
   * @param mixed $value
   *   The new value for 'add' and 'replace' operations; null for 'remove'.
   */
  public function __construct(
    public string $op,
    public string $path,
    public mixed $value,
  ) {}

  /**
   * Creates a ScimPatchOperation from a raw decoded operation entry.
   *
   * @param array<string, mixed> $entry
   *   A single entry from the 'Operations' PATCH array.
   *
   * @return self
   *   A populated ScimPatchOperation instance.
   */
  public static function fromArray(array $entry): self {
    return new self(
      op:    strtolower((string) ($entry['op'] ?? '')),
      path:  (string) ($entry['path'] ?? ''),
      value: $entry['value'] ?? null,
    );
  }

  /**
   * Returns true if this is a valid operation type per RFC 7644.
   *
   * @return bool
   *   TRUE when op is one of add, remove, replace.
   */
  public function isValid(): bool {
    return in_array($this->op, [self::OP_ADD, self::OP_REMOVE, self::OP_REPLACE], true);
  }

  /**
   * Parses the attribute path and returns the top-level attribute name.
   *
   * For example, 'emails[type eq "work"].value' returns 'emails',
   * 'name.givenName' returns 'name', and 'active' returns 'active'.
   *
   * @return string
   *   The top-level SCIM attribute name.
   */
  public function topLevelAttribute(): string {
    $path = $this->path;
    // Strip filter expressions: emails[...] → emails
    $path = (string) preg_replace('/\[.*?\]/', '', $path);
    // Return first segment of dot notation.
    return explode('.', $path)[0];
  }

  /**
   * Returns the scalar string value if value is a string, or null otherwise.
   *
   * Convenience helper for simple scalar attribute patches.
   *
   * @return string|null
   *   The string value or null.
   */
  public function scalarStringValue(): ?string {
    return is_string($this->value) ? $this->value : null;
  }

  /**
   * Returns the scalar bool value if value can be interpreted as bool.
   *
   * @return bool|null
   *   The bool value or null.
   */
  public function scalarBoolValue(): ?bool {
    if (is_bool($this->value)) {
      return $this->value;
    }
    if (is_string($this->value)) {
      $lower = strtolower($this->value);
      if ($lower === 'true') {
        return true;
      }
      if ($lower === 'false') {
        return false;
      }
    }
    return null;
  }

}
