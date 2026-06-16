<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Value;

/**
 * Enum representing the supported WebAuthn attestation conveyance policies.
 *
 * Maps directly to the AttestationConveyancePreference values defined in the
 * WebAuthn Level 3 specification (§5.4.6). The string value is used when
 * serialising the PublicKeyCredentialCreationOptions to JSON.
 */
enum AttestationPolicy: string {

  /**
   * No attestation statement is requested or verified.
   *
   * The authenticator may include an attestation statement but the relying
   * party neither requests nor validates it. Appropriate for general-purpose
   * consumer sites where device-model provenance is not a compliance
   * requirement.
   */
  case None = 'none';

  /**
   * Attestation is requested but the authenticator may anonymise it.
   *
   * The authenticator returns an attestation statement. CTAP2 authenticators
   * may route it through an anonymisation CA so that individual devices cannot
   * be tracked. Suitable for regulated environments that need a basic
   * assurance of authenticator type without identifying individual tokens.
   */
  case Indirect = 'indirect';

  /**
   * Full attestation is requested and must be verifiable.
   *
   * The authenticator returns a complete, manufacturer-signed attestation
   * certificate chain. The relying party MUST validate the chain against a
   * trust anchor (MDS3 / enterprise root CA). Use for high-assurance
   * deployments such as government portals or financial institutions.
   */
  case Direct = 'direct';

  /**
   * Creates an AttestationPolicy from a string, defaulting to None on unknown.
   *
   * @param string $value
   *   One of 'none', 'indirect', or 'direct'.
   *
   * @return self
   *   The matching enum case, or self::None if the value is unrecognised.
   */
  public static function fromStringWithDefault(string $value): self {
    return self::tryFrom($value) ?? self::None;
  }

  /**
   * Returns a human-readable label for UI display.
   *
   * @return string
   *   Display label.
   */
  public function label(): string {
    return match($this) {
      self::None => 'None — no attestation required',
      self::Indirect => 'Indirect — anonymised attestation',
      self::Direct => 'Direct — full manufacturer attestation',
    };
  }

}
