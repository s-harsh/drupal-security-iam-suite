<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\passkey_forge\Value\AttestationPolicy;
use Psr\Log\LoggerInterface;

/**
 * Validates WebAuthn attestation statements against the configured policy.
 *
 * During passkey registration the authenticator may include an attestation
 * statement that proves the device's manufacturer and model. This service
 * applies the site-wide attestation policy — and optionally per-role policy
 * overrides — to decide whether a given attestation statement is acceptable.
 *
 * WebAuthn Level 3 defines three conveyance preferences (§5.4.6):
 *   - none: attestation is not requested; any response is accepted.
 *   - indirect: attestation is requested but may be anonymised by the
 *     platform; the relying party validates the type but not the chain.
 *   - direct: full manufacturer attestation must be present and the
 *     certificate chain must validate against a known trust anchor.
 *
 * For 'direct', this implementation checks that the attestation format is
 * one of the FIDO MDS3 formats ('packed', 'tpm', 'android-key',
 * 'android-safetynet', 'fido-u2f', 'apple') and that a non-empty
 * certificate chain was provided. Full MDS3 trust-anchor validation would
 * require the FIDO metadata service and is beyond the scope of this module's
 * built-in validation — operators should integrate webauthn-lib's
 * MetadataStatementRepository for that.
 */
final class AttestationValidator {

  /**
   * Attestation formats that carry a verifiable certificate chain.
   */
  private const VERIFIABLE_FORMATS = [
    'packed',
    'tpm',
    'android-key',
    'android-safetynet',
    'fido-u2f',
    'apple',
  ];

  /**
   * Constructs an AttestationValidator.
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
   * Determines whether an attestation response satisfies the active policy.
   *
   * @param string $attestationFormat
   *   The attestation statement format identifier (e.g. 'none', 'packed').
   * @param string[] $certChain
   *   PEM-encoded certificate chain from the attestation statement. Empty for
   *   'none' and 'self' attestation.
   * @param string|null $roleOverridePolicy
   *   Optional attestation policy string to use instead of the site default.
   *   Pass a role-specific override from the settings form, or NULL to use
   *   the global site policy.
   *
   * @return bool
   *   TRUE when the attestation satisfies the policy; FALSE when it does not.
   */
  public function validate(
    string $attestationFormat,
    array $certChain,
    ?string $roleOverridePolicy = null,
  ): bool {
    $policy = $roleOverridePolicy !== null
      ? AttestationPolicy::fromStringWithDefault($roleOverridePolicy)
      : $this->getConfiguredPolicy();

    return match ($policy) {
      AttestationPolicy::None => $this->validateNonePolicy($attestationFormat),
      AttestationPolicy::Indirect => $this->validateIndirectPolicy($attestationFormat),
      AttestationPolicy::Direct => $this->validateDirectPolicy($attestationFormat, $certChain),
    };
  }

  /**
   * Returns the site-wide attestation policy from configuration.
   *
   * @return \Drupal\passkey_forge\Value\AttestationPolicy
   *   The configured attestation policy.
   */
  public function getConfiguredPolicy(): AttestationPolicy {
    $configValue = (string) $this->configFactory
      ->get('passkey_forge.settings')
      ->get('attestation_policy');

    return AttestationPolicy::fromStringWithDefault($configValue);
  }

  /**
   * Validates against the 'none' policy.
   *
   * Any attestation format is accepted when the policy is 'none'. This
   * includes self-attestation and completely absent statements.
   *
   * @param string $attestationFormat
   *   The attestation format identifier.
   *
   * @return bool
   *   Always TRUE.
   */
  private function validateNonePolicy(string $attestationFormat): bool {
    $this->logger->debug(
      'Attestation policy=none: accepted format @fmt.',
      ['@fmt' => $attestationFormat],
    );
    return true;
  }

  /**
   * Validates against the 'indirect' policy.
   *
   * The authenticator must supply some attestation format — a bare 'none'
   * format is not acceptable when indirect attestation is required. The
   * certificate chain itself is not validated.
   *
   * @param string $attestationFormat
   *   The attestation format identifier.
   *
   * @return bool
   *   TRUE if the format is not bare 'none'.
   */
  private function validateIndirectPolicy(string $attestationFormat): bool {
    if ($attestationFormat === 'none') {
      $this->logger->notice(
        'Attestation policy=indirect: rejected bare "none" format.',
      );
      return false;
    }

    $this->logger->debug(
      'Attestation policy=indirect: accepted format @fmt.',
      ['@fmt' => $attestationFormat],
    );
    return true;
  }

  /**
   * Validates against the 'direct' policy.
   *
   * Requires a verifiable format and a non-empty certificate chain.
   *
   * @param string $attestationFormat
   *   The attestation format identifier.
   * @param string[] $certChain
   *   PEM-encoded certificate chain.
   *
   * @return bool
   *   TRUE only when the format is a known verifiable type AND the certificate
   *   chain contains at least one entry.
   */
  private function validateDirectPolicy(string $attestationFormat, array $certChain): bool {
    if (!in_array($attestationFormat, self::VERIFIABLE_FORMATS, strict: true)) {
      $this->logger->notice(
        'Attestation policy=direct: rejected unverifiable format @fmt.',
        ['@fmt' => $attestationFormat],
      );
      return false;
    }

    if (empty($certChain)) {
      $this->logger->notice(
        'Attestation policy=direct: rejected empty certificate chain for format @fmt.',
        ['@fmt' => $attestationFormat],
      );
      return false;
    }

    $this->logger->debug(
      'Attestation policy=direct: accepted format @fmt with @count cert(s).',
      ['@fmt' => $attestationFormat, '@count' => count($certChain)],
    );
    return true;
  }

  /**
   * Returns all available policy options as a key=>label array.
   *
   * Used to populate the settings form select element.
   *
   * @return array<string, string>
   *   Map of policy machine name to display label.
   */
  public function getPolicyOptions(): array {
    $options = [];
    foreach (AttestationPolicy::cases() as $case) {
      $options[$case->value] = $case->label();
    }
    return $options;
  }

}
