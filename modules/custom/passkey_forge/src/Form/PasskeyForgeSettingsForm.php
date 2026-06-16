<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Form;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\passkey_forge\Service\AttestationValidator;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Administration settings form for the Passkey Forge module.
 *
 * Exposes all configuration keys from passkey_forge.settings:
 *   - enabled: global on/off switch
 *   - rp_id: Relying Party ID (domain)
 *   - rp_name: Relying Party display name
 *   - allowed_origins: list of accepted origins
 *   - attestation_policy: none / indirect / direct
 *   - timeout: WebAuthn ceremony timeout in ms
 *   - require_resident_key: require discoverable credentials
 *   - user_verification: required / preferred / discouraged
 *   - enforce_for_roles: roles that must use passkeys
 *   - allow_password_fallback: allow password login when no passkey exists
 *   - challenge_ttl: challenge session lifetime in seconds
 */
final class PasskeyForgeSettingsForm extends ConfigFormBase {

  /**
   * The module settings config object name.
   */
  private const CONFIG_NAME = 'passkey_forge.settings';

  /**
   * Constructs a PasskeyForgeSettingsForm.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\passkey_forge\Service\AttestationValidator $attestationValidator
   *   The attestation validator (provides policy option labels).
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager (used to load role entities for the role list).
   */
  public function __construct(
    ConfigFactoryInterface $configFactory,
    private readonly AttestationValidator $attestationValidator,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {
    parent::__construct($configFactory);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('passkey_forge.attestation_validator'),
      $container->get('entity_type.manager'),
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return [self::CONFIG_NAME];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'passkey_forge_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config(self::CONFIG_NAME);

    $form['global'] = [
      '#type' => 'details',
      '#title' => $this->t('Global settings'),
      '#open' => TRUE,
    ];

    $form['global']['enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable Passkey Forge'),
      '#description' => $this->t(
        'When unchecked, all registration and authentication endpoints return 503 and the passkey login bypass on the standard login form is disabled. Existing credentials are preserved.',
      ),
      '#default_value' => (bool) $config->get('enabled'),
    ];

    $form['global']['allow_password_fallback'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow password fallback'),
      '#description' => $this->t(
        'When checked, users without any registered passkey may still log in with their password. When unchecked, users in an enforced role who have no passkey will be blocked from logging in — useful for stricter compliance environments.',
      ),
      '#default_value' => (bool) $config->get('allow_password_fallback'),
    ];

    $form['relying_party'] = [
      '#type' => 'details',
      '#title' => $this->t('Relying Party (RP) configuration'),
      '#open' => TRUE,
    ];

    $form['relying_party']['rp_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Relying Party ID'),
      '#description' => $this->t(
        'The domain used as the WebAuthn Relying Party ID. Must be a registrable domain suffix of the site origin (e.g. <code>example.com</code> for <code>https://app.example.com</code>). Changing this after credentials have been registered will break existing passkeys.',
      ),
      '#default_value' => (string) $config->get('rp_id'),
      '#required' => TRUE,
      '#maxlength' => 253,
    ];

    $form['relying_party']['rp_name'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Relying Party display name'),
      '#description' => $this->t(
        'Human-readable name shown in the browser passkey registration UI (e.g. "Acme Corp Portal"). Max 64 characters.',
      ),
      '#default_value' => (string) $config->get('rp_name'),
      '#required' => TRUE,
      '#maxlength' => 64,
    ];

    $form['relying_party']['allowed_origins'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed origins'),
      '#description' => $this->t(
        'One absolute origin per line (scheme + host + optional port, e.g. <code>https://example.com</code>). The origin in the browser\'s clientDataJSON must match one of these values. Include all hostnames users access the site from.',
      ),
      '#default_value' => implode("\n", (array) $config->get('allowed_origins')),
      '#required' => TRUE,
      '#rows' => 4,
    ];

    $form['webauthn'] = [
      '#type' => 'details',
      '#title' => $this->t('WebAuthn ceremony options'),
      '#open' => TRUE,
    ];

    $form['webauthn']['attestation_policy'] = [
      '#type' => 'radios',
      '#title' => $this->t('Default attestation policy'),
      '#description' => $this->t(
        '<strong>None</strong>: No attestation is requested. Widest device compatibility. Suitable for most consumer sites.<br><strong>Indirect</strong>: Attestation is requested but the platform may anonymise it. Provides device type assurance without individual tracking.<br><strong>Direct</strong>: Full manufacturer-signed attestation is required with a verifiable certificate chain. Use for regulated or high-security environments.',
      ),
      '#options' => $this->attestationValidator->getPolicyOptions(),
      '#default_value' => (string) $config->get('attestation_policy'),
      '#required' => TRUE,
    ];

    $form['webauthn']['timeout'] = [
      '#type' => 'number',
      '#title' => $this->t('Ceremony timeout'),
      '#description' => $this->t('Milliseconds the browser will wait for the authenticator. Range 10000–300000.'),
      '#default_value' => (int) $config->get('timeout'),
      '#required' => TRUE,
      '#min' => 10000,
      '#max' => 300000,
      '#step' => 1000,
      '#field_suffix' => $this->t('ms'),
    ];

    $form['webauthn']['user_verification'] = [
      '#type' => 'radios',
      '#title' => $this->t('User verification'),
      '#description' => $this->t(
        '<strong>Required</strong>: Authenticator must verify the user (PIN, biometric). The UV flag in authenticatorData is enforced.<br><strong>Preferred</strong> (default): UV is requested but not required — supports authenticators without built-in verification.<br><strong>Discouraged</strong>: UV is not requested. Use only when user experience is paramount and security requirements are minimal.',
      ),
      '#options' => [
        'required' => $this->t('Required'),
        'preferred' => $this->t('Preferred'),
        'discouraged' => $this->t('Discouraged'),
      ],
      '#default_value' => (string) ($config->get('user_verification') ?? 'preferred'),
      '#required' => TRUE,
    ];

    $form['webauthn']['require_resident_key'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Require resident (discoverable) key'),
      '#description' => $this->t(
        'When checked, credentials must be stored on the authenticator (resident keys / passkeys in the FIDO2 sense). This enables usernameless login flows but limits compatibility with older security keys.',
      ),
      '#default_value' => (bool) $config->get('require_resident_key'),
    ];

    $form['webauthn']['challenge_ttl'] = [
      '#type' => 'number',
      '#title' => $this->t('Challenge TTL'),
      '#description' => $this->t('Seconds a pending challenge is valid before it must be cleared. Range 30–600.'),
      '#default_value' => (int) $config->get('challenge_ttl'),
      '#required' => TRUE,
      '#min' => 30,
      '#max' => 600,
      '#step' => 1,
      '#field_suffix' => $this->t('seconds'),
    ];

    $form['enforcement'] = [
      '#type' => 'details',
      '#title' => $this->t('Per-role passkey enforcement'),
      '#open' => TRUE,
    ];

    $roles = $this->entityTypeManager->getStorage('user_role')->loadMultiple();
    $roleOptions = [];
    foreach ($roles as $rid => $role) {
      if (!in_array($rid, ['anonymous', 'authenticated'], strict: true)) {
        $roleOptions[$rid] = $role->label();
      }
    }

    $form['enforcement']['enforce_for_roles'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Require passkey for roles'),
      '#description' => $this->t(
        'Users with any of the selected roles must authenticate with a passkey. On login, users in these roles who have not registered a passkey will receive a warning directing them to register one. Combine with "Allow password fallback" unchecked to hard-enforce.',
      ),
      '#options' => $roleOptions,
      '#default_value' => (array) $config->get('enforce_for_roles'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    $rpId = trim((string) $form_state->getValue('rp_id'));
    if (empty($rpId)) {
      $form_state->setErrorByName('rp_id', $this->t('Relying Party ID is required.'));
    } elseif (!preg_match('/^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$/i', $rpId)) {
      $form_state->setErrorByName('rp_id', $this->t('Relying Party ID must be a valid domain name.'));
    }

    $rpName = trim((string) $form_state->getValue('rp_name'));
    if (empty($rpName)) {
      $form_state->setErrorByName('rp_name', $this->t('Relying Party display name is required.'));
    }

    $originsRaw = trim((string) $form_state->getValue('allowed_origins'));
    if (empty($originsRaw)) {
      $form_state->setErrorByName('allowed_origins', $this->t('At least one allowed origin is required.'));
    } else {
      $origins = array_filter(array_map('trim', explode("\n", $originsRaw)));
      foreach ($origins as $origin) {
        if (!UrlHelper::isValid($origin, absolute: true)) {
          $form_state->setErrorByName(
            'allowed_origins',
            $this->t('"%origin" is not a valid absolute URL origin.', ['%origin' => $origin]),
          );
          break;
        }
        if (!preg_match('#^https?://#i', $origin)) {
          $form_state->setErrorByName(
            'allowed_origins',
            $this->t('"%origin" must use http or https scheme.', ['%origin' => $origin]),
          );
          break;
        }
      }
    }

    $timeout = (int) $form_state->getValue('timeout');
    if ($timeout < 10000 || $timeout > 300000) {
      $form_state->setErrorByName('timeout', $this->t('Timeout must be between 10000 and 300000 milliseconds.'));
    }

    $challengeTtl = (int) $form_state->getValue('challenge_ttl');
    if ($challengeTtl < 30 || $challengeTtl > 600) {
      $form_state->setErrorByName('challenge_ttl', $this->t('Challenge TTL must be between 30 and 600 seconds.'));
    }

    $uv = (string) $form_state->getValue('user_verification');
    if (!in_array($uv, ['required', 'preferred', 'discouraged'], strict: true)) {
      $form_state->setErrorByName('user_verification', $this->t('Invalid user verification value.'));
    }

    $attPolicy = (string) $form_state->getValue('attestation_policy');
    if (!in_array($attPolicy, ['none', 'indirect', 'direct'], strict: true)) {
      $form_state->setErrorByName('attestation_policy', $this->t('Invalid attestation policy.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $originsRaw = (string) $form_state->getValue('allowed_origins');
    $origins = array_values(array_filter(array_map('trim', explode("\n", $originsRaw))));

    $enforceRolesRaw = (array) $form_state->getValue('enforce_for_roles');
    $enforceRoles = array_values(array_filter($enforceRolesRaw));

    $this->config(self::CONFIG_NAME)
      ->set('enabled', (bool) $form_state->getValue('enabled'))
      ->set('rp_id', trim((string) $form_state->getValue('rp_id')))
      ->set('rp_name', trim((string) $form_state->getValue('rp_name')))
      ->set('allowed_origins', $origins)
      ->set('attestation_policy', (string) $form_state->getValue('attestation_policy'))
      ->set('timeout', (int) $form_state->getValue('timeout'))
      ->set('require_resident_key', (bool) $form_state->getValue('require_resident_key'))
      ->set('user_verification', (string) $form_state->getValue('user_verification'))
      ->set('enforce_for_roles', $enforceRoles)
      ->set('allow_password_fallback', (bool) $form_state->getValue('allow_password_fallback'))
      ->set('challenge_ttl', (int) $form_state->getValue('challenge_ttl'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
