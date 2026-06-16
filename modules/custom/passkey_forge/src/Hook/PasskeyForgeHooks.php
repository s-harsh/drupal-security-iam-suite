<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\passkey_forge\Service\PasskeyStorage;
use Drupal\user\UserInterface;

/**
 * OOP hook implementations for the Passkey Forge module.
 *
 * Implements hook_user_login, hook_user_delete, hook_requirements, and
 * hook_help via Drupal 11's #[Hook] attribute system. Registered as a tagged
 * service so the hook discovery system finds and invokes the methods.
 */
final class PasskeyForgeHooks {

  use StringTranslationTrait;

  /**
   * Constructs a PasskeyForgeHooks.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\passkey_forge\Service\PasskeyStorage $storage
   *   The passkey credential storage service.
   * @param \Drupal\Core\Session\AccountInterface $currentUser
   *   The currently authenticated user (for access checks in hooks).
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly PasskeyStorage $storage,
    private readonly AccountInterface $currentUser,
  ) {}

  /**
   * Implements hook_user_login().
   *
   * Enforces per-role passkey requirements. If a role is in the
   * 'enforce_for_roles' list and the logging-in user has no registered passkey,
   * the login is allowed to proceed but a warning is displayed directing the
   * user to register a passkey. In a future enhancement this hook can redirect
   * the user to the registration flow instead.
   *
   * @param \Drupal\user\UserInterface $account
   *   The user that just logged in.
   */
  #[Hook('user_login')]
  public function userLogin(UserInterface $account): void {
    $config = $this->configFactory->get('passkey_forge.settings');

    if (!(bool) $config->get('enabled')) {
      return;
    }

    $enforceForRoles = (array) $config->get('enforce_for_roles');
    if (empty($enforceForRoles)) {
      return;
    }

    $userRoles = $account->getRoles();
    $isEnforced = (bool) array_intersect($enforceForRoles, $userRoles);

    if (!$isEnforced) {
      return;
    }

    if (!$this->storage->userHasPasskey((int) $account->id())) {
      \Drupal::messenger()->addWarning($this->t(
        'Your role requires passkey authentication. Please <a href=":url">register a passkey</a> to secure your account.',
        [':url' => Url::fromRoute('passkey_forge.register', ['user' => $account->id()])->toString()],
      ));
    }
  }

  /**
   * Implements hook_user_delete().
   *
   * Removes all registered passkeys for a user when their account is deleted.
   *
   * @param \Drupal\user\UserInterface $account
   *   The user account being deleted.
   */
  #[Hook('user_delete')]
  public function userDelete(UserInterface $account): void {
    $this->storage->deleteByUid((int) $account->id());
  }

  /**
   * Implements hook_requirements().
   *
   * Reports the module status and configuration validity on the Drupal status
   * report page. Checks that the RP ID is configured and that the webauthn-lib
   * dependency is available.
   *
   * @param string $phase
   *   The requirements phase: 'install', 'update', or 'runtime'.
   *
   * @return array<string, array<string, mixed>>
   *   Requirements array keyed by requirement name.
   */
  #[Hook('requirements')]
  public function requirements(string $phase): array {
    if ($phase !== 'runtime') {
      return [];
    }

    $requirements = [];
    $config = $this->configFactory->get('passkey_forge.settings');

    // Check RP ID is configured.
    $rpId = (string) $config->get('rp_id');
    if (empty($rpId) || $rpId === 'example.com') {
      $requirements['passkey_forge_rp_id'] = [
        'title' => $this->t('Passkey Forge: Relying Party ID'),
        'value' => $this->t('Not configured'),
        'description' => $this->t(
          'The Relying Party ID (RP ID) is not configured or is still set to the default "example.com". <a href=":url">Configure it</a> to match your site domain.',
          [':url' => Url::fromRoute('passkey_forge.settings')->toString()],
        ),
        'severity' => REQUIREMENT_WARNING,
      ];
    } else {
      $requirements['passkey_forge_rp_id'] = [
        'title' => $this->t('Passkey Forge: Relying Party ID'),
        'value' => $rpId,
        'severity' => REQUIREMENT_OK,
      ];
    }

    // Check web-auth/webauthn-lib availability.
    $webauthnLibAvailable = class_exists('\Webauthn\PublicKeyCredentialCreationOptions')
      || class_exists('\Webauthn\AuthenticatorAttestationResponse');

    if (!$webauthnLibAvailable) {
      $requirements['passkey_forge_webauthn_lib'] = [
        'title' => $this->t('Passkey Forge: web-auth/webauthn-lib'),
        'value' => $this->t('Not installed'),
        'description' => $this->t(
          'The web-auth/webauthn-lib Composer package is not installed. Run <code>composer require web-auth/webauthn-lib:^4.9</code> in your Drupal root. Passkey registration and authentication will not function without it.',
        ),
        'severity' => REQUIREMENT_ERROR,
      ];
    } else {
      $requirements['passkey_forge_webauthn_lib'] = [
        'title' => $this->t('Passkey Forge: web-auth/webauthn-lib'),
        'value' => $this->t('Installed'),
        'severity' => REQUIREMENT_OK,
      ];
    }

    return $requirements;
  }

  /**
   * Implements hook_help().
   *
   * @param string $route_name
   *   The current route name.
   * @param \Drupal\Core\Routing\RouteMatchInterface $route_match
   *   The current route match.
   *
   * @return string|array<mixed>
   *   A render array or empty string.
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): string|array {
    if ($route_name !== 'help.page.passkey_forge') {
      return '';
    }

    $settingsUrl = Url::fromRoute('passkey_forge.settings')->toString();

    $output = '<h2>' . $this->t('Passkey Forge') . '</h2>';
    $output .= '<p>' . $this->t(
      'Passkey Forge provides enterprise-grade <a href=":webauthn_url">FIDO2/WebAuthn Level 3</a> passkey authentication for Drupal 11. Users can register hardware security keys, platform authenticators (Face ID, Touch ID, Windows Hello), and roaming FIDO2 authenticators as passwordless login methods.',
      [':webauthn_url' => 'https://www.w3.org/TR/webauthn-3/'],
    ) . '</p>';
    $output .= '<h3>' . $this->t('Features') . '</h3>';
    $output .= '<ul>';
    $output .= '<li>' . $this->t('Platform authenticators (Touch ID, Face ID, Windows Hello) and roaming USB/NFC/BLE security keys.') . '</li>';
    $output .= '<li>' . $this->t('Configurable attestation policies: none, indirect, or direct per site or role.') . '</li>';
    $output .= '<li>' . $this->t('Per-role enforcement — require passkeys for privileged roles such as administrator.') . '</li>';
    $output .= '<li>' . $this->t('Graceful password fallback when no passkey is registered.') . '</li>';
    $output .= '<li>' . $this->t('Admin interface to view and revoke individual credentials per user.') . '</li>';
    $output .= '</ul>';
    $output .= '<p>' . $this->t(
      'Configure the Relying Party ID, attestation policy, and role enforcement at <a href=":settings_url">Passkey Forge Settings</a>.',
      [':settings_url' => $settingsUrl],
    ) . '</p>';

    return [
      '#markup' => $output,
      '#allowed_tags' => ['h2', 'h3', 'p', 'ul', 'li', 'em', 'a', 'code'],
    ];
  }

}
