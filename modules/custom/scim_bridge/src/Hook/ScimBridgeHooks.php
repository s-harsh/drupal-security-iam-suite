<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;

/**
 * OOP hook implementations for the SCIM Bridge module.
 *
 * Implements hook_help and hook_requirements via Drupal 11's #[Hook] attribute
 * system. Registered as a tagged service so the hook discovery system finds
 * and invokes the methods automatically.
 */
final class ScimBridgeHooks {

  use StringTranslationTrait;

  /**
   * Constructs a ScimBridgeHooks instance.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * Implements hook_help().
   *
   * Returns a render array describing the module when the user visits the help
   * page for scim_bridge.
   *
   * @param string $route_name
   *   The current route name.
   * @param \Drupal\Core\Routing\RouteMatchInterface $route_match
   *   The current route match object.
   *
   * @return string|array<mixed>
   *   A render array or empty string.
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): string|array {
    if ($route_name !== 'help.page.scim_bridge') {
      return '';
    }

    $settingsUrl = Url::fromRoute('scim_bridge.settings')->toString();
    $mappingUrl  = Url::fromRoute('scim_bridge.mapping')->toString();

    $output  = '<h2>' . $this->t('SCIM Bridge') . '</h2>';
    $output .= '<p>' . $this->t(
      'SCIM Bridge exposes an <a href=":rfc">RFC 7644 SCIM 2.0</a> server that allows enterprise Identity Providers such as Okta, Azure Active Directory, and Google Workspace to provision, update, and deprovision Drupal user accounts and roles automatically.',
      [':rfc' => 'https://datatracker.ietf.org/doc/html/rfc7644'],
    ) . '</p>';
    $output .= '<h3>' . $this->t('Endpoints') . '</h3>';
    $output .= '<ul>';
    $output .= '<li><code>/scim/v2/Users</code> — ' . $this->t('List, create, update, patch, and delete user accounts.') . '</li>';
    $output .= '<li><code>/scim/v2/Groups</code> — ' . $this->t('Map SCIM groups to Drupal roles.') . '</li>';
    $output .= '<li><code>/scim/v2/ServiceProviderConfig</code> — ' . $this->t('Advertise supported SCIM features.') . '</li>';
    $output .= '<li><code>/scim/v2/Schemas</code> — ' . $this->t('Return the SCIM schema definitions.') . '</li>';
    $output .= '</ul>';
    $output .= '<h3>' . $this->t('Configuration') . '</h3>';
    $output .= '<p>' . $this->t(
      'Add Bearer tokens for each IdP at <a href=":settings_url">SCIM Bridge Settings</a>. Configure attribute mapping at <a href=":mapping_url">SCIM Attribute Mapping</a>.',
      [':settings_url' => $settingsUrl, ':mapping_url' => $mappingUrl],
    ) . '</p>';

    return [
      '#markup' => $output,
      '#allowed_tags' => ['h2', 'h3', 'p', 'ul', 'li', 'em', 'a', 'code'],
    ];
  }

  /**
   * Implements hook_requirements().
   *
   * Reports whether the module is active and at least one IdP token is
   * configured on the Drupal Status Report page.
   *
   * @param string $phase
   *   The phase: 'install', 'update', or 'runtime'.
   *
   * @return array<string, array<string, mixed>>
   *   Requirements array keyed by requirement name.
   */
  #[Hook('requirements')]
  public function requirements(string $phase): array {
    if ($phase !== 'runtime') {
      return [];
    }

    $config  = $this->configFactory->get('scim_bridge.settings');
    $enabled = (bool) $config->get('enabled');
    $tokens  = (array) ($config->get('idp_tokens') ?? []);

    $activeTokens = array_filter(
      $tokens,
      static fn(mixed $t): bool => is_array($t) && !empty($t['enabled']),
    );

    if (!$enabled) {
      return [
        'scim_bridge' => [
          'title'    => $this->t('SCIM Bridge'),
          'value'    => $this->t('Disabled'),
          'description' => $this->t('SCIM Bridge is installed but the module is currently disabled in settings.'),
          'severity' => REQUIREMENT_WARNING,
        ],
      ];
    }

    if (empty($activeTokens)) {
      return [
        'scim_bridge' => [
          'title'    => $this->t('SCIM Bridge'),
          'value'    => $this->t('No active IdP tokens'),
          'description' => $this->t('SCIM Bridge is enabled but no active Bearer tokens are configured. All SCIM requests will be rejected with HTTP 401.'),
          'severity' => REQUIREMENT_WARNING,
        ],
      ];
    }

    return [
      'scim_bridge' => [
        'title'    => $this->t('SCIM Bridge'),
        'value'    => $this->t('Active (@count token(s))', ['@count' => count($activeTokens)]),
        'description' => $this->t('SCIM 2.0 endpoints are active and accepting requests.'),
        'severity' => REQUIREMENT_OK,
      ],
    ];
  }

}
