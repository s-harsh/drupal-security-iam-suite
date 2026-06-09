<?php

declare(strict_types=1);

namespace Drupal\hibp_password_guard\Hook;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\Core\Url;
use Drupal\hibp_password_guard\Service\HibpApiClient;

/**
 * OOP hook implementations for the HIBP Password Guard module.
 *
 * Implements hook_requirements (status report) and hook_help via Drupal 11's
 * #[Hook] attribute system. Registered as a tagged service so the hook
 * discovery system finds and invokes the methods automatically.
 */
final class HibpPasswordGuardHooks {

  use StringTranslationTrait;

  /**
   * Cache key used to avoid hammering the HIBP API from the status report.
   */
  private const PROBE_CACHE_KEY = 'hibp_password_guard.requirements_probe';

  /**
   * TTL in seconds for the requirements probe cache entry (5 minutes).
   */
  private const PROBE_CACHE_TTL = 300;

  /**
   * Innocuous HIBP prefix used for the connectivity probe.
   */
  private const PROBE_PREFIX = '00000';

  /**
   * Constructs an HibpPasswordGuardHooks.
   *
   * @param \Drupal\hibp_password_guard\Service\HibpApiClient $apiClient
   *   The HIBP API client (used to probe connectivity in requirements()).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Cache\CacheBackendInterface $defaultCache
   *   The default cache bin used to store the probe result for 5 minutes.
   */
  public function __construct(
    private readonly HibpApiClient $apiClient,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly CacheBackendInterface $defaultCache,
  ) {}

  /**
   * Implements hook_requirements().
   *
   * Probes the HIBP API with an innocuous prefix and reports connectivity
   * on the Drupal Status Report page. Probe results are cached for 5 minutes
   * to prevent excessive outbound requests on repeated page loads.
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

    // Return cached probe result if still valid.
    $cached = $this->defaultCache->get(self::PROBE_CACHE_KEY);
    if ($cached !== FALSE) {
      return $cached->data;
    }

    $requirements = $this->probeApiConnectivity();

    $this->defaultCache->set(
      self::PROBE_CACHE_KEY,
      $requirements,
      time() + self::PROBE_CACHE_TTL,
    );

    return $requirements;
  }

  /**
   * Implements hook_help().
   *
   * Returns a render array with module description and relevant links when
   * the user visits the module help page.
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
    if ($route_name !== 'help.page.hibp_password_guard') {
      return '';
    }

    $settingsUrl = Url::fromRoute('hibp_password_guard.settings')->toString();

    $output = '<h2>' . $this->t('HIBP Password Guard') . '</h2>';
    $output .= '<p>' . $this->t(
      'HIBP Password Guard integrates with the <a href=":hibp_url">Have I Been Pwned</a> Pwned Passwords API to prevent users from choosing passwords that have appeared in known data breaches. The check uses a k-anonymity model: only the first 5 hexadecimal characters of the password\'s SHA-1 hash are sent to the API, preserving full privacy while still detecting compromised passwords.',
      [':hibp_url' => 'https://haveibeenpwned.com/Passwords'],
    ) . '</p>';
    $output .= '<p>' . $this->t(
      'The module provides a <em>Not Pwned Password</em> constraint plugin for the <a href=":pp_url">Password Policy</a> module. Add the constraint to any password policy to enforce breach checking for the users that policy applies to.',
      [':pp_url' => 'https://www.drupal.org/project/password_policy'],
    ) . '</p>';
    $output .= '<p>' . $this->t(
      'Configure the module at <a href=":settings_url">HIBP Password Guard Settings</a>. Options include cache TTL, degradation mode (fail open or fail closed), HTTP timeout, and the API base URL.',
      [':settings_url' => $settingsUrl],
    ) . '</p>';

    return [
      '#markup' => $output,
      '#allowed_tags' => ['h2', 'p', 'em', 'a'],
    ];
  }

  /**
   * Probes the HIBP API and returns a requirements array entry.
   *
   * @return array<string, array<string, mixed>>
   *   Requirements array with a single 'hibp_password_guard' key.
   */
  private function probeApiConnectivity(): array {
    $response = $this->apiClient->fetchRange(self::PROBE_PREFIX);

    if ($response->success) {
      return [
        'hibp_password_guard' => [
          'title' => $this->t('HIBP Pwned Passwords API'),
          'value' => $this->t('Reachable'),
          'description' => $this->t('The Have I Been Pwned Pwned Passwords API is accessible and returned a successful response.'),
          'severity' => REQUIREMENT_OK,
        ],
      ];
    }

    if ($response->statusCode > 0) {
      // Non-200 HTTP response: warning.
      return [
        'hibp_password_guard' => [
          'title' => $this->t('HIBP Pwned Passwords API'),
          'value' => $this->t('Warning: HTTP @status', ['@status' => $response->statusCode]),
          'description' => $this->t(
            'The Have I Been Pwned API returned an unexpected HTTP status code (@status). Password breach checks may not function correctly.',
            ['@status' => $response->statusCode],
          ),
          'severity' => REQUIREMENT_WARNING,
        ],
      ];
    }

    // statusCode == 0 means a connection-level failure.
    return [
      'hibp_password_guard' => [
        'title' => $this->t('HIBP Pwned Passwords API'),
        'value' => $this->t('Error: unreachable'),
        'description' => $this->t(
          'Could not connect to the Have I Been Pwned API (@error). Check outbound HTTPS connectivity and the configured API base URL.',
          ['@error' => $response->errorMessage],
        ),
        'severity' => REQUIREMENT_ERROR,
      ],
    ];
  }

}
