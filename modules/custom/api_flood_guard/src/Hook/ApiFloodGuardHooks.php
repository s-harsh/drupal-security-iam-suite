<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Link;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Psr\Log\LoggerInterface;

/**
 * OOP hook implementations for API Flood Guard.
 *
 * Registered in api_flood_guard.services.yml with the drupal.hook tag.
 */
final class ApiFloodGuardHooks {

  use StringTranslationTrait;

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly Connection $database,
  ) {}

  /**
   * Implements hook_help().
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): string|array {
    if ($route_name !== 'help.page.api_flood_guard') {
      return [];
    }

    $settingsUrl = Url::fromRoute('api_flood_guard.settings');
    $floodStateUrl = Url::fromRoute('api_flood_guard.flood_state');
    $logUrl = Url::fromRoute('api_flood_guard.log');

    $settingsLink = Link::fromTextAndUrl($this->t('API Flood Guard Settings'), $settingsUrl)->toString();
    $floodStateLink = Link::fromTextAndUrl($this->t('Flood State Dashboard'), $floodStateUrl)->toString();
    $logLink = Link::fromTextAndUrl($this->t('Block Events Log'), $logUrl)->toString();

    $output = '<h2>' . $this->t('About') . '</h2>';
    $output .= '<p>' . $this->t('API Flood Guard protects API authentication endpoints — including JSON:API, REST user login, and OAuth token endpoints — against brute-force and credential-stuffing attacks. It applies configurable per-IP and per-username flood controls, supports a CIDR-aware IP allowlist, and integrates with IP reputation providers such as AbuseIPDB via a plugin system.') . '</p>';
    $output .= '<h2>' . $this->t('How it works') . '</h2>';
    $output .= '<p>' . $this->t('A high-priority kernel request event subscriber (priority 300) intercepts requests to protected API paths before routing and authentication run. Each request passes through: allowlist check, IP reputation check, per-IP flood check, per-username flood check, and flood counter registration. Blocked requests receive a 429 (or 503) response with a JSON:API-compatible error body and a Retry-After header.') . '</p>';
    $output .= '<h2>' . $this->t('Administration') . '</h2>';
    $output .= '<ul>';
    $output .= '<li>' . $this->t('@link — Configure protected paths, thresholds, IP allowlist, and reputation provider settings.', ['@link' => $settingsLink]) . '</li>';
    $output .= '<li>' . $this->t('@link — View and clear active flood entries in real time.', ['@link' => $floodStateLink]) . '</li>';
    $output .= '<li>' . $this->t('@link — View structured log entries for recent block events.', ['@link' => $logLink]) . '</li>';
    $output .= '</ul>';

    return [
      '#markup' => $output,
    ];
  }

  /**
   * Implements hook_cache_bin_info().
   */
  #[Hook('cache_bin_info')]
  public function cacheBinInfo(): array {
    return [
      'api_flood_guard' => [
        'label' => $this->t('API Flood Guard IP reputation cache'),
        'description' => $this->t('Caches AbuseIPDB and other reputation provider responses per IP address.'),
      ],
    ];
  }

  /**
   * Implements hook_cron().
   *
   * Logs a monitoring summary of active flood entries and recent block events.
   */
  #[Hook('cron')]
  public function cron(): void {
    // Count active (non-expired) flood entries by namespace.
    $now = \time();

    $ipCount = (int) $this->database->select('flood', 'f')
      ->condition('f.event', 'api_flood_guard.ip')
      ->condition('f.expiration', $now, '>')
      ->countQuery()
      ->execute()
      ->fetchField();

    $userCount = (int) $this->database->select('flood', 'f')
      ->condition('f.event', 'api_flood_guard.user')
      ->condition('f.expiration', $now, '>')
      ->countQuery()
      ->execute()
      ->fetchField();

    // Count watchdog block events in the last 24 hours.
    $yesterday = $now - 86400;
    $blockCount = 0;

    if ($this->database->schema()->tableExists('watchdog')) {
      $blockCount = (int) $this->database->select('watchdog', 'w')
        ->condition('w.type', 'api_flood_guard')
        ->condition('w.severity', 4) // RfcLogLevel::WARNING = 4
        ->condition('w.timestamp', $yesterday, '>')
        ->countQuery()
        ->execute()
        ->fetchField();
    }

    $this->logger->info(
      'API Flood Guard cron summary: @ip_count active IP flood entries, @user_count active username flood entries, @block_count block events in last 24 hours.',
      [
        '@ip_count' => $ipCount,
        '@user_count' => $userCount,
        '@block_count' => $blockCount,
      ]
    );
  }

}
