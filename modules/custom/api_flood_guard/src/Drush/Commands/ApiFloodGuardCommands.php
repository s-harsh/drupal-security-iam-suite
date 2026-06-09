<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Drush\Commands;

use Drupal\api_flood_guard\Plugin\Manager\IpReputationManager;
use Drupal\api_flood_guard\Service\ApiFloodManager;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Flood\FloodInterface;
use Drush\Attributes as CLI;
use Drush\Commands\DrushCommands;

/**
 * Drush commands for API Flood Guard.
 *
 * Provides status, clear, allowlist-add, and test-ip commands for use in
 * automated runbooks and incident response scripts.
 */
final class ApiFloodGuardCommands extends DrushCommands {

  public function __construct(
    private readonly FloodInterface $flood,
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ApiFloodManager $floodManager,
    private readonly IpReputationManager $reputationManager,
  ) {
    parent::__construct();
  }

  /**
   * Shows the current count of active API flood entries by namespace.
   */
  #[CLI\Command(name: 'api-flood-guard:status', aliases: ['afg:status'])]
  #[CLI\Usage(name: 'drush api-flood-guard:status', description: 'Show active API flood entry counts.')]
  public function status(): void {
    $now = time();

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

    $this->io()->table(
      ['Namespace', 'Active Entries'],
      [
        ['api_flood_guard.ip', $ipCount],
        ['api_flood_guard.user', $userCount],
        ['Total', $ipCount + $userCount],
      ]
    );
  }

  /**
   * Clears API flood entries matching the specified filters.
   */
  #[CLI\Command(name: 'api-flood-guard:clear', aliases: ['afg:clear'])]
  #[CLI\Option(name: 'ip', description: 'Clear flood entries for this specific IP address.')]
  #[CLI\Option(name: 'user', description: 'Clear flood entries for this specific username.')]
  #[CLI\Option(name: 'all', description: 'Clear all API flood entries.')]
  #[CLI\Usage(name: 'drush api-flood-guard:clear --all', description: 'Clear all API flood entries.')]
  #[CLI\Usage(name: 'drush api-flood-guard:clear --ip=192.168.1.1', description: 'Clear flood entries for a specific IP.')]
  #[CLI\Usage(name: 'drush api-flood-guard:clear --user=admin', description: 'Clear flood entries for a specific username.')]
  public function clear(array $options = ['ip' => NULL, 'user' => NULL, 'all' => FALSE]): void {
    $ip = $options['ip'];
    $user = $options['user'];
    $all = (bool) $options['all'];

    if ($all) {
      $deleted = $this->database->delete('flood')
        ->condition('event', 'api_flood_guard.%', 'LIKE')
        ->execute();
      $this->io()->success("Cleared all API flood entries ($deleted rows deleted).");
      return;
    }

    if ($ip !== NULL) {
      $this->flood->clear('api_flood_guard.ip', $ip);
      $this->io()->success("Cleared IP flood entries for $ip.");
    }

    if ($user !== NULL) {
      $hashedUser = hash('sha256', strtolower(trim($user)));
      $this->flood->clear('api_flood_guard.user', $hashedUser);
      $this->io()->success("Cleared username flood entries for '$user'.");
    }

    if ($ip === NULL && $user === NULL && !$all) {
      $this->io()->error('Specify --ip=<ip>, --user=<name>, or --all.');
    }
  }

  /**
   * Adds a CIDR range to the API Flood Guard IP allowlist.
   */
  #[CLI\Command(name: 'api-flood-guard:allowlist-add', aliases: ['afg:allowlist-add'])]
  #[CLI\Argument(name: 'cidr', description: 'CIDR range or IP address to add to the allowlist (e.g. 10.0.0.0/8 or 192.168.1.5).')]
  #[CLI\Usage(name: 'drush api-flood-guard:allowlist-add 10.0.0.0/8', description: 'Add 10.0.0.0/8 to the allowlist.')]
  public function allowlistAdd(string $cidr): void {
    $cidr = trim($cidr);
    $ip = str_contains($cidr, '/') ? explode('/', $cidr, 2)[0] : $cidr;

    if (@inet_pton($ip) === FALSE) {
      $this->io()->error("'$cidr' is not a valid IP address or CIDR range.");
      return;
    }

    $config = $this->configFactory->getEditable('api_flood_guard.settings');
    $allowlist = $config->get('allowlist') ?? [];

    if (in_array($cidr, $allowlist, TRUE)) {
      $this->io()->note("'$cidr' is already in the allowlist.");
      return;
    }

    $allowlist[] = $cidr;
    $config->set('allowlist', $allowlist)->save();
    $this->io()->success("Added '$cidr' to the API Flood Guard allowlist.");
  }

  /**
   * Tests a given IP against the configured IP reputation provider.
   */
  #[CLI\Command(name: 'api-flood-guard:test-ip', aliases: ['afg:test-ip'])]
  #[CLI\Argument(name: 'ip', description: 'The IP address to test against the reputation provider.')]
  #[CLI\Usage(name: 'drush api-flood-guard:test-ip 1.2.3.4', description: 'Check IP 1.2.3.4 against the configured reputation provider.')]
  public function testIp(string $ip): void {
    $config = $this->configFactory->get('api_flood_guard.settings');
    $enabledProvider = (string) ($config->get('reputation_providers.enabled_provider') ?? '');

    if ($enabledProvider === '' || $enabledProvider === 'null_provider') {
      $this->io()->note('Reputation check disabled. IP would pass to flood checks.');
      return;
    }

    try {
      $plugin = $this->reputationManager->createInstance($enabledProvider);

      if (!$plugin->isConfigured()) {
        $this->io()->note("Provider '$enabledProvider' is not configured (missing API key or credentials). IP would pass to flood checks.");
        return;
      }

      $result = $plugin->checkIp($ip);

      if ($result->providerError) {
        $this->io()->warning('Provider returned an error (fail-open). IP would be allowed through.');
        return;
      }

      if ($result->isBlocked) {
        $this->io()->error("BLOCKED (score: {$result->confidenceScore}, provider: {$result->providerName}, from_cache: " . ($result->fromCache ? 'yes' : 'no') . ')');
      }
      else {
        $this->io()->success("ALLOWED (score: {$result->confidenceScore}, provider: {$result->providerName}, from_cache: " . ($result->fromCache ? 'yes' : 'no') . ')');
      }
    }
    catch (\Exception $e) {
      $this->io()->error("Failed to instantiate provider '$enabledProvider': " . $e->getMessage());
    }
  }

}
