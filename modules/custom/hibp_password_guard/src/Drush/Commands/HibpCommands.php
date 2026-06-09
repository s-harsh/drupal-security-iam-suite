<?php

declare(strict_types=1);

namespace Drupal\hibp_password_guard\Drush\Commands;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\hibp_password_guard\Service\HibpPasswordCheckerService;
use Drush\Attributes as CLI;
use Drush\Commands\DrushCommands;
use Drush\Commands\AutowireTrait;

/**
 * Drush 12 command for HIBP password breach checking.
 *
 * Provides the hibp:check-user command which allows administrators to test
 * whether a given user's password (by plaintext) would be flagged as pwned
 * by the HIBP API.
 *
 * Discovery: Drush 12 auto-discovers commandfiles in src/Drush/Commands/
 * when AutowireTrait is used. No drush.services.yml is required.
 */
final class HibpCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * Constructs an HibpCommands instance.
   *
   * @param \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService $checkerService
   *   The HIBP password checker service.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager (used to look up users by name).
   */
  public function __construct(
    private readonly HibpPasswordCheckerService $checkerService,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {
    parent::__construct();
  }

  /**
   * Checks whether a given user's password is in the HIBP breach database.
   *
   * Without --plaintext, this command attempts to load the user by name and
   * warns if the stored hash algorithm cannot be directly compared. With
   * --plaintext, the supplied string is SHA-1 hashed locally and checked.
   *
   * @param string $username
   *   The Drupal username to check.
   */
  #[CLI\Command(name: 'hibp:check-user', aliases: ['hibp-cu'])]
  #[CLI\Argument(name: 'username', description: 'The Drupal username to check.')]
  #[CLI\Option(name: 'plaintext', description: 'Supply a plaintext password to test directly instead of using the stored hash.')]
  #[CLI\Option(name: 'bypass-cache', description: 'Skip the cache and force a fresh API call.')]
  #[CLI\Usage(name: 'drush hibp:check-user admin --plaintext="MyPassword123!"', description: 'Check if the given plaintext password is pwned.')]
  #[CLI\Usage(name: 'drush hibp:check-user editor --bypass-cache', description: 'Check without cache (not possible without --plaintext; shows limitation message).')]
  public function checkUser(
    string $username,
    array $options = ['plaintext' => NULL, 'bypass-cache' => FALSE],
  ): void {
    $plaintext = $options['plaintext'] ?? NULL;
    $bypassCache = (bool) ($options['bypass-cache'] ?? FALSE);

    if ($plaintext === NULL) {
      // Without --plaintext, load the user entity to confirm existence, then
      // explain why a direct hash comparison is not feasible with PHPass.
      $users = $this->entityTypeManager
        ->getStorage('user')
        ->loadByProperties(['name' => $username]);

      if (empty($users)) {
        $this->io()->error(sprintf('User "%s" not found.', $username));
        return;
      }

      $this->io()->warning(sprintf(
        'User "%s" exists. Drupal stores passwords with PHPass (not SHA-1), so direct hash comparison with HIBP is not possible. Use --plaintext="<password>" to test a specific plaintext password.',
        $username,
      ));
      return;
    }

    // With --plaintext: hash locally and check via the HIBP checker service.
    $result = $this->checkerService->check($plaintext, $bypassCache);

    if ($result->apiError) {
      $this->io()->error(sprintf(
        'HIBP API error: %s. Could not complete the check.',
        $result->errorType,
      ));
      return;
    }

    if ($result->isPwned) {
      $this->io()->warning(sprintf(
        '[WARNING] The supplied password for "%s" has been found in %d breach record(s). It should NOT be used.',
        $username,
        $result->breachCount,
      ));
    }
    else {
      $this->io()->success(sprintf(
        '[OK] The supplied password for "%s" was not found in the HIBP breach database.',
        $username,
      ));
    }
  }

}
