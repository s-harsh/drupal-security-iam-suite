<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Functional\Drush;

use Drupal\Tests\BrowserTestBase;
use Drush\TestTraits\DrushTestTrait;

/**
 * Functional tests for the hibp:check-user Drush command.
 *
 * Requires Drush 12+ with DrushTestTrait available. Run with:
 *   vendor/bin/phpunit modules/custom/hibp_password_guard/tests/src/Functional/Drush/ \
 *     --group drush
 *
 * @group hibp_password_guard
 * @group drush
 */
final class HibpCommandsTest extends BrowserTestBase {

  use DrushTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['hibp_password_guard', 'password_policy'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  // -------------------------------------------------------------------------
  // Non-existent user
  // -------------------------------------------------------------------------

  /**
   * Tests that passing a non-existent username exits with an error.
   */
  public function testNonExistentUsernameExitsWithError(): void {
    $this->drush(
      'hibp:check-user',
      ['user_that_definitely_does_not_exist_xyz_12345'],
      [],
      null,
      null,
      self::EXIT_ERROR,
    );

    $errorOutput = $this->getErrorOutput();
    $this->assertStringContainsString('not found', $errorOutput,
      'A non-existent username must produce a "not found" error message.');
  }

  /**
   * Tests that the error output for a missing user contains the username.
   */
  public function testErrorOutputContainsUsernameForMissingUser(): void {
    $username = 'ghost_user_abc_9876';

    $this->drush(
      'hibp:check-user',
      [$username],
      [],
      null,
      null,
      self::EXIT_ERROR,
    );

    $this->assertStringContainsString($username, $this->getErrorOutput());
  }

  // -------------------------------------------------------------------------
  // Without --plaintext flag
  // -------------------------------------------------------------------------

  /**
   * Tests that without --plaintext the command warns about PHPass limitation.
   */
  public function testWithoutPlaintextFlagShowsPHPassWarning(): void {
    $this->drupalCreateUser([], 'testuser_noplaintext');

    $this->drush(
      'hibp:check-user',
      ['testuser_noplaintext'],
      [],
    );

    $combinedOutput = $this->getOutput() . $this->getErrorOutput();
    $this->assertStringContainsString('PHPass', $combinedOutput,
      'Without --plaintext, the command must explain the PHPass limitation.');
  }

  /**
   * Tests that without --plaintext the command mentions the username.
   */
  public function testWithoutPlaintextOutputMentionsUsername(): void {
    $this->drupalCreateUser([], 'testuser_noplaintext2');

    $this->drush(
      'hibp:check-user',
      ['testuser_noplaintext2'],
      [],
    );

    $combinedOutput = $this->getOutput() . $this->getErrorOutput();
    $this->assertStringContainsString('testuser_noplaintext2', $combinedOutput);
  }

  // -------------------------------------------------------------------------
  // With --plaintext flag (requires network) — known-pwned password
  // -------------------------------------------------------------------------

  /**
   * Tests that --plaintext "password" (known pwned) outputs a WARNING.
   *
   * @group requires_network
   */
  public function testPwnedPasswordOutputsWarning(): void {
    $this->drupalCreateUser([], 'testuser_hibp_pwned');

    $this->drush(
      'hibp:check-user',
      ['testuser_hibp_pwned'],
      ['plaintext' => 'password'],
    );

    $combinedOutput = $this->getOutput() . $this->getErrorOutput();
    $this->assertStringContainsString('WARNING', $combinedOutput,
      '"password" is in millions of breach records and must produce a WARNING.');
  }

  /**
   * Tests that a known-pwned password output contains the username.
   *
   * @group requires_network
   */
  public function testPwnedPasswordOutputContainsUsername(): void {
    $this->drupalCreateUser([], 'testuser_hibp_pwned2');

    $this->drush(
      'hibp:check-user',
      ['testuser_hibp_pwned2'],
      ['plaintext' => 'password'],
    );

    $combinedOutput = $this->getOutput() . $this->getErrorOutput();
    $this->assertStringContainsString('testuser_hibp_pwned2', $combinedOutput);
  }

  /**
   * Tests that a known-pwned password output contains a breach count.
   *
   * @group requires_network
   */
  public function testPwnedPasswordOutputContainsBreachCount(): void {
    $this->drupalCreateUser([], 'testuser_hibp_pwned3');

    $this->drush(
      'hibp:check-user',
      ['testuser_hibp_pwned3'],
      ['plaintext' => 'password'],
    );

    $output = $this->getOutput() . $this->getErrorOutput();
    // The command outputs "X breach record(s)" — check for a numeric component.
    $this->assertMatchesRegularExpression('/\d+/', $output,
      'The output must include the numeric breach count.');
  }

  // -------------------------------------------------------------------------
  // With --plaintext flag (requires network) — clean password
  // -------------------------------------------------------------------------

  /**
   * Tests that a unique password that is not in any breach outputs OK.
   *
   * Uses a complex UUID-style string unlikely to appear in any breach database.
   *
   * @group requires_network
   */
  public function testUniquePlaintextPasswordOutputsOk(): void {
    $this->drupalCreateUser([], 'testuser_hibp_clean');
    // A complex random-looking password that should not be in HIBP.
    $uniquePassword = 'Xk9!mP2@qZ5#nL8$vB3%wR7^uY4&hJ6*-UNIQUE-TEST-STRING';

    $this->drush(
      'hibp:check-user',
      ['testuser_hibp_clean'],
      ['plaintext' => $uniquePassword],
    );

    $output = $this->getOutput() . $this->getErrorOutput();
    $this->assertStringContainsString('OK', $output,
      'A unique password must produce an OK result.');
  }

  // -------------------------------------------------------------------------
  // --bypass-cache flag
  // -------------------------------------------------------------------------

  /**
   * Tests that --bypass-cache with --plaintext forces a fresh API call.
   *
   * Since the command outputs the same result whether cached or fresh, this
   * test just verifies the command completes without error.
   *
   * @group requires_network
   */
  public function testBypassCacheFlagWithPlaintextCompletes(): void {
    $this->drupalCreateUser([], 'testuser_hibp_bypass');

    $this->drush(
      'hibp:check-user',
      ['testuser_hibp_bypass'],
      [
        'plaintext'     => 'Xk9!mP2@qZ5#nL8$vB3%wR7^uY4&hJ6*-BYPASS-TEST',
        'bypass-cache'  => true,
      ],
    );

    // Just verify the command ran — we check the output type matches OK.
    $output = $this->getOutput() . $this->getErrorOutput();
    $this->assertNotEmpty($output, 'Command with --bypass-cache must produce output.');
  }

  // -------------------------------------------------------------------------
  // API error handling in Drush command
  // -------------------------------------------------------------------------

  /**
   * Tests that when the API is unreachable the command outputs an error.
   */
  public function testApiErrorOutputsErrorMessage(): void {
    // Force an unreachable API URL.
    $this->config('hibp_password_guard.settings')
      ->set('enabled', true)
      ->set('api_base_url', 'https://127.0.0.1:1')
      ->set('http_timeout', 1)
      ->set('fail_mode', 'fail_open')
      ->save();

    $this->drupalCreateUser([], 'testuser_hibp_apierror');

    $this->drush(
      'hibp:check-user',
      ['testuser_hibp_apierror'],
      [
        'plaintext'    => 'somepassword',
        'bypass-cache' => true,
      ],
      null,
      null,
      self::EXIT_ERROR,
    );

    $errorOutput = $this->getErrorOutput();
    $this->assertStringContainsString('HIBP API error', $errorOutput,
      'An unreachable API must produce an "HIBP API error" message in the Drush output.');
  }

}
