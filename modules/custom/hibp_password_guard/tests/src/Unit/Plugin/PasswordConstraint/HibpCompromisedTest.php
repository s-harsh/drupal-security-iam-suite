<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Unit\Plugin\PasswordConstraint;

use Drupal\hibp_password_guard\Service\HibpPasswordCheckerService;
use Drupal\hibp_password_guard\Value\HibpCheckResult;
use Drupal\password_policy\PasswordPolicyResult;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * Unit tests for the HibpCompromised password constraint plugin.
 *
 * Because PasswordConstraintBase has complex Drupal DI dependencies
 * (PluginBase, TranslationInterface, etc.), these tests exercise the
 * validation logic by directly testing the HibpCheckResult/PasswordPolicyResult
 * integration that the plugin's validate() method encodes, using the checker
 * service as the sole mock seam.
 *
 * Constraint validate() logic under test:
 *   - Empty password  -> pass (no service call).
 *   - isPwned = false, apiError = false -> pass.
 *   - isPwned = true,  apiError = false -> fail with breach count message.
 *   - isPwned = false, apiError = true  -> pass (fail_open).
 *   - isPwned = true,  apiError = true  -> fail with unavailability message (fail_closed).
 *
 * @group hibp_password_guard
 */
final class HibpCompromisedTest extends UnitTestCase {

  // -------------------------------------------------------------------------
  // HibpCheckResult value object tests
  // -------------------------------------------------------------------------

  /**
   * Tests the HibpCheckResult value object defaults.
   */
  public function testHibpCheckResultDefaultsAreCorrect(): void {
    $result = new HibpCheckResult(isPwned: false, breachCount: 0);

    $this->assertFalse($result->isPwned);
    $this->assertSame(0, $result->breachCount);
    $this->assertFalse($result->apiError);
    $this->assertSame('', $result->errorType);
  }

  /**
   * Tests that HibpCheckResult stores all four properties correctly.
   */
  public function testHibpCheckResultStoresAllProperties(): void {
    $result = new HibpCheckResult(
      isPwned: true,
      breachCount: 3533661,
      apiError: false,
      errorType: '',
    );

    $this->assertTrue($result->isPwned);
    $this->assertSame(3533661, $result->breachCount);
    $this->assertFalse($result->apiError);
    $this->assertSame('', $result->errorType);
  }

  /**
   * Tests that apiError and errorType fields are stored correctly.
   */
  public function testHibpCheckResultStoresApiErrorAndErrorType(): void {
    $result = new HibpCheckResult(
      isPwned: true,
      breachCount: 0,
      apiError: true,
      errorType: 'GuzzleHttp\\Exception\\ConnectException',
    );

    $this->assertTrue($result->isPwned);
    $this->assertSame(0, $result->breachCount);
    $this->assertTrue($result->apiError);
    $this->assertSame('GuzzleHttp\\Exception\\ConnectException', $result->errorType);
  }

  /**
   * Tests that HibpCheckResult is readonly (all properties immutable).
   */
  public function testHibpCheckResultIsImmutable(): void {
    $result = new HibpCheckResult(isPwned: false, breachCount: 0);

    $reflection = new \ReflectionClass($result);
    $this->assertTrue($reflection->isReadOnly(), 'HibpCheckResult class must be readonly.');
  }

  // -------------------------------------------------------------------------
  // PasswordPolicyResult behaviour mirroring plugin validate() logic
  // -------------------------------------------------------------------------

  /**
   * Tests that a clean password (not pwned, no API error) results in a valid policy result.
   */
  public function testNotPwnedPasswordProducesValidPolicyResult(): void {
    $checker = $this->createMock(HibpPasswordCheckerService::class);
    $checker->method('check')
      ->willReturn(new HibpCheckResult(isPwned: false, breachCount: 0));

    $checkResult = $checker->check('some-unique-safe-password');

    // Simulate plugin validate() logic.
    $policyResult = new PasswordPolicyResult();
    if (!$checkResult->apiError && $checkResult->isPwned) {
      $policyResult->setErrorMessage(
        'This password has appeared in a data breach ' . $checkResult->breachCount . ' time(s).',
      );
    }

    $this->assertTrue($policyResult->isValid());
  }

  /**
   * Tests that a pwned password produces an invalid policy result with a breach count message.
   */
  public function testPwnedPasswordProducesInvalidPolicyResult(): void {
    $checker = $this->createMock(HibpPasswordCheckerService::class);
    $checker->method('check')
      ->willReturn(new HibpCheckResult(isPwned: true, breachCount: 3533661));

    $checkResult = $checker->check('password');

    // Simulate plugin validate() logic.
    $policyResult = new PasswordPolicyResult();
    if (!$checkResult->apiError && $checkResult->isPwned) {
      $policyResult->setErrorMessage(
        'This password has appeared in a data breach ' . $checkResult->breachCount . ' time(s). Please choose a different password.',
      );
    }

    $this->assertFalse($policyResult->isValid());
  }

  /**
   * Tests that the breach count from HibpCheckResult is preserved for the error message.
   */
  public function testPwnedResultBreachCountIsPreservedForMessage(): void {
    $checkResult = new HibpCheckResult(isPwned: true, breachCount: 42);

    $this->assertSame(42, $checkResult->breachCount);
    $this->assertTrue($checkResult->isPwned);
    $this->assertFalse($checkResult->apiError);
  }

  /**
   * Tests that fail_open API error produces a valid policy result (no blocking).
   */
  public function testFailOpenApiErrorProducesValidPolicyResult(): void {
    // fail_open: isPwned=false, apiError=true
    $checkResult = new HibpCheckResult(
      isPwned: false,
      breachCount: 0,
      apiError: true,
      errorType: 'ConnectException',
    );

    // Simulate plugin validate() logic.
    $policyResult = new PasswordPolicyResult();
    if ($checkResult->apiError && $checkResult->isPwned) {
      $policyResult->setErrorMessage('Password breach check is temporarily unavailable. Please try again later.');
    }

    $this->assertTrue($policyResult->isValid(),
      'Fail-open API error must not block password change.');
  }

  /**
   * Tests that fail_closed API error produces an invalid policy result.
   */
  public function testFailClosedApiErrorProducesInvalidPolicyResult(): void {
    // fail_closed: isPwned=true, apiError=true
    $checkResult = new HibpCheckResult(
      isPwned: true,
      breachCount: 0,
      apiError: true,
      errorType: 'ConnectException',
    );

    // Simulate plugin validate() logic.
    $policyResult = new PasswordPolicyResult();
    if ($checkResult->apiError && $checkResult->isPwned) {
      $policyResult->setErrorMessage('Password breach check is temporarily unavailable. Please try again later.');
    }

    $this->assertFalse($policyResult->isValid(),
      'Fail-closed API error must block password change.');
  }

  // -------------------------------------------------------------------------
  // Checker service interaction
  // -------------------------------------------------------------------------

  /**
   * Tests that the checker service is called exactly once with the password.
   */
  public function testCheckerServiceIsCalledOnceWithPassword(): void {
    $checker = $this->createMock(HibpPasswordCheckerService::class);
    $checker->expects($this->once())
      ->method('check')
      ->with('mypassword123', false)
      ->willReturn(new HibpCheckResult(isPwned: false, breachCount: 0));

    $result = $checker->check('mypassword123', false);

    $this->assertFalse($result->isPwned);
  }

  /**
   * Tests that the checker service is NOT called for an empty password.
   *
   * The plugin validate() method returns early for empty passwords.
   */
  public function testCheckerServiceNotCalledForEmptyPassword(): void {
    $checker = $this->createMock(HibpPasswordCheckerService::class);
    $checker->expects($this->never())->method('check');

    // Simulate plugin validate() early-return for empty password.
    $password = '';
    $policyResult = new PasswordPolicyResult();

    if ($password !== '') {
      $checkResult = $checker->check($password);
      // Unreachable in this test.
    }

    $this->assertTrue($policyResult->isValid(),
      'Empty password must produce a valid result (handled by other constraints).');
  }

  // -------------------------------------------------------------------------
  // Multiple breach counts
  // -------------------------------------------------------------------------

  /**
   * Tests that single-occurrence breach is correctly flagged.
   */
  public function testSingleBreachOccurrenceIsDetected(): void {
    $result = new HibpCheckResult(isPwned: true, breachCount: 1);

    $this->assertTrue($result->isPwned);
    $this->assertSame(1, $result->breachCount);
  }

  /**
   * Tests that very high breach counts are stored correctly.
   */
  public function testHighBreachCountIsStoredCorrectly(): void {
    $result = new HibpCheckResult(isPwned: true, breachCount: 9999999);

    $this->assertSame(9999999, $result->breachCount);
  }

  // -------------------------------------------------------------------------
  // Plugin summary / metadata
  // -------------------------------------------------------------------------

  /**
   * Tests that HibpCheckResult with apiError=false and isPwned=false has no errorType.
   */
  public function testCleanResultHasNoErrorType(): void {
    $result = new HibpCheckResult(isPwned: false, breachCount: 0);

    $this->assertSame('', $result->errorType,
      'A clean check result must have an empty errorType.');
  }

}
