<?php

declare(strict_types=1);

namespace Drupal\Tests\passkey_forge\Unit\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\passkey_forge\Service\AttestationValidator;
use Drupal\passkey_forge\Value\AttestationPolicy;
use Drupal\Tests\UnitTestCase;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for AttestationValidator.
 *
 * @coversDefaultClass \Drupal\passkey_forge\Service\AttestationValidator
 * @group passkey_forge
 */
final class AttestationValidatorTest extends UnitTestCase {

  /**
   * Creates an AttestationValidator wired to a given policy string.
   *
   * @param string $policy
   *   One of 'none', 'indirect', 'direct'.
   *
   * @return \Drupal\passkey_forge\Service\AttestationValidator
   */
  private function buildValidator(string $policy): AttestationValidator {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')
      ->with('attestation_policy')
      ->willReturn($policy);

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')
      ->with('passkey_forge.settings')
      ->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);

    return new AttestationValidator($configFactory, $logger);
  }

  // -------------------------------------------------------------------------
  // getConfiguredPolicy
  // -------------------------------------------------------------------------

  /**
   * @covers ::getConfiguredPolicy
   */
  public function testGetConfiguredPolicyReturnsNone(): void {
    $validator = $this->buildValidator('none');
    $this->assertSame(AttestationPolicy::None, $validator->getConfiguredPolicy());
  }

  /**
   * @covers ::getConfiguredPolicy
   */
  public function testGetConfiguredPolicyReturnsIndirect(): void {
    $validator = $this->buildValidator('indirect');
    $this->assertSame(AttestationPolicy::Indirect, $validator->getConfiguredPolicy());
  }

  /**
   * @covers ::getConfiguredPolicy
   */
  public function testGetConfiguredPolicyReturnsDirect(): void {
    $validator = $this->buildValidator('direct');
    $this->assertSame(AttestationPolicy::Direct, $validator->getConfiguredPolicy());
  }

  /**
   * @covers ::getConfiguredPolicy
   */
  public function testGetConfiguredPolicyDefaultsToNoneForUnknown(): void {
    $validator = $this->buildValidator('foobar');
    $this->assertSame(AttestationPolicy::None, $validator->getConfiguredPolicy());
  }

  // -------------------------------------------------------------------------
  // Policy: none
  // -------------------------------------------------------------------------

  /**
   * @covers ::validate
   */
  public function testNonePolicyAcceptsNoneFormat(): void {
    $validator = $this->buildValidator('none');
    $this->assertTrue($validator->validate('none', []));
  }

  /**
   * @covers ::validate
   */
  public function testNonePolicyAcceptsPackedFormat(): void {
    $validator = $this->buildValidator('none');
    $this->assertTrue($validator->validate('packed', ['---cert---']));
  }

  /**
   * @covers ::validate
   */
  public function testNonePolicyAcceptsAnyFormat(): void {
    $validator = $this->buildValidator('none');
    $this->assertTrue($validator->validate('tpm', []));
    $this->assertTrue($validator->validate('android-key', []));
    $this->assertTrue($validator->validate('fido-u2f', []));
  }

  // -------------------------------------------------------------------------
  // Policy: indirect
  // -------------------------------------------------------------------------

  /**
   * @covers ::validate
   */
  public function testIndirectPolicyRejectsBareNoneFormat(): void {
    $validator = $this->buildValidator('indirect');
    $this->assertFalse($validator->validate('none', []));
  }

  /**
   * @covers ::validate
   */
  public function testIndirectPolicyAcceptsPackedFormat(): void {
    $validator = $this->buildValidator('indirect');
    $this->assertTrue($validator->validate('packed', []));
  }

  /**
   * @covers ::validate
   */
  public function testIndirectPolicyAcceptsTpmFormat(): void {
    $validator = $this->buildValidator('indirect');
    $this->assertTrue($validator->validate('tpm', ['---cert---']));
  }

  /**
   * @covers ::validate
   */
  public function testIndirectPolicyAcceptsAndroidKeyFormat(): void {
    $validator = $this->buildValidator('indirect');
    $this->assertTrue($validator->validate('android-key', []));
  }

  /**
   * @covers ::validate
   */
  public function testIndirectPolicyAcceptsAppleFormat(): void {
    $validator = $this->buildValidator('indirect');
    $this->assertTrue($validator->validate('apple', ['---cert---']));
  }

  // -------------------------------------------------------------------------
  // Policy: direct
  // -------------------------------------------------------------------------

  /**
   * @covers ::validate
   */
  public function testDirectPolicyRejectsNoneFormat(): void {
    $validator = $this->buildValidator('direct');
    $this->assertFalse($validator->validate('none', []));
  }

  /**
   * @covers ::validate
   */
  public function testDirectPolicyRejectsPackedWithoutCertChain(): void {
    $validator = $this->buildValidator('direct');
    $this->assertFalse($validator->validate('packed', []));
  }

  /**
   * @covers ::validate
   */
  public function testDirectPolicyAcceptsPackedWithCertChain(): void {
    $validator = $this->buildValidator('direct');
    $this->assertTrue($validator->validate('packed', ['---pem-cert---']));
  }

  /**
   * @covers ::validate
   */
  public function testDirectPolicyAcceptsTpmWithCertChain(): void {
    $validator = $this->buildValidator('direct');
    $this->assertTrue($validator->validate('tpm', ['---cert1---', '---cert2---']));
  }

  /**
   * @covers ::validate
   */
  public function testDirectPolicyRejectsUnknownFormatEvenWithCert(): void {
    $validator = $this->buildValidator('direct');
    $this->assertFalse($validator->validate('unknown-format', ['---cert---']));
  }

  /**
   * @covers ::validate
   */
  public function testDirectPolicyAcceptsFidoU2fWithCert(): void {
    $validator = $this->buildValidator('direct');
    $this->assertTrue($validator->validate('fido-u2f', ['---cert---']));
  }

  /**
   * @covers ::validate
   */
  public function testDirectPolicyAcceptsAndroidSafetynetWithCert(): void {
    $validator = $this->buildValidator('direct');
    $this->assertTrue($validator->validate('android-safetynet', ['---cert---']));
  }

  // -------------------------------------------------------------------------
  // Role override
  // -------------------------------------------------------------------------

  /**
   * @covers ::validate
   */
  public function testRoleOverrideDirectSupersitesPolicyNone(): void {
    // Site policy is 'none' but override is 'direct'.
    $validator = $this->buildValidator('none');
    // 'packed' with cert chain should pass under 'direct'.
    $this->assertTrue($validator->validate('packed', ['---cert---'], 'direct'));
  }

  /**
   * @covers ::validate
   */
  public function testRoleOverrideNoneAcceptsEverything(): void {
    // Site policy is 'direct' but override is 'none'.
    $validator = $this->buildValidator('direct');
    $this->assertTrue($validator->validate('none', [], 'none'));
  }

  /**
   * @covers ::validate
   */
  public function testRoleOverrideIndirectRejectsBareNone(): void {
    $validator = $this->buildValidator('none');
    $this->assertFalse($validator->validate('none', [], 'indirect'));
  }

  /**
   * @covers ::validate
   */
  public function testRoleOverrideInvalidStringDefaultsToNone(): void {
    $validator = $this->buildValidator('direct');
    // Unknown override → treated as 'none' → accepts everything.
    $this->assertTrue($validator->validate('none', [], 'invalid-policy-string'));
  }

  // -------------------------------------------------------------------------
  // getPolicyOptions
  // -------------------------------------------------------------------------

  /**
   * @covers ::getPolicyOptions
   */
  public function testGetPolicyOptionsReturnsThreeEntries(): void {
    $validator = $this->buildValidator('none');
    $options = $validator->getPolicyOptions();
    $this->assertCount(3, $options);
  }

  /**
   * @covers ::getPolicyOptions
   */
  public function testGetPolicyOptionsContainsAllPolicies(): void {
    $validator = $this->buildValidator('none');
    $options = $validator->getPolicyOptions();
    $this->assertArrayHasKey('none', $options);
    $this->assertArrayHasKey('indirect', $options);
    $this->assertArrayHasKey('direct', $options);
  }

  /**
   * @covers ::getPolicyOptions
   */
  public function testGetPolicyOptionsValuesAreNonEmptyStrings(): void {
    $validator = $this->buildValidator('none');
    foreach ($validator->getPolicyOptions() as $key => $label) {
      $this->assertNotEmpty($label, "Label for policy '{$key}' must not be empty.");
    }
  }

}
