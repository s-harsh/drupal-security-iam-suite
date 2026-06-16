<?php

declare(strict_types=1);

namespace Drupal\Tests\passkey_forge\Unit\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\passkey_forge\Service\WebAuthnService;
use Drupal\passkey_forge\Value\AttestationPolicy;
use Drupal\passkey_forge\Value\PasskeyCredential;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for WebAuthnService.
 *
 * @coversDefaultClass \Drupal\passkey_forge\Service\WebAuthnService
 * @group passkey_forge
 */
final class WebAuthnServiceTest extends UnitTestCase {

  /**
   * Default RP ID used in test configurations.
   */
  private const RP_ID = 'example.com';

  /**
   * Default allowed origin.
   */
  private const ORIGIN = 'https://example.com';

  /**
   * Builds a WebAuthnService with a configurable mock settings map.
   *
   * @param array<string, mixed> $settingsOverride
   *   Values to merge into the default settings.
   *
   * @return \Drupal\passkey_forge\Service\WebAuthnService
   */
  private function buildService(array $settingsOverride = []): WebAuthnService {
    $defaults = [
      'rp_id' => self::RP_ID,
      'rp_name' => 'Test Site',
      'allowed_origins' => [self::ORIGIN],
      'attestation_policy' => 'none',
      'timeout' => 60000,
      'require_resident_key' => false,
      'user_verification' => 'preferred',
    ];

    $settings = array_merge($defaults, $settingsOverride);

    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnCallback(
      static fn(string $key) => $settings[$key] ?? null,
    );

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')
      ->with('passkey_forge.settings')
      ->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);

    return new WebAuthnService($configFactory, $logger);
  }

  // -------------------------------------------------------------------------
  // generateChallenge
  // -------------------------------------------------------------------------

  /**
   * @covers ::generateChallenge
   */
  public function testGenerateChallengeReturnsNonEmptyString(): void {
    $service = $this->buildService();
    $challenge = $service->generateChallenge();
    $this->assertNotEmpty($challenge);
    $this->assertIsString($challenge);
  }

  /**
   * @covers ::generateChallenge
   */
  public function testGenerateChallengeIsBase64url(): void {
    $service = $this->buildService();
    $challenge = $service->generateChallenge();
    $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $challenge, 'Challenge must be base64url (no +/= chars).');
  }

  /**
   * @covers ::generateChallenge
   */
  public function testGenerateChallengeHasNoPaddingEquals(): void {
    $service = $this->buildService();
    $challenge = $service->generateChallenge();
    $this->assertStringNotContainsString('=', $challenge);
  }

  /**
   * @covers ::generateChallenge
   */
  public function testGenerateChallengeProducesUniqueValues(): void {
    $service = $this->buildService();
    $a = $service->generateChallenge();
    $b = $service->generateChallenge();
    $this->assertNotSame($a, $b, 'Two consecutive challenges must not be identical.');
  }

  /**
   * @covers ::generateChallenge
   */
  public function testGenerateChallengeDecodesToThirtyTwoBytes(): void {
    $service = $this->buildService();
    $challenge = $service->generateChallenge();

    // Restore padding for decoding.
    $padded = $challenge . str_repeat('=', (4 - strlen($challenge) % 4) % 4);
    $decoded = base64_decode(strtr($padded, '-_', '+/'), strict: true);

    $this->assertNotFalse($decoded);
    $this->assertSame(32, strlen($decoded), 'Challenge must encode 32 random bytes.');
  }

  // -------------------------------------------------------------------------
  // generateUserHandle
  // -------------------------------------------------------------------------

  /**
   * @covers ::generateUserHandle
   */
  public function testGenerateUserHandleIsBase64url(): void {
    $service = $this->buildService();
    $handle = $service->generateUserHandle(42);
    $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $handle);
  }

  /**
   * @covers ::generateUserHandle
   */
  public function testGenerateUserHandleIsDeterministic(): void {
    $service = $this->buildService();
    $this->assertSame(
      $service->generateUserHandle(99),
      $service->generateUserHandle(99),
      'User handle must be deterministic for the same UID.',
    );
  }

  /**
   * @covers ::generateUserHandle
   */
  public function testGenerateUserHandleDiffersForDifferentUids(): void {
    $service = $this->buildService();
    $this->assertNotSame(
      $service->generateUserHandle(1),
      $service->generateUserHandle(2),
    );
  }

  /**
   * @covers ::generateUserHandle
   */
  public function testGenerateUserHandleDoesNotExposeUid(): void {
    $service = $this->buildService();
    $handle = $service->generateUserHandle(12345);
    // The UID '12345' must not appear literally in the handle.
    $this->assertStringNotContainsString('12345', $handle);
  }

  // -------------------------------------------------------------------------
  // buildRegistrationOptions
  // -------------------------------------------------------------------------

  /**
   * @covers ::buildRegistrationOptions
   */
  public function testBuildRegistrationOptionsReturnsRequiredKeys(): void {
    $service = $this->buildService();
    $options = $service->buildRegistrationOptions(1, 'alice', 'Alice');

    $this->assertArrayHasKey('challenge', $options);
    $this->assertArrayHasKey('rp', $options);
    $this->assertArrayHasKey('user', $options);
    $this->assertArrayHasKey('pubKeyCredParams', $options);
    $this->assertArrayHasKey('timeout', $options);
    $this->assertArrayHasKey('attestation', $options);
  }

  /**
   * @covers ::buildRegistrationOptions
   */
  public function testBuildRegistrationOptionsPopulatesRpFromConfig(): void {
    $service = $this->buildService(['rp_id' => 'mysite.org', 'rp_name' => 'My Site']);
    $options = $service->buildRegistrationOptions(1, 'alice', 'Alice');

    $this->assertSame('mysite.org', $options['rp']['id']);
    $this->assertSame('My Site', $options['rp']['name']);
  }

  /**
   * @covers ::buildRegistrationOptions
   */
  public function testBuildRegistrationOptionsUsesConfiguredAttestation(): void {
    $service = $this->buildService(['attestation_policy' => 'indirect']);
    $options = $service->buildRegistrationOptions(1, 'alice', 'Alice');

    $this->assertSame('indirect', $options['attestation']);
  }

  /**
   * @covers ::buildRegistrationOptions
   */
  public function testBuildRegistrationOptionsPolicyOverrideWins(): void {
    $service = $this->buildService(['attestation_policy' => 'none']);
    $options = $service->buildRegistrationOptions(
      uid: 1,
      username: 'alice',
      displayName: 'Alice',
      policyOverride: AttestationPolicy::Direct,
    );

    $this->assertSame('direct', $options['attestation']);
  }

  /**
   * @covers ::buildRegistrationOptions
   */
  public function testBuildRegistrationOptionsExcludesExistingCredentials(): void {
    $service = $this->buildService();

    $existing = new PasskeyCredential(
      id: 5,
      uid: 1,
      credentialId: 'abc123',
      publicKey: '---pem---',
      aaguid: null,
      signCount: 0,
      attestationType: AttestationPolicy::None,
      transports: ['usb'],
      label: 'My key',
      revoked: false,
      created: time(),
      lastUsed: null,
    );

    $options = $service->buildRegistrationOptions(1, 'alice', 'Alice', [$existing]);

    $this->assertArrayHasKey('excludeCredentials', $options);
    $this->assertCount(1, $options['excludeCredentials']);
    $this->assertSame('abc123', $options['excludeCredentials'][0]['id']);
    $this->assertSame(['usb'], $options['excludeCredentials'][0]['transports']);
  }

  /**
   * @covers ::buildRegistrationOptions
   */
  public function testBuildRegistrationOptionsIncludesEs256AndRs256Params(): void {
    $service = $this->buildService();
    $options = $service->buildRegistrationOptions(1, 'alice', 'Alice');

    $algs = array_column($options['pubKeyCredParams'], 'alg');
    $this->assertContains(-7, $algs, 'ES256 (alg=-7) must be in pubKeyCredParams.');
    $this->assertContains(-257, $algs, 'RS256 (alg=-257) must be in pubKeyCredParams.');
  }

  /**
   * @covers ::buildRegistrationOptions
   */
  public function testBuildRegistrationOptionsTimeoutMatchesConfig(): void {
    $service = $this->buildService(['timeout' => 120000]);
    $options = $service->buildRegistrationOptions(1, 'alice', 'Alice');

    $this->assertSame(120000, $options['timeout']);
  }

  // -------------------------------------------------------------------------
  // buildAuthenticationOptions
  // -------------------------------------------------------------------------

  /**
   * @covers ::buildAuthenticationOptions
   */
  public function testBuildAuthenticationOptionsReturnsRequiredKeys(): void {
    $service = $this->buildService();
    $options = $service->buildAuthenticationOptions();

    $this->assertArrayHasKey('challenge', $options);
    $this->assertArrayHasKey('rpId', $options);
    $this->assertArrayHasKey('timeout', $options);
    $this->assertArrayHasKey('allowCredentials', $options);
    $this->assertArrayHasKey('userVerification', $options);
  }

  /**
   * @covers ::buildAuthenticationOptions
   */
  public function testBuildAuthenticationOptionsEmptyAllowList(): void {
    $service = $this->buildService();
    $options = $service->buildAuthenticationOptions([]);

    $this->assertEmpty($options['allowCredentials']);
  }

  /**
   * @covers ::buildAuthenticationOptions
   */
  public function testBuildAuthenticationOptionsPopulatesAllowList(): void {
    $service = $this->buildService();

    $cred = new PasskeyCredential(
      id: 3,
      uid: 1,
      credentialId: 'cred-xyz',
      publicKey: '---pem---',
      aaguid: null,
      signCount: 5,
      attestationType: AttestationPolicy::None,
      transports: ['internal'],
      label: null,
      revoked: false,
      created: time(),
      lastUsed: null,
    );

    $options = $service->buildAuthenticationOptions([$cred]);

    $this->assertCount(1, $options['allowCredentials']);
    $this->assertSame('cred-xyz', $options['allowCredentials'][0]['id']);
    $this->assertSame(['internal'], $options['allowCredentials'][0]['transports']);
  }

  /**
   * @covers ::buildAuthenticationOptions
   */
  public function testBuildAuthenticationOptionsRpIdFromConfig(): void {
    $service = $this->buildService(['rp_id' => 'auth.example.net']);
    $options = $service->buildAuthenticationOptions();

    $this->assertSame('auth.example.net', $options['rpId']);
  }

  // -------------------------------------------------------------------------
  // verifyRegistrationResponse — error cases (no real CBOR/crypto needed)
  // -------------------------------------------------------------------------

  /**
   * @covers ::verifyRegistrationResponse
   */
  public function testVerifyRegistrationResponseThrowsOnInvalidClientDataJson(): void {
    $service = $this->buildService();
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/clientDataJSON/');

    $service->verifyRegistrationResponse(
      ['response' => ['clientDataJSON' => '!!!not-base64url!!!']],
      'somechallenge',
    );
  }

  /**
   * @covers ::verifyRegistrationResponse
   */
  public function testVerifyRegistrationResponseThrowsOnWrongType(): void {
    $service = $this->buildService();

    $clientData = json_encode(['type' => 'webauthn.get', 'challenge' => 'abc', 'origin' => self::ORIGIN]);
    $encoded = rtrim(strtr(base64_encode($clientData), '+/', '-_'), '=');

    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/webauthn\.create/');

    $service->verifyRegistrationResponse(
      ['response' => ['clientDataJSON' => $encoded, 'attestationObject' => '']],
      'abc',
    );
  }

  /**
   * @covers ::verifyRegistrationResponse
   */
  public function testVerifyRegistrationResponseThrowsOnChallengeMismatch(): void {
    $service = $this->buildService();

    $clientData = json_encode(['type' => 'webauthn.create', 'challenge' => 'challenge-A', 'origin' => self::ORIGIN]);
    $encoded = rtrim(strtr(base64_encode($clientData), '+/', '-_'), '=');

    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/[Cc]hallenge/');

    $service->verifyRegistrationResponse(
      ['response' => ['clientDataJSON' => $encoded, 'attestationObject' => '']],
      'challenge-B',
    );
  }

  /**
   * @covers ::verifyRegistrationResponse
   */
  public function testVerifyRegistrationResponseThrowsOnDisallowedOrigin(): void {
    $service = $this->buildService(['allowed_origins' => ['https://allowed.com']]);

    $clientData = json_encode([
      'type' => 'webauthn.create',
      'challenge' => 'ch',
      'origin' => 'https://evil.com',
    ]);
    $encoded = rtrim(strtr(base64_encode($clientData), '+/', '-_'), '=');

    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/[Oo]rigin/');

    $service->verifyRegistrationResponse(
      ['response' => ['clientDataJSON' => $encoded, 'attestationObject' => '']],
      'ch',
    );
  }

  // -------------------------------------------------------------------------
  // verifyAuthenticationResponse — error cases
  // -------------------------------------------------------------------------

  /**
   * @covers ::verifyAuthenticationResponse
   */
  public function testVerifyAuthenticationResponseThrowsOnWrongType(): void {
    $service = $this->buildService();

    $clientData = json_encode(['type' => 'webauthn.create', 'challenge' => 'ch', 'origin' => self::ORIGIN]);
    $encoded = rtrim(strtr(base64_encode($clientData), '+/', '-_'), '=');

    $credential = $this->makeCredential();

    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/webauthn\.get/');

    $service->verifyAuthenticationResponse(
      ['response' => ['clientDataJSON' => $encoded, 'authenticatorData' => '', 'signature' => '']],
      'ch',
      $credential,
    );
  }

  /**
   * @covers ::verifyAuthenticationResponse
   */
  public function testVerifyAuthenticationResponseThrowsOnChallengeMismatch(): void {
    $service = $this->buildService();

    $clientData = json_encode(['type' => 'webauthn.get', 'challenge' => 'correct-challenge', 'origin' => self::ORIGIN]);
    $encoded = rtrim(strtr(base64_encode($clientData), '+/', '-_'), '=');

    $credential = $this->makeCredential();

    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/[Cc]hallenge/');

    $service->verifyAuthenticationResponse(
      ['response' => ['clientDataJSON' => $encoded, 'authenticatorData' => '', 'signature' => '']],
      'wrong-challenge',
      $credential,
    );
  }

  /**
   * @covers ::verifyAuthenticationResponse
   */
  public function testVerifyAuthenticationResponseThrowsOnDisallowedOrigin(): void {
    $service = $this->buildService(['allowed_origins' => ['https://good.com']]);

    $clientData = json_encode(['type' => 'webauthn.get', 'challenge' => 'ch', 'origin' => 'https://bad.com']);
    $encoded = rtrim(strtr(base64_encode($clientData), '+/', '-_'), '=');

    $credential = $this->makeCredential();

    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/[Oo]rigin/');

    $service->verifyAuthenticationResponse(
      ['response' => ['clientDataJSON' => $encoded, 'authenticatorData' => '', 'signature' => '']],
      'ch',
      $credential,
    );
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Creates a minimal PasskeyCredential for use in test assertions.
   */
  private function makeCredential(int $signCount = 0): PasskeyCredential {
    return new PasskeyCredential(
      id: 1,
      uid: 42,
      credentialId: 'test-cred-id',
      publicKey: '-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n',
      aaguid: null,
      signCount: $signCount,
      attestationType: AttestationPolicy::None,
      transports: [],
      label: null,
      revoked: false,
      created: time(),
      lastUsed: null,
    );
  }

}
