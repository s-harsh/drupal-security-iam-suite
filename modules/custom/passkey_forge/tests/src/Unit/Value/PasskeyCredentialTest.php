<?php

declare(strict_types=1);

namespace Drupal\Tests\passkey_forge\Unit\Value;

use Drupal\passkey_forge\Value\AttestationPolicy;
use Drupal\passkey_forge\Value\PasskeyCredential;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for the PasskeyCredential value object.
 *
 * @coversDefaultClass \Drupal\passkey_forge\Value\PasskeyCredential
 * @group passkey_forge
 */
final class PasskeyCredentialTest extends UnitTestCase {

  /**
   * Creates a default PasskeyCredential with sensible test values.
   *
   * @param array<string, mixed> $override
   *   Named arguments to override individual constructor parameters.
   *
   * @return \Drupal\passkey_forge\Value\PasskeyCredential
   */
  private function makeCredential(array $override = []): PasskeyCredential {
    $defaults = [
      'id' => 1,
      'uid' => 42,
      'credentialId' => 'base64url-credential-id',
      'publicKey' => "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
      'aaguid' => '12345678-1234-5678-1234-567812345678',
      'signCount' => 10,
      'attestationType' => AttestationPolicy::None,
      'transports' => ['usb', 'nfc'],
      'label' => 'My YubiKey',
      'revoked' => false,
      'created' => 1700000000,
      'lastUsed' => 1700001000,
    ];

    $merged = array_merge($defaults, $override);

    return new PasskeyCredential(
      id: $merged['id'],
      uid: $merged['uid'],
      credentialId: $merged['credentialId'],
      publicKey: $merged['publicKey'],
      aaguid: $merged['aaguid'],
      signCount: $merged['signCount'],
      attestationType: $merged['attestationType'],
      transports: $merged['transports'],
      label: $merged['label'],
      revoked: $merged['revoked'],
      created: $merged['created'],
      lastUsed: $merged['lastUsed'],
    );
  }

  // -------------------------------------------------------------------------
  // Constructor + property access
  // -------------------------------------------------------------------------

  /**
   * @covers ::__construct
   */
  public function testConstructorSetsAllProperties(): void {
    $cred = $this->makeCredential();

    $this->assertSame(1, $cred->id);
    $this->assertSame(42, $cred->uid);
    $this->assertSame('base64url-credential-id', $cred->credentialId);
    $this->assertStringContainsString('PUBLIC KEY', $cred->publicKey);
    $this->assertSame('12345678-1234-5678-1234-567812345678', $cred->aaguid);
    $this->assertSame(10, $cred->signCount);
    $this->assertSame(AttestationPolicy::None, $cred->attestationType);
    $this->assertSame(['usb', 'nfc'], $cred->transports);
    $this->assertSame('My YubiKey', $cred->label);
    $this->assertFalse($cred->revoked);
    $this->assertSame(1700000000, $cred->created);
    $this->assertSame(1700001000, $cred->lastUsed);
  }

  /**
   * @covers ::__construct
   *
   * The class must be declared readonly to guarantee immutability.
   */
  public function testClassIsReadonly(): void {
    $reflection = new \ReflectionClass(PasskeyCredential::class);
    $this->assertTrue($reflection->isReadOnly(), 'PasskeyCredential must be a readonly class.');
  }

  /**
   * @covers ::__construct
   */
  public function testNullableFieldsAcceptNull(): void {
    $cred = $this->makeCredential(['aaguid' => null, 'label' => null, 'lastUsed' => null]);

    $this->assertNull($cred->aaguid);
    $this->assertNull($cred->label);
    $this->assertNull($cred->lastUsed);
  }

  // -------------------------------------------------------------------------
  // isActive
  // -------------------------------------------------------------------------

  /**
   * @covers ::isActive
   */
  public function testIsActiveTrueWhenNotRevoked(): void {
    $cred = $this->makeCredential(['revoked' => false]);
    $this->assertTrue($cred->isActive());
  }

  /**
   * @covers ::isActive
   */
  public function testIsActiveFalseWhenRevoked(): void {
    $cred = $this->makeCredential(['revoked' => true]);
    $this->assertFalse($cred->isActive());
  }

  // -------------------------------------------------------------------------
  // revoke
  // -------------------------------------------------------------------------

  /**
   * @covers ::revoke
   */
  public function testRevokeReturnsNewInstance(): void {
    $original = $this->makeCredential();
    $revoked = $original->revoke();

    $this->assertNotSame($original, $revoked);
  }

  /**
   * @covers ::revoke
   */
  public function testRevokeSetsFlagToTrue(): void {
    $original = $this->makeCredential(['revoked' => false]);
    $revoked = $original->revoke();

    $this->assertTrue($revoked->revoked);
  }

  /**
   * @covers ::revoke
   */
  public function testRevokePreservesOtherFields(): void {
    $original = $this->makeCredential();
    $revoked = $original->revoke();

    $this->assertSame($original->id, $revoked->id);
    $this->assertSame($original->uid, $revoked->uid);
    $this->assertSame($original->credentialId, $revoked->credentialId);
    $this->assertSame($original->signCount, $revoked->signCount);
    $this->assertSame($original->label, $revoked->label);
  }

  /**
   * @covers ::revoke
   */
  public function testOriginalRemainsUnchangedAfterRevoke(): void {
    $original = $this->makeCredential(['revoked' => false]);
    $original->revoke();

    $this->assertFalse($original->revoked, 'Original must be unchanged (immutable).');
  }

  // -------------------------------------------------------------------------
  // withSignCount
  // -------------------------------------------------------------------------

  /**
   * @covers ::withSignCount
   */
  public function testWithSignCountReturnsNewInstance(): void {
    $original = $this->makeCredential(['signCount' => 5]);
    $updated = $original->withSignCount(10);

    $this->assertNotSame($original, $updated);
  }

  /**
   * @covers ::withSignCount
   */
  public function testWithSignCountUpdatesCounter(): void {
    $original = $this->makeCredential(['signCount' => 5]);
    $updated = $original->withSignCount(20);

    $this->assertSame(20, $updated->signCount);
  }

  /**
   * @covers ::withSignCount
   */
  public function testWithSignCountPreservesOtherFields(): void {
    $original = $this->makeCredential(['signCount' => 5]);
    $updated = $original->withSignCount(99);

    $this->assertSame($original->id, $updated->id);
    $this->assertSame($original->uid, $updated->uid);
    $this->assertSame($original->credentialId, $updated->credentialId);
    $this->assertSame($original->publicKey, $updated->publicKey);
    $this->assertSame($original->revoked, $updated->revoked);
  }

  /**
   * @covers ::withSignCount
   */
  public function testWithSignCountUpdatesLastUsed(): void {
    $before = time();
    $original = $this->makeCredential(['lastUsed' => null]);
    $updated = $original->withSignCount(1);
    $after = time();

    $this->assertNotNull($updated->lastUsed);
    $this->assertGreaterThanOrEqual($before, $updated->lastUsed);
    $this->assertLessThanOrEqual($after, $updated->lastUsed);
  }

  /**
   * @covers ::withSignCount
   */
  public function testOriginalSignCountUnchangedAfterWithSignCount(): void {
    $original = $this->makeCredential(['signCount' => 7]);
    $original->withSignCount(99);

    $this->assertSame(7, $original->signCount, 'Original must remain immutable.');
  }

  // -------------------------------------------------------------------------
  // transportsJson
  // -------------------------------------------------------------------------

  /**
   * @covers ::transportsJson
   */
  public function testTransportsJsonEncodesArray(): void {
    $cred = $this->makeCredential(['transports' => ['usb', 'nfc']]);
    $json = $cred->transportsJson();

    $this->assertJson($json);
    $decoded = json_decode($json, true);
    $this->assertSame(['usb', 'nfc'], $decoded);
  }

  /**
   * @covers ::transportsJson
   */
  public function testTransportsJsonEmptyArray(): void {
    $cred = $this->makeCredential(['transports' => []]);
    $this->assertSame('[]', $cred->transportsJson());
  }

  // -------------------------------------------------------------------------
  // fromDatabaseRow
  // -------------------------------------------------------------------------

  /**
   * @covers ::fromDatabaseRow
   */
  public function testFromDatabaseRowHydratesAllFields(): void {
    $row = [
      'id' => '5',
      'uid' => '99',
      'credential_id' => 'cred-abc',
      'public_key' => '---pem---',
      'aaguid' => 'aabbccdd-0011-2233-4455-667788990011',
      'sign_count' => '42',
      'attestation_type' => 'indirect',
      'transports' => '["internal","hybrid"]',
      'label' => 'Face ID',
      'revoked' => '0',
      'created' => '1700000000',
      'last_used' => '1700001000',
    ];

    $cred = PasskeyCredential::fromDatabaseRow($row);

    $this->assertSame(5, $cred->id);
    $this->assertSame(99, $cred->uid);
    $this->assertSame('cred-abc', $cred->credentialId);
    $this->assertSame('---pem---', $cred->publicKey);
    $this->assertSame('aabbccdd-0011-2233-4455-667788990011', $cred->aaguid);
    $this->assertSame(42, $cred->signCount);
    $this->assertSame(AttestationPolicy::Indirect, $cred->attestationType);
    $this->assertSame(['internal', 'hybrid'], $cred->transports);
    $this->assertSame('Face ID', $cred->label);
    $this->assertFalse($cred->revoked);
    $this->assertSame(1700000000, $cred->created);
    $this->assertSame(1700001000, $cred->lastUsed);
  }

  /**
   * @covers ::fromDatabaseRow
   */
  public function testFromDatabaseRowHandlesNullOptionalFields(): void {
    $row = [
      'id' => '1',
      'uid' => '1',
      'credential_id' => 'cred-x',
      'public_key' => '---pem---',
      'aaguid' => null,
      'sign_count' => '0',
      'attestation_type' => 'none',
      'transports' => null,
      'label' => null,
      'revoked' => '0',
      'created' => '0',
      'last_used' => null,
    ];

    $cred = PasskeyCredential::fromDatabaseRow($row);

    $this->assertNull($cred->aaguid);
    $this->assertNull($cred->label);
    $this->assertNull($cred->lastUsed);
    $this->assertSame([], $cred->transports);
  }

  /**
   * @covers ::fromDatabaseRow
   */
  public function testFromDatabaseRowTreatsEmptyAaguidAsNull(): void {
    $row = [
      'id' => '1',
      'uid' => '1',
      'credential_id' => 'c',
      'public_key' => '---pem---',
      'aaguid' => '',
      'sign_count' => '0',
      'attestation_type' => 'none',
      'transports' => null,
      'label' => null,
      'revoked' => '0',
      'created' => '0',
      'last_used' => null,
    ];

    $cred = PasskeyCredential::fromDatabaseRow($row);
    $this->assertNull($cred->aaguid);
  }

  /**
   * @covers ::fromDatabaseRow
   */
  public function testFromDatabaseRowDefaultsUnknownAttestationTypeToNone(): void {
    $row = [
      'id' => '1',
      'uid' => '1',
      'credential_id' => 'c',
      'public_key' => '---pem---',
      'aaguid' => null,
      'sign_count' => '0',
      'attestation_type' => 'completely-unknown-value',
      'transports' => null,
      'label' => null,
      'revoked' => '0',
      'created' => '0',
      'last_used' => null,
    ];

    $cred = PasskeyCredential::fromDatabaseRow($row);
    $this->assertSame(AttestationPolicy::None, $cred->attestationType);
  }

  /**
   * @covers ::fromDatabaseRow
   */
  public function testFromDatabaseRowSetsRevokedTrue(): void {
    $row = [
      'id' => '1',
      'uid' => '1',
      'credential_id' => 'c',
      'public_key' => '---pem---',
      'aaguid' => null,
      'sign_count' => '0',
      'attestation_type' => 'none',
      'transports' => null,
      'label' => null,
      'revoked' => '1',
      'created' => '0',
      'last_used' => null,
    ];

    $cred = PasskeyCredential::fromDatabaseRow($row);
    $this->assertTrue($cred->revoked);
    $this->assertFalse($cred->isActive());
  }

}
