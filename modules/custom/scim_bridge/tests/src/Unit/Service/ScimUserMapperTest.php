<?php

declare(strict_types=1);

namespace Drupal\Tests\scim_bridge\Unit\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\Query\QueryInterface;
use Drupal\Core\Password\PasswordGeneratorInterface;
use Drupal\scim_bridge\Service\ScimFilterParser;
use Drupal\scim_bridge\Service\ScimUserMapper;
use Drupal\scim_bridge\Value\ScimPatchOperation;
use Drupal\scim_bridge\Value\ScimUser;
use Drupal\Tests\UnitTestCase;
use Drupal\user\UserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for ScimUserMapper.
 *
 * @coversDefaultClass \Drupal\scim_bridge\Service\ScimUserMapper
 * @group scim_bridge
 */
final class ScimUserMapperTest extends UnitTestCase {

  // ---------------------------------------------------------------------------
  // Test data
  // ---------------------------------------------------------------------------

  private const DEFAULT_ATTR_MAP = [
    'userName'              => 'name',
    'emails[0].value'       => 'mail',
    'displayName'           => 'field_display_name',
    'name.givenName'        => 'field_first_name',
    'name.familyName'       => 'field_last_name',
    'active'                => 'status',
    'externalId'            => 'field_scim_external_id',
  ];

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Builds a config factory mock returning the default mapping and settings.
   */
  private function makeConfigFactory(
    array $attrMap = self::DEFAULT_ATTR_MAP,
    string $conflictStrategy = 'skip',
    int $maxPageSize = 100,
  ): ConfigFactoryInterface {
    $mappingConfig = $this->createMock(ImmutableConfig::class);
    $mappingConfig->method('get')->willReturnMap([
      ['user_attribute_map', $attrMap],
    ]);

    $settingsConfig = $this->createMock(ImmutableConfig::class);
    $settingsConfig->method('get')->willReturnMap([
      ['conflict_strategy', $conflictStrategy],
      ['max_page_size',     $maxPageSize],
      ['sync_log_enabled',  FALSE],
    ]);

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturnMap([
      ['scim_bridge.mapping',  $mappingConfig],
      ['scim_bridge.settings', $settingsConfig],
    ]);

    return $factory;
  }

  /**
   * Builds a minimal UserInterface mock.
   *
   * @param string $uid
   *   The user ID.
   * @param string $name
   *   The account name.
   * @param string $mail
   *   The email address.
   * @param bool $active
   *   Whether the account is active.
   */
  private function makeUser(
    string $uid = '42',
    string $name = 'jdoe',
    string $mail = 'jdoe@example.com',
    bool $active = true,
  ): UserInterface&MockObject {
    $user = $this->createMock(UserInterface::class);
    $user->method('id')->willReturn($uid);
    $user->method('getAccountName')->willReturn($name);
    $user->method('getDisplayName')->willReturn($name);
    $user->method('getEmail')->willReturn($mail);
    $user->method('isActive')->willReturn($active);
    $user->method('hasField')->willReturn(FALSE);
    return $user;
  }

  /**
   * Builds the service under test.
   */
  private function makeService(
    EntityTypeManagerInterface $etm,
    ConfigFactoryInterface $configFactory,
    ?ScimFilterParser $filterParser = null,
    ?PasswordGeneratorInterface $passwordGenerator = null,
  ): ScimUserMapper {
    return new ScimUserMapper(
      $etm,
      $configFactory,
      $this->createMock(LoggerInterface::class),
      $filterParser ?? new ScimFilterParser(),
      $passwordGenerator ?? $this->makePasswordGenerator(),
    );
  }

  /**
   * Returns a password generator mock.
   */
  private function makePasswordGenerator(): PasswordGeneratorInterface&MockObject {
    $gen = $this->createMock(PasswordGeneratorInterface::class);
    $gen->method('generate')->willReturn('random-password-32chars-long!!!!!');
    return $gen;
  }

  /**
   * Builds a storage mock that returns a given user when load() is called.
   */
  private function makeStorageWithUser(UserInterface $user): EntityStorageInterface&MockObject {
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('load')->willReturn($user);
    return $storage;
  }

  /**
   * Builds a EntityTypeManagerInterface mock.
   */
  private function makeEtmWithUserStorage(EntityStorageInterface $storage): EntityTypeManagerInterface&MockObject {
    $etm = $this->createMock(EntityTypeManagerInterface::class);
    $etm->method('getStorage')->with('user')->willReturn($storage);
    return $etm;
  }

  // ---------------------------------------------------------------------------
  // drupalUserToScimUser() tests
  // ---------------------------------------------------------------------------

  /**
   * @covers ::drupalUserToScimUser
   */
  public function testDrupalUserToScimUserSetsBasicFields(): void {
    $user    = $this->makeUser('7', 'alice', 'alice@example.com', true);
    $storage = $this->makeStorageWithUser($user);
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $scimUser = $service->drupalUserToScimUser($user);

    $this->assertSame('7', $scimUser->id);
    $this->assertSame('alice', $scimUser->userName);
    $this->assertSame('alice@example.com', $scimUser->primaryEmail);
    $this->assertTrue($scimUser->active);
  }

  /**
   * @covers ::drupalUserToScimUser
   */
  public function testDrupalUserToScimUserInactiveAccount(): void {
    $user    = $this->makeUser('3', 'blocked', 'blocked@example.com', false);
    $storage = $this->makeStorageWithUser($user);
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $scimUser = $service->drupalUserToScimUser($user);

    $this->assertFalse($scimUser->active);
  }

  /**
   * @covers ::drupalUserToScimUser
   */
  public function testDrupalUserToScimUserReturnsScimUserInstance(): void {
    $user    = $this->makeUser();
    $storage = $this->makeStorageWithUser($user);
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $this->assertInstanceOf(ScimUser::class, $service->drupalUserToScimUser($user));
  }

  // ---------------------------------------------------------------------------
  // getUser() tests
  // ---------------------------------------------------------------------------

  /**
   * @covers ::getUser
   */
  public function testGetUserReturnsNullForNonNumericId(): void {
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->expects($this->never())->method('load');
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $this->assertNull($service->getUser('not-a-number'));
  }

  /**
   * @covers ::getUser
   */
  public function testGetUserReturnsNullForUidZero(): void {
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->expects($this->never())->method('load');
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $this->assertNull($service->getUser('0'));
  }

  /**
   * @covers ::getUser
   */
  public function testGetUserReturnsNullWhenEntityNotFound(): void {
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('load')->willReturn(NULL);
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $this->assertNull($service->getUser('999'));
  }

  /**
   * @covers ::getUser
   */
  public function testGetUserReturnsMappedScimUser(): void {
    $user    = $this->makeUser('42', 'john', 'john@example.com', true);
    $storage = $this->makeStorageWithUser($user);
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $result = $service->getUser('42');

    $this->assertNotNull($result);
    $this->assertSame('42', $result->id);
    $this->assertSame('john', $result->userName);
  }

  // ---------------------------------------------------------------------------
  // deleteUser() tests
  // ---------------------------------------------------------------------------

  /**
   * @covers ::deleteUser
   */
  public function testDeleteUserReturnsFalseForInvalidId(): void {
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('load')->willReturn(NULL);
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $this->assertFalse($service->deleteUser('abc'));
  }

  /**
   * @covers ::deleteUser
   */
  public function testDeleteUserReturnsFalseWhenUserNotFound(): void {
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('load')->willReturn(NULL);
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $this->assertFalse($service->deleteUser('100'));
  }

  /**
   * @covers ::deleteUser
   */
  public function testDeleteUserCallsDeleteOnEntity(): void {
    $user = $this->makeUser('15');
    $user->expects($this->once())->method('delete');

    $storage = $this->makeStorageWithUser($user);
    $service = $this->makeService(
      $this->makeEtmWithUserStorage($storage),
      $this->makeConfigFactory(),
    );

    $result = $service->deleteUser('15');
    $this->assertTrue($result);
  }

  // ---------------------------------------------------------------------------
  // ScimUser value object helpers
  // ---------------------------------------------------------------------------

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::fromArray
   */
  public function testScimUserFromArrayParsesBasicFields(): void {
    $data = [
      'id'          => '5',
      'externalId'  => 'ext-99',
      'userName'    => 'bob',
      'displayName' => 'Bob Smith',
      'active'      => true,
      'emails'      => [['value' => 'bob@example.com', 'primary' => true, 'type' => 'work']],
    ];

    $scimUser = ScimUser::fromArray($data);

    $this->assertSame('5', $scimUser->id);
    $this->assertSame('ext-99', $scimUser->externalId);
    $this->assertSame('bob', $scimUser->userName);
    $this->assertSame('Bob Smith', $scimUser->displayName);
    $this->assertSame('bob@example.com', $scimUser->primaryEmail);
    $this->assertTrue($scimUser->active);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::fromArray
   */
  public function testScimUserFromArrayDefaultsActiveToTrue(): void {
    $scimUser = ScimUser::fromArray(['userName' => 'noactive']);
    $this->assertTrue($scimUser->active);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::fromArray
   */
  public function testScimUserFromArraySelectsPrimaryEmail(): void {
    $data = [
      'emails' => [
        ['value' => 'work@example.com', 'type' => 'work', 'primary' => true],
        ['value' => 'home@example.com', 'type' => 'home'],
      ],
    ];
    $scimUser = ScimUser::fromArray($data);
    $this->assertSame('work@example.com', $scimUser->primaryEmail);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::fromArray
   */
  public function testScimUserFromArrayFallsBackToFirstEmailWhenNoPrimary(): void {
    $data = [
      'emails' => [
        ['value' => 'first@example.com', 'type' => 'home'],
        ['value' => 'second@example.com', 'type' => 'work'],
      ],
    ];
    $scimUser = ScimUser::fromArray($data);
    // Prefers type=work over first.
    $this->assertSame('second@example.com', $scimUser->primaryEmail);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::toScimArray
   */
  public function testToScimArrayContainsRequiredSchemaKey(): void {
    $scimUser = new ScimUser(id: '1', userName: 'test', primaryEmail: 'test@example.com');
    $arr = $scimUser->toScimArray();
    $this->assertArrayHasKey('schemas', $arr);
    $this->assertContains('urn:ietf:params:scim:schemas:core:2.0:User', $arr['schemas']);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::toScimArray
   */
  public function testToScimArrayContainsUserName(): void {
    $scimUser = new ScimUser(id: '2', userName: 'jsmith');
    $arr = $scimUser->toScimArray();
    $this->assertSame('jsmith', $arr['userName']);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::toScimArray
   */
  public function testToScimArrayEmailsArrayWhenEmailPresent(): void {
    $scimUser = new ScimUser(id: '3', userName: 'user', primaryEmail: 'u@example.com');
    $arr = $scimUser->toScimArray();
    $this->assertArrayHasKey('emails', $arr);
    $this->assertSame('u@example.com', $arr['emails'][0]['value']);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::toScimArray
   */
  public function testToScimArrayOmitsEmailsKeyWhenEmpty(): void {
    $scimUser = new ScimUser(id: '4', userName: 'nomail', primaryEmail: '');
    $arr = $scimUser->toScimArray();
    $this->assertArrayNotHasKey('emails', $arr);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimUser::withId
   */
  public function testWithIdReturnsNewInstance(): void {
    $scimUser    = new ScimUser(id: '', userName: 'test');
    $withId      = $scimUser->withId('55');
    $this->assertSame('55', $withId->id);
    $this->assertSame('', $scimUser->id); // original unchanged
  }

  // ---------------------------------------------------------------------------
  // ScimPatchOperation tests
  // ---------------------------------------------------------------------------

  /**
   * @covers \Drupal\scim_bridge\Value\ScimPatchOperation::fromArray
   */
  public function testPatchOperationFromArrayNormalisesOpToLower(): void {
    $op = ScimPatchOperation::fromArray(['op' => 'REPLACE', 'path' => 'active', 'value' => false]);
    $this->assertSame('replace', $op->op);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimPatchOperation::isValid
   */
  public function testPatchOperationIsValidForKnownOps(): void {
    foreach (['add', 'remove', 'replace'] as $opName) {
      $op = new ScimPatchOperation($opName, 'active', null);
      $this->assertTrue($op->isValid(), "Expected '$opName' to be valid.");
    }
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimPatchOperation::isValid
   */
  public function testPatchOperationIsInvalidForUnknownOp(): void {
    $op = new ScimPatchOperation('merge', 'active', null);
    $this->assertFalse($op->isValid());
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimPatchOperation::topLevelAttribute
   */
  public function testTopLevelAttributeStripsFilterExpression(): void {
    $op = new ScimPatchOperation('replace', 'emails[type eq "work"].value', 'new@example.com');
    $this->assertSame('emails', $op->topLevelAttribute());
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimPatchOperation::topLevelAttribute
   */
  public function testTopLevelAttributeExtractsDotNotationFirst(): void {
    $op = new ScimPatchOperation('replace', 'name.givenName', 'Alice');
    $this->assertSame('name', $op->topLevelAttribute());
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimPatchOperation::scalarBoolValue
   */
  public function testScalarBoolValueReturnsTrueForStringTrue(): void {
    $op = new ScimPatchOperation('replace', 'active', 'true');
    $this->assertTrue($op->scalarBoolValue());
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimPatchOperation::scalarBoolValue
   */
  public function testScalarBoolValueReturnsFalseForBoolFalse(): void {
    $op = new ScimPatchOperation('replace', 'active', false);
    $this->assertFalse($op->scalarBoolValue());
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimPatchOperation::scalarBoolValue
   */
  public function testScalarBoolValueReturnsNullForArray(): void {
    $op = new ScimPatchOperation('replace', 'active', ['a' => 1]);
    $this->assertNull($op->scalarBoolValue());
  }

}
