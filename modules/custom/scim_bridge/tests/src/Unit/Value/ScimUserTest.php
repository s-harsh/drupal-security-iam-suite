<?php

declare(strict_types=1);

namespace Drupal\Tests\scim_bridge\Unit\Value;

use Drupal\scim_bridge\Value\ScimUser;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for the ScimUser value object.
 *
 * @coversDefaultClass \Drupal\scim_bridge\Value\ScimUser
 * @group scim_bridge
 */
final class ScimUserTest extends UnitTestCase {

  // ---------------------------------------------------------------------------
  // Construction and fromArray()
  // ---------------------------------------------------------------------------

  /**
   * @covers ::__construct
   * @covers ::fromArray
   */
  public function testFromArraySetsAllTopLevelFields(): void {
    $data = [
      'id'          => '99',
      'externalId'  => 'ext-abc',
      'userName'    => 'jane',
      'displayName' => 'Jane Doe',
      'active'      => false,
      'title'       => 'Engineer',
      'locale'      => 'en-GB',
      'timezone'    => 'Europe/London',
    ];

    $user = ScimUser::fromArray($data);

    $this->assertSame('99', $user->id);
    $this->assertSame('ext-abc', $user->externalId);
    $this->assertSame('jane', $user->userName);
    $this->assertSame('Jane Doe', $user->displayName);
    $this->assertFalse($user->active);
    $this->assertSame('Engineer', $user->title);
    $this->assertSame('en-GB', $user->locale);
    $this->assertSame('Europe/London', $user->timezone);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayParsesNestedNameFields(): void {
    $data = [
      'name' => [
        'givenName'  => 'John',
        'familyName' => 'Smith',
      ],
    ];

    $user = ScimUser::fromArray($data);

    $this->assertSame('John', $user->givenName);
    $this->assertSame('Smith', $user->familyName);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayHandlesMissingNameBlock(): void {
    $user = ScimUser::fromArray(['userName' => 'nnoname']);
    $this->assertSame('', $user->givenName);
    $this->assertSame('', $user->familyName);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayDefaultsActiveToTrue(): void {
    $user = ScimUser::fromArray([]);
    $this->assertTrue($user->active);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArraySelectsPrimaryEmail(): void {
    $data = [
      'emails' => [
        ['value' => 'work@test.com', 'type' => 'work', 'primary' => true],
        ['value' => 'home@test.com', 'type' => 'home'],
      ],
    ];
    $user = ScimUser::fromArray($data);
    $this->assertSame('work@test.com', $user->primaryEmail);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayFallsBackToWorkTypeEmailWhenNoPrimary(): void {
    $data = [
      'emails' => [
        ['value' => 'home@test.com', 'type' => 'home'],
        ['value' => 'work@test.com', 'type' => 'work'],
      ],
    ];
    $user = ScimUser::fromArray($data);
    $this->assertSame('work@test.com', $user->primaryEmail);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayFallsBackToFirstEmailWhenNoWorkOrPrimary(): void {
    $data = [
      'emails' => [
        ['value' => 'first@test.com', 'type' => 'home'],
        ['value' => 'second@test.com', 'type' => 'mobile'],
      ],
    ];
    $user = ScimUser::fromArray($data);
    $this->assertSame('first@test.com', $user->primaryEmail);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayHandlesEmptyEmailsArray(): void {
    $user = ScimUser::fromArray(['emails' => []]);
    $this->assertSame('', $user->primaryEmail);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayParsesPhoneNumber(): void {
    $data = [
      'phoneNumbers' => [['value' => '+1-555-0100', 'type' => 'work', 'primary' => true]],
    ];
    $user = ScimUser::fromArray($data);
    $this->assertSame('+1-555-0100', $user->phoneNumber);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayParsesAddressFields(): void {
    $data = [
      'addresses' => [
        ['locality' => 'Seattle', 'country' => 'US', 'primary' => true, 'type' => 'work'],
      ],
    ];
    $user = ScimUser::fromArray($data);
    $this->assertSame('Seattle', $user->city);
    $this->assertSame('US', $user->country);
  }

  /**
   * @covers ::fromArray
   */
  public function testFromArrayStoresRawPayload(): void {
    $data = ['userName' => 'raw_test', 'custom_field' => 'my_value'];
    $user = ScimUser::fromArray($data);
    $this->assertSame($data, $user->rawPayload);
  }

  // ---------------------------------------------------------------------------
  // withId()
  // ---------------------------------------------------------------------------

  /**
   * @covers ::withId
   */
  public function testWithIdCreatesNewInstance(): void {
    $original = new ScimUser(id: '', userName: 'foo');
    $updated  = $original->withId('123');

    $this->assertNotSame($original, $updated);
    $this->assertSame('123', $updated->id);
    $this->assertSame('', $original->id);
  }

  /**
   * @covers ::withId
   */
  public function testWithIdPreservesOtherProperties(): void {
    $original = new ScimUser(
      id:           '',
      externalId:   'ext-1',
      userName:     'preserved',
      displayName:  'Preserved User',
      primaryEmail: 'p@test.com',
      active:       false,
    );
    $updated = $original->withId('77');

    $this->assertSame('ext-1', $updated->externalId);
    $this->assertSame('preserved', $updated->userName);
    $this->assertSame('Preserved User', $updated->displayName);
    $this->assertSame('p@test.com', $updated->primaryEmail);
    $this->assertFalse($updated->active);
  }

  // ---------------------------------------------------------------------------
  // toScimArray()
  // ---------------------------------------------------------------------------

  /**
   * @covers ::toScimArray
   */
  public function testToScimArrayHasSchemas(): void {
    $user = new ScimUser(id: '1', userName: 'test');
    $arr  = $user->toScimArray();
    $this->assertArrayHasKey('schemas', $arr);
    $this->assertContains('urn:ietf:params:scim:schemas:core:2.0:User', $arr['schemas']);
  }

  /**
   * @covers ::toScimArray
   */
  public function testToScimArrayHasIdAndUserName(): void {
    $user = new ScimUser(id: '5', userName: 'jane');
    $arr  = $user->toScimArray();
    $this->assertSame('5', $arr['id']);
    $this->assertSame('jane', $arr['userName']);
  }

  /**
   * @covers ::toScimArray
   */
  public function testToScimArrayFormattedNameConcatenatesFirstAndLast(): void {
    $user = new ScimUser(id: '1', userName: 'u', givenName: 'John', familyName: 'Doe');
    $arr  = $user->toScimArray();
    $this->assertSame('John Doe', $arr['name']['formatted']);
  }

  /**
   * @covers ::toScimArray
   */
  public function testToScimArrayFormattedNameHandlesEmptyParts(): void {
    $user = new ScimUser(id: '1', userName: 'u', givenName: 'Solo', familyName: '');
    $arr  = $user->toScimArray();
    $this->assertSame('Solo', $arr['name']['formatted']);
  }

  /**
   * @covers ::toScimArray
   */
  public function testToScimArrayOmitsOptionalFieldsWhenEmpty(): void {
    $user = new ScimUser(id: '1', userName: 'u');
    $arr  = $user->toScimArray();

    $this->assertArrayNotHasKey('emails', $arr);
    $this->assertArrayNotHasKey('phoneNumbers', $arr);
    $this->assertArrayNotHasKey('addresses', $arr);
    $this->assertArrayNotHasKey('title', $arr);
  }

  /**
   * @covers ::toScimArray
   */
  public function testToScimArrayIncludesEmailsWhenPresent(): void {
    $user = new ScimUser(id: '1', userName: 'u', primaryEmail: 'u@example.com');
    $arr  = $user->toScimArray();

    $this->assertArrayHasKey('emails', $arr);
    $this->assertSame('u@example.com', $arr['emails'][0]['value']);
    $this->assertTrue($arr['emails'][0]['primary']);
  }

  /**
   * @covers ::toScimArray
   */
  public function testToScimArrayHasMetaWithResourceType(): void {
    $user = new ScimUser(id: '8', userName: 'u');
    $arr  = $user->toScimArray();

    $this->assertArrayHasKey('meta', $arr);
    $this->assertSame('User', $arr['meta']['resourceType']);
    $this->assertStringContainsString('/scim/v2/Users/8', $arr['meta']['location']);
  }

  /**
   * @covers ::toScimArray
   */
  public function testToScimArrayActiveFieldReflectsStatus(): void {
    $active   = new ScimUser(id: '1', userName: 'a', active: true);
    $inactive = new ScimUser(id: '2', userName: 'b', active: false);

    $this->assertTrue($active->toScimArray()['active']);
    $this->assertFalse($inactive->toScimArray()['active']);
  }

  // ---------------------------------------------------------------------------
  // Immutability
  // ---------------------------------------------------------------------------

  /**
   * Verifies the readonly class cannot have its properties mutated.
   *
   * @covers ::__construct
   */
  public function testScimUserIsImmutable(): void {
    $user = new ScimUser(id: '10', userName: 'readonly_test');

    try {
      // @phpstan-ignore-line
      $user->userName = 'mutated';
      $this->fail('Expected Error when mutating readonly property.');
    }
    catch (\Error) {
      $this->assertTrue(true, 'Readonly property correctly prevents mutation.');
    }
  }

}
