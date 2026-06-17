<?php

declare(strict_types=1);

namespace Drupal\Tests\scim_bridge\Unit\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\scim_bridge\Service\ScimGroupMapper;
use Drupal\scim_bridge\Value\ScimGroup;
use Drupal\Tests\UnitTestCase;
use Drupal\user\RoleInterface;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for ScimGroupMapper.
 *
 * @coversDefaultClass \Drupal\scim_bridge\Service\ScimGroupMapper
 * @group scim_bridge
 */
final class ScimGroupMapperTest extends UnitTestCase {

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Builds a config factory mock.
   */
  private function makeConfigFactory(
    array $groupRoleMap = [],
    int $maxPageSize = 100,
  ): ConfigFactoryInterface {
    $mappingConfig = $this->createMock(ImmutableConfig::class);
    $mappingConfig->method('get')->willReturnMap([
      ['group_role_map', $groupRoleMap],
    ]);

    $settingsConfig = $this->createMock(ImmutableConfig::class);
    $settingsConfig->method('get')->willReturnMap([
      ['max_page_size',    $maxPageSize],
      ['sync_log_enabled', FALSE],
    ]);

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturnMap([
      ['scim_bridge.mapping',  $mappingConfig],
      ['scim_bridge.settings', $settingsConfig],
    ]);

    return $factory;
  }

  /**
   * Builds a RoleInterface mock.
   */
  private function makeRole(string $id, string $label): RoleInterface&MockObject {
    $role = $this->createMock(RoleInterface::class);
    $role->method('id')->willReturn($id);
    $role->method('label')->willReturn($label);
    return $role;
  }

  /**
   * Builds the service under test.
   */
  private function makeService(
    EntityTypeManagerInterface $etm,
    ConfigFactoryInterface $configFactory,
  ): ScimGroupMapper {
    return new ScimGroupMapper(
      $etm,
      $configFactory,
      $this->createMock(LoggerInterface::class),
    );
  }

  // ---------------------------------------------------------------------------
  // getGroup() tests
  // ---------------------------------------------------------------------------

  /**
   * @covers ::getGroup
   */
  public function testGetGroupReturnsNullWhenRoleNotFound(): void {
    $roleStorage = $this->createMock(EntityStorageInterface::class);
    $roleStorage->method('load')->willReturn(NULL);

    $userStorage = $this->createMock(EntityStorageInterface::class);

    $etm = $this->createMock(EntityTypeManagerInterface::class);
    $etm->method('getStorage')->willReturnMap([
      ['user_role', $roleStorage],
      ['user',      $userStorage],
    ]);

    $service = $this->makeService($etm, $this->makeConfigFactory());

    $this->assertNull($service->getGroup('nonexistent_role'));
  }

  /**
   * @covers ::getGroup
   */
  public function testGetGroupReturnsScimGroupForExistingRole(): void {
    $role        = $this->makeRole('editor', 'Editor');
    $roleStorage = $this->createMock(EntityStorageInterface::class);
    $roleStorage->method('load')->willReturn($role);

    // Query mock returning empty UIDs for role members.
    $query = $this->createMock(\Drupal\Core\Entity\Query\QueryInterface::class);
    $query->method('accessCheck')->willReturnSelf();
    $query->method('condition')->willReturnSelf();
    $query->method('execute')->willReturn([]);

    $userStorage = $this->createMock(EntityStorageInterface::class);
    $userStorage->method('getQuery')->willReturn($query);

    $etm = $this->createMock(EntityTypeManagerInterface::class);
    $etm->method('getStorage')->willReturnMap([
      ['user_role', $roleStorage],
      ['user',      $userStorage],
    ]);

    $service = $this->makeService($etm, $this->makeConfigFactory());
    $result  = $service->getGroup('editor');

    $this->assertInstanceOf(ScimGroup::class, $result);
    $this->assertSame('editor', $result->id);
    $this->assertSame('Editor', $result->displayName);
  }

  // ---------------------------------------------------------------------------
  // deleteGroup() tests
  // ---------------------------------------------------------------------------

  /**
   * @covers ::deleteGroup
   */
  public function testDeleteGroupReturnsFalseWhenNotFound(): void {
    $roleStorage = $this->createMock(EntityStorageInterface::class);
    $roleStorage->method('load')->willReturn(NULL);

    $etm = $this->createMock(EntityTypeManagerInterface::class);
    $etm->method('getStorage')->willReturn($roleStorage);

    $service = $this->makeService($etm, $this->makeConfigFactory());

    $this->assertFalse($service->deleteGroup('ghost'));
  }

  /**
   * @covers ::deleteGroup
   */
  public function testDeleteGroupReturnsFalseForAnonymousRole(): void {
    $role        = $this->makeRole(RoleInterface::ANONYMOUS_ID, 'Anonymous');
    $roleStorage = $this->createMock(EntityStorageInterface::class);
    $roleStorage->method('load')->willReturn($role);

    $etm = $this->createMock(EntityTypeManagerInterface::class);
    $etm->method('getStorage')->willReturn($roleStorage);

    $service = $this->makeService($etm, $this->makeConfigFactory());

    $this->assertFalse($service->deleteGroup(RoleInterface::ANONYMOUS_ID));
  }

  /**
   * @covers ::deleteGroup
   */
  public function testDeleteGroupReturnsFalseForAuthenticatedRole(): void {
    $role        = $this->makeRole(RoleInterface::AUTHENTICATED_ID, 'Authenticated');
    $roleStorage = $this->createMock(EntityStorageInterface::class);
    $roleStorage->method('load')->willReturn($role);

    $etm = $this->createMock(EntityTypeManagerInterface::class);
    $etm->method('getStorage')->willReturn($roleStorage);

    $service = $this->makeService($etm, $this->makeConfigFactory());

    $this->assertFalse($service->deleteGroup(RoleInterface::AUTHENTICATED_ID));
  }

  /**
   * @covers ::deleteGroup
   */
  public function testDeleteGroupCallsDeleteOnRole(): void {
    $role = $this->makeRole('custom_role', 'Custom Role');
    $role->expects($this->once())->method('delete');

    $roleStorage = $this->createMock(EntityStorageInterface::class);
    $roleStorage->method('load')->willReturn($role);

    $etm = $this->createMock(EntityTypeManagerInterface::class);
    $etm->method('getStorage')->willReturn($roleStorage);

    $service = $this->makeService($etm, $this->makeConfigFactory());

    $this->assertTrue($service->deleteGroup('custom_role'));
  }

  // ---------------------------------------------------------------------------
  // ScimGroup value object tests
  // ---------------------------------------------------------------------------

  /**
   * @covers \Drupal\scim_bridge\Value\ScimGroup::fromArray
   */
  public function testScimGroupFromArrayParsesFields(): void {
    $data = [
      'id'          => 'engineers',
      'externalId'  => 'ext-g-1',
      'displayName' => 'Engineering',
      'members'     => [
        ['value' => '10', 'display' => 'Alice'],
        ['value' => '20', 'display' => 'Bob'],
      ],
    ];

    $group = ScimGroup::fromArray($data);

    $this->assertSame('engineers', $group->id);
    $this->assertSame('Engineering', $group->displayName);
    $this->assertCount(2, $group->members);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimGroup::memberIds
   */
  public function testMemberIdsReturnsUserIds(): void {
    $group = new ScimGroup(
      id: 'admins',
      displayName: 'Admins',
      members: [['value' => '5'], ['value' => '9']],
    );

    $this->assertSame(['5', '9'], $group->memberIds());
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimGroup::memberIds
   */
  public function testMemberIdsReturnsEmptyArrayWhenNoMembers(): void {
    $group = new ScimGroup(id: 'empty', displayName: 'Empty');
    $this->assertSame([], $group->memberIds());
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimGroup::toScimArray
   */
  public function testToScimArrayContainsGroupSchema(): void {
    $group = new ScimGroup(id: 'mods', displayName: 'Moderators');
    $arr   = $group->toScimArray();

    $this->assertArrayHasKey('schemas', $arr);
    $this->assertContains('urn:ietf:params:scim:schemas:core:2.0:Group', $arr['schemas']);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimGroup::toScimArray
   */
  public function testToScimArrayIncludesDisplayName(): void {
    $group = new ScimGroup(id: 'mods', displayName: 'Moderators');
    $arr   = $group->toScimArray();

    $this->assertSame('Moderators', $arr['displayName']);
  }

  /**
   * @covers \Drupal\scim_bridge\Value\ScimGroup::withId
   */
  public function testWithIdReturnsNewInstance(): void {
    $group  = new ScimGroup(id: '', displayName: 'Test');
    $withId = $group->withId('new_id');

    $this->assertSame('new_id', $withId->id);
    $this->assertSame('', $group->id); // original unchanged
  }

}
