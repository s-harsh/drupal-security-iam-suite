<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\scim_bridge\Value\ScimGroup;
use Drupal\scim_bridge\Value\ScimPatchOperation;
use Drupal\user\RoleInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Maps SCIM 2.0 Group resources to Drupal roles and vice versa.
 *
 * In Drupal there is no standalone "group" entity: groups are represented by
 * roles. This service translates SCIM Group CRUD operations into Drupal role
 * and user-role-assignment operations. The group-to-role mapping is configured
 * in scim_bridge.mapping and can be customised per site.
 */
final class ScimGroupMapper {

  /**
   * The SCIM mapping configuration object name.
   */
  private const MAPPING_CONFIG = 'scim_bridge.mapping';

  /**
   * The SCIM Bridge settings configuration object name.
   */
  private const SETTINGS_CONFIG = 'scim_bridge.settings';

  /**
   * Constructs a ScimGroupMapper.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The SCIM Bridge logger channel.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Returns a paginated list of SCIM Group resources.
   *
   * Only roles that appear in the group_role_map configuration are surfaced.
   * When the map is empty, all non-system roles are listed.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming HTTP request with query parameters.
   *
   * @return array<string, mixed>
   *   A SCIM ListResponse array ready for JSON encoding.
   */
  public function listGroups(Request $request): array {
    $startIndex = max(1, (int) ($request->query->get('startIndex', 1) ?? 1));
    $count      = max(1, min(
      (int) ($request->query->get('count', 100) ?? 100),
      (int) ($this->configFactory->get(self::SETTINGS_CONFIG)->get('max_page_size') ?? 100),
    ));

    $roles = $this->getMappedRoles();

    $totalResults = count($roles);
    $sliced       = array_slice(array_values($roles), $startIndex - 1, $count);

    $resources = [];
    foreach ($sliced as $role) {
      $resources[] = $this->drupalRoleToScimGroup($role)->toScimArray();
    }

    return [
      'schemas'      => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      'totalResults' => $totalResults,
      'startIndex'   => $startIndex,
      'itemsPerPage' => count($resources),
      'Resources'    => $resources,
    ];
  }

  /**
   * Returns a single SCIM Group resource by role machine name.
   *
   * @param string $id
   *   The Drupal role machine name used as the SCIM Group id.
   *
   * @return \Drupal\scim_bridge\Value\ScimGroup|null
   *   The SCIM Group value object, or null when the role does not exist.
   */
  public function getGroup(string $id): ?ScimGroup {
    $role = $this->loadRole($id);
    if ($role === null) {
      return null;
    }
    return $this->drupalRoleToScimGroup($role);
  }

  /**
   * Creates or locates a Drupal role from a SCIM Group resource (POST).
   *
   * If a role with the same machine name already exists, the existing role is
   * returned (idempotent). If the group_role_map has an entry for this
   * displayName the mapped role is used; otherwise the displayName is
   * machine-name-ified and a new role is created.
   *
   * @param \Drupal\scim_bridge\Value\ScimGroup $scimGroup
   *   The SCIM Group value object.
   *
   * @return array{scimGroup: \Drupal\scim_bridge\Value\ScimGroup, created: bool}
   *   Array with the resulting ScimGroup and whether a new role was created.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if entity storage fails.
   */
  public function createGroup(ScimGroup $scimGroup): array {
    $roleId = $this->resolveMachineNameForGroup($scimGroup->displayName);

    $existing = $this->loadRole($roleId);
    if ($existing !== null) {
      $this->syncGroupMembers($existing, $scimGroup);
      return ['scimGroup' => $this->drupalRoleToScimGroup($existing), 'created' => false];
    }

    /** @var \Drupal\user\RoleInterface $role */
    $role = $this->entityTypeManager->getStorage('user_role')->create([
      'id'    => $roleId,
      'label' => $scimGroup->displayName,
    ]);
    $role->save();
    $this->syncGroupMembers($role, $scimGroup);

    $this->logger->notice('SCIM: created role @role from SCIM Group @name.', [
      '@role' => $roleId,
      '@name' => $scimGroup->displayName,
    ]);

    return ['scimGroup' => $this->drupalRoleToScimGroup($role), 'created' => true];
  }

  /**
   * Fully replaces a Drupal role's label and membership from a SCIM Group (PUT).
   *
   * @param string $id
   *   The Drupal role machine name.
   * @param \Drupal\scim_bridge\Value\ScimGroup $scimGroup
   *   The replacement SCIM Group value object.
   *
   * @return \Drupal\scim_bridge\Value\ScimGroup|null
   *   The updated ScimGroup, or null when the role does not exist.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if entity storage fails.
   */
  public function replaceGroup(string $id, ScimGroup $scimGroup): ?ScimGroup {
    $role = $this->loadRole($id);
    if ($role === null) {
      return null;
    }
    $role->set('label', $scimGroup->displayName);
    $role->save();
    $this->syncGroupMembers($role, $scimGroup);
    $this->logger->notice('SCIM: replaced role @role via PUT.', ['@role' => $id]);
    return $this->drupalRoleToScimGroup($role);
  }

  /**
   * Applies PATCH operations to a Drupal role and its membership.
   *
   * Supports:
   *   - replace displayName → updates role label
   *   - add members → grants role to listed users
   *   - remove members → revokes role from listed users
   *
   * @param string $id
   *   The Drupal role machine name.
   * @param \Drupal\scim_bridge\Value\ScimPatchOperation[] $operations
   *   Array of parsed patch operations.
   *
   * @return \Drupal\scim_bridge\Value\ScimGroup|null
   *   The patched ScimGroup, or null when the role does not exist.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if entity storage fails.
   */
  public function patchGroup(string $id, array $operations): ?ScimGroup {
    $role = $this->loadRole($id);
    if ($role === null) {
      return null;
    }

    foreach ($operations as $op) {
      if (!$op->isValid()) {
        continue;
      }

      $attr = strtolower($op->topLevelAttribute());

      if ($attr === 'displayname' || $attr === 'displayName') {
        if ($op->op !== ScimPatchOperation::OP_REMOVE) {
          $str = $op->scalarStringValue();
          if ($str !== null && $str !== '') {
            $role->set('label', $str);
            $role->save();
          }
        }
        continue;
      }

      if ($attr === 'members') {
        $memberIds = $this->extractMemberIds($op->value);
        if ($op->op === ScimPatchOperation::OP_ADD) {
          $this->grantRoleToUsers($role->id(), $memberIds);
        }
        elseif ($op->op === ScimPatchOperation::OP_REMOVE) {
          $this->revokeRoleFromUsers($role->id(), $memberIds);
        }
        elseif ($op->op === ScimPatchOperation::OP_REPLACE) {
          $this->setRoleMembers($role, $memberIds);
        }
      }
    }

    $this->logger->notice('SCIM: patched role @role (@count ops).', [
      '@role'  => $id,
      '@count' => count($operations),
    ]);
    return $this->drupalRoleToScimGroup($role);
  }

  /**
   * Deletes a Drupal role by machine name.
   *
   * @param string $id
   *   The Drupal role machine name.
   *
   * @return bool
   *   TRUE when the role existed and was deleted; FALSE when not found.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if entity storage fails.
   */
  public function deleteGroup(string $id): bool {
    $role = $this->loadRole($id);
    if ($role === null) {
      return false;
    }
    // System roles cannot be deleted.
    if (in_array($id, [RoleInterface::ANONYMOUS_ID, RoleInterface::AUTHENTICATED_ID], true)) {
      return false;
    }
    $role->delete();
    $this->logger->notice('SCIM: deleted role @role.', ['@role' => $id]);
    return true;
  }

  /**
   * Converts a Drupal role entity to a ScimGroup value object.
   *
   * Queries all users that hold this role and includes them as members.
   *
   * @param \Drupal\user\RoleInterface $role
   *   The Drupal role entity.
   *
   * @return \Drupal\scim_bridge\Value\ScimGroup
   *   The SCIM Group value object.
   */
  private function drupalRoleToScimGroup(RoleInterface $role): ScimGroup {
    $uids = $this->entityTypeManager->getStorage('user')->getQuery()
      ->accessCheck(FALSE)
      ->condition('roles', $role->id())
      ->condition('uid', 0, '>')
      ->execute();

    $members = array_map(
      static fn(mixed $uid): array => ['value' => (string) $uid, 'display' => ''],
      array_values($uids),
    );

    return new ScimGroup(
      id:          (string) $role->id(),
      externalId:  '',
      displayName: $role->label(),
      members:     $members,
    );
  }

  /**
   * Synchronises the members of a Drupal role with those in a ScimGroup.
   *
   * Adds the role to users listed as members and leaves non-listed users
   * unchanged (additive-only). To fully replace membership use setRoleMembers().
   *
   * @param \Drupal\user\RoleInterface $role
   *   The role to update membership for.
   * @param \Drupal\scim_bridge\Value\ScimGroup $scimGroup
   *   The SCIM Group providing the member list.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if user save fails.
   */
  private function syncGroupMembers(RoleInterface $role, ScimGroup $scimGroup): void {
    if (empty($scimGroup->members)) {
      return;
    }
    $this->grantRoleToUsers($role->id(), $scimGroup->memberIds());
  }

  /**
   * Replaces all members of a role with the given set of user IDs.
   *
   * @param \Drupal\user\RoleInterface $role
   *   The role.
   * @param string[] $newMemberIds
   *   The complete set of user IDs that should hold this role.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if user save fails.
   */
  private function setRoleMembers(RoleInterface $role, array $newMemberIds): void {
    $roleId = $role->id();

    // Remove role from current members not in the new list.
    $currentUids = (array) $this->entityTypeManager->getStorage('user')->getQuery()
      ->accessCheck(FALSE)
      ->condition('roles', $roleId)
      ->condition('uid', 0, '>')
      ->execute();

    $toRemove = array_diff($currentUids, $newMemberIds);
    $toAdd    = array_diff($newMemberIds, $currentUids);

    $this->revokeRoleFromUsers($roleId, array_map('strval', $toRemove));
    $this->grantRoleToUsers($roleId, $toAdd);
  }

  /**
   * Grants a role to a set of users identified by their Drupal user IDs.
   *
   * @param string $roleId
   *   The role machine name.
   * @param string[] $userIds
   *   Array of Drupal user IDs as strings.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if user save fails.
   */
  private function grantRoleToUsers(string $roleId, array $userIds): void {
    $storage = $this->entityTypeManager->getStorage('user');
    foreach ($userIds as $uid) {
      if (!ctype_digit((string) $uid) || $uid === '0') {
        continue;
      }
      $user = $storage->load((int) $uid);
      if ($user === null) {
        continue;
      }
      if (!$user->hasRole($roleId)) {
        $user->addRole($roleId);
        $user->save();
      }
    }
  }

  /**
   * Revokes a role from a set of users identified by their Drupal user IDs.
   *
   * @param string $roleId
   *   The role machine name.
   * @param string[] $userIds
   *   Array of Drupal user IDs as strings.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if user save fails.
   */
  private function revokeRoleFromUsers(string $roleId, array $userIds): void {
    $storage = $this->entityTypeManager->getStorage('user');
    foreach ($userIds as $uid) {
      if (!ctype_digit((string) $uid) || $uid === '0') {
        continue;
      }
      $user = $storage->load((int) $uid);
      if ($user === null) {
        continue;
      }
      if ($user->hasRole($roleId)) {
        $user->removeRole($roleId);
        $user->save();
      }
    }
  }

  /**
   * Loads a Drupal role entity by machine name.
   *
   * @param string $id
   *   The role machine name.
   *
   * @return \Drupal\user\RoleInterface|null
   *   The role entity or null.
   */
  private function loadRole(string $id): ?RoleInterface {
    $role = $this->entityTypeManager->getStorage('user_role')->load($id);
    if (!$role instanceof RoleInterface) {
      return null;
    }
    return $role;
  }

  /**
   * Returns all Drupal roles that should be exposed as SCIM Groups.
   *
   * When a group_role_map is configured, only those roles are returned.
   * Otherwise, all roles except anonymous and authenticated are returned.
   *
   * @return \Drupal\user\RoleInterface[]
   *   Keyed array of role entities.
   */
  private function getMappedRoles(): array {
    $groupRoleMap = (array) ($this->configFactory->get(self::MAPPING_CONFIG)->get('group_role_map') ?? []);
    $roleStorage  = $this->entityTypeManager->getStorage('user_role');

    if (!empty($groupRoleMap)) {
      $roles = [];
      foreach ($groupRoleMap as $displayName => $roleId) {
        $role = $this->loadRole((string) $roleId);
        if ($role !== null) {
          $roles[$role->id()] = $role;
        }
      }
      return $roles;
    }

    // No explicit map: expose all non-system roles.
    $all = $roleStorage->loadMultiple();
    return array_filter(
      $all,
      static fn(mixed $r): bool => $r instanceof RoleInterface
        && !in_array($r->id(), [RoleInterface::ANONYMOUS_ID, RoleInterface::AUTHENTICATED_ID], true),
    );
  }

  /**
   * Derives a Drupal role machine name from a SCIM Group displayName.
   *
   * First checks the group_role_map. If not found, converts the display name
   * to lowercase, replacing non-alphanumeric characters with underscores, and
   * truncating to 64 characters (Drupal role ID limit).
   *
   * @param string $displayName
   *   The SCIM Group displayName.
   *
   * @return string
   *   The Drupal role machine name.
   */
  private function resolveMachineNameForGroup(string $displayName): string {
    $groupRoleMap = (array) ($this->configFactory->get(self::MAPPING_CONFIG)->get('group_role_map') ?? []);
    if (isset($groupRoleMap[$displayName])) {
      return (string) $groupRoleMap[$displayName];
    }
    $machined = strtolower(preg_replace('/[^a-z0-9_]+/i', '_', $displayName) ?? '');
    return substr(trim($machined, '_'), 0, 64);
  }

  /**
   * Extracts member user IDs from a PATCH operation value.
   *
   * The value may be:
   *   - An array of member objects: [['value' => '123'], ...]
   *   - A scalar user ID string: '123'
   *   - null (for remove-all)
   *
   * @param mixed $value
   *   The raw value from the PATCH operation.
   *
   * @return string[]
   *   Flat array of user ID strings.
   */
  private function extractMemberIds(mixed $value): array {
    if (is_array($value)) {
      return array_values(array_filter(
        array_map(static fn(mixed $m): string => (string) ($m['value'] ?? ''), $value),
        static fn(string $v): bool => $v !== '',
      ));
    }
    if (is_string($value) && $value !== '') {
      return [$value];
    }
    return [];
  }

}
