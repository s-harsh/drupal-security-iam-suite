<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Password\PasswordGeneratorInterface;
use Drupal\scim_bridge\Value\ScimPatchOperation;
use Drupal\scim_bridge\Value\ScimUser;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Maps SCIM User resources to Drupal user entities and vice versa.
 *
 * Handles create, read, update, patch, delete, and list operations for
 * Drupal user accounts. Attribute mapping is driven by the scim_bridge.mapping
 * configuration object, allowing site administrators to control which SCIM
 * attributes are written to which Drupal user fields.
 */
final class ScimUserMapper {

  /**
   * The SCIM mapping configuration object name.
   */
  private const MAPPING_CONFIG = 'scim_bridge.mapping';

  /**
   * The SCIM Bridge settings configuration object name.
   */
  private const SETTINGS_CONFIG = 'scim_bridge.settings';

  /**
   * Constructs a ScimUserMapper.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The SCIM Bridge logger channel.
   * @param \Drupal\scim_bridge\Service\ScimFilterParser $filterParser
   *   The SCIM filter parser service.
   * @param \Drupal\Core\Password\PasswordGeneratorInterface $passwordGenerator
   *   The password generator used when creating new accounts.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly ScimFilterParser $filterParser,
    private readonly PasswordGeneratorInterface $passwordGenerator,
  ) {}

  /**
   * Returns a paginated list of SCIM User resources.
   *
   * Supports filter, startIndex, and count query parameters as defined by
   * RFC 7644 §3.4.2.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming HTTP request carrying query parameters.
   *
   * @return array<string, mixed>
   *   A SCIM ListResponse array ready for JSON encoding.
   */
  public function listUsers(Request $request): array {
    $filterStr  = (string) ($request->query->get('filter', '') ?? '');
    $startIndex = max(1, (int) ($request->query->get('startIndex', 1) ?? 1));
    $count      = $this->resolvePageCount((int) ($request->query->get('count', 100) ?? 100));

    $storage = $this->entityTypeManager->getStorage('user');
    $query   = $storage->getQuery()->accessCheck(FALSE);
    // Exclude anonymous user (uid 0).
    $query->condition('uid', 0, '>');

    $attributeMap = $this->getAttributeMap();

    if ($filterStr !== '') {
      $criteria = $this->filterParser->parse($filterStr);
      if ($criteria !== null) {
        $conditions = $this->filterParser->toEntityQueryConditions($criteria, $this->invertAttributeMap($attributeMap));
        foreach ($conditions as $cond) {
          if ($cond['field'] === 'status' && strtolower((string) $cond['value']) === 'true') {
            $cond['value'] = 1;
          }
          $query->condition($cond['field'], $cond['value'], $cond['op']);
        }
      }
    }

    // Get total count before pagination.
    $countQuery  = clone $query;
    $totalResults = (int) $countQuery->count()->execute();

    // Apply offset and limit.
    $offset = $startIndex - 1;
    $query->range($offset, $count);
    $query->sort('uid', 'ASC');
    $uids = $query->execute();

    /** @var \Drupal\user\UserInterface[] $users */
    $users = $storage->loadMultiple($uids);

    $resources = [];
    foreach ($users as $user) {
      $scimUser = $this->drupalUserToScimUser($user);
      // Post-query filter when complex filter criteria not handled by entity query.
      if ($filterStr !== '' && !$this->userMatchesFilter($scimUser, $filterStr)) {
        continue;
      }
      $resources[] = $scimUser->toScimArray();
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
   * Finds and returns a single Drupal user as a SCIM User resource.
   *
   * @param string $id
   *   The Drupal user ID.
   *
   * @return \Drupal\scim_bridge\Value\ScimUser|null
   *   The SCIM User value object, or null when the user does not exist.
   */
  public function getUser(string $id): ?ScimUser {
    $user = $this->loadDrupalUser($id);
    if ($user === null) {
      return null;
    }
    return $this->drupalUserToScimUser($user);
  }

  /**
   * Creates a new Drupal user from a SCIM User resource.
   *
   * Checks for username and email conflicts before creating. The conflict
   * strategy (skip or update) in settings determines behaviour on conflict.
   *
   * @param \Drupal\scim_bridge\Value\ScimUser $scimUser
   *   The SCIM User value object parsed from the request body.
   *
   * @return array{scimUser: \Drupal\scim_bridge\Value\ScimUser, conflict: bool}
   *   Array with the resulting ScimUser (with id set) and a conflict flag.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if entity storage fails.
   */
  public function createUser(ScimUser $scimUser): array {
    // Check for existing user by userName or email.
    $existing = $this->findExistingUser($scimUser);
    if ($existing !== null) {
      $settings = $this->configFactory->get(self::SETTINGS_CONFIG);
      if ((string) $settings->get('conflict_strategy') === 'update') {
        $this->applyScimUserToEntity($scimUser, $existing);
        $existing->save();
        $this->logger->notice('SCIM: updated existing user @uid on conflict (strategy=update).', ['@uid' => $existing->id()]);
        return ['scimUser' => $this->drupalUserToScimUser($existing), 'conflict' => true];
      }
      // Default: skip — return the existing record.
      $this->logger->notice('SCIM: returning existing user @uid on conflict (strategy=skip).', ['@uid' => $existing->id()]);
      return ['scimUser' => $this->drupalUserToScimUser($existing), 'conflict' => true];
    }

    /** @var \Drupal\user\UserInterface $user */
    $user = $this->entityTypeManager->getStorage('user')->create([]);
    $this->applyScimUserToEntity($scimUser, $user);
    // Set a random password — SCIM provisioning manages account, not password.
    $user->setPassword($this->passwordGenerator->generate(32));
    $user->save();

    $this->logger->notice('SCIM: created user @uid (userName: @name).', [
      '@uid'  => $user->id(),
      '@name' => $scimUser->userName,
    ]);

    return ['scimUser' => $this->drupalUserToScimUser($user), 'conflict' => false];
  }

  /**
   * Fully replaces a Drupal user with the given SCIM User resource (PUT).
   *
   * @param string $id
   *   The Drupal user ID.
   * @param \Drupal\scim_bridge\Value\ScimUser $scimUser
   *   The replacement SCIM User value object.
   *
   * @return \Drupal\scim_bridge\Value\ScimUser|null
   *   The updated ScimUser, or null when the user does not exist.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if entity storage fails.
   */
  public function replaceUser(string $id, ScimUser $scimUser): ?ScimUser {
    $user = $this->loadDrupalUser($id);
    if ($user === null) {
      return null;
    }
    $this->applyScimUserToEntity($scimUser, $user);
    $user->save();
    $this->logger->notice('SCIM: replaced user @uid via PUT.', ['@uid' => $id]);
    return $this->drupalUserToScimUser($user);
  }

  /**
   * Applies a list of SCIM PATCH operations to a Drupal user (PATCH).
   *
   * @param string $id
   *   The Drupal user ID.
   * @param \Drupal\scim_bridge\Value\ScimPatchOperation[] $operations
   *   Array of patch operations parsed from the request body.
   *
   * @return \Drupal\scim_bridge\Value\ScimUser|null
   *   The patched ScimUser, or null when the user does not exist.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if entity storage fails.
   */
  public function patchUser(string $id, array $operations): ?ScimUser {
    $user = $this->loadDrupalUser($id);
    if ($user === null) {
      return null;
    }

    $attributeMap = $this->getAttributeMap();

    foreach ($operations as $op) {
      if (!$op->isValid()) {
        continue;
      }
      $this->applyPatchOperation($op, $user, $attributeMap);
    }

    $user->save();
    $this->logger->notice('SCIM: patched user @uid (@count operations).', [
      '@uid'   => $id,
      '@count' => count($operations),
    ]);
    return $this->drupalUserToScimUser($user);
  }

  /**
   * Deletes a Drupal user by ID.
   *
   * @param string $id
   *   The Drupal user ID.
   *
   * @return bool
   *   TRUE when the user existed and was deleted; FALSE when not found.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *   Thrown if entity storage fails.
   */
  public function deleteUser(string $id): bool {
    $user = $this->loadDrupalUser($id);
    if ($user === null) {
      return false;
    }
    $user->delete();
    $this->logger->notice('SCIM: deleted user @uid.', ['@uid' => $id]);
    return true;
  }

  /**
   * Converts a Drupal UserInterface entity to a ScimUser value object.
   *
   * @param \Drupal\user\UserInterface $user
   *   The Drupal user entity.
   *
   * @return \Drupal\scim_bridge\Value\ScimUser
   *   The SCIM User value object.
   */
  public function drupalUserToScimUser(UserInterface $user): ScimUser {
    $attributeMap = $this->getAttributeMap();

    $externalId  = '';
    $displayName = '';
    $givenName   = '';
    $familyName  = '';
    $phone       = '';
    $title       = '';
    $city        = '';
    $country     = '';

    foreach ($attributeMap as $scimAttr => $drupalField) {
      if (!$user->hasField($drupalField)) {
        continue;
      }
      $fieldValue = (string) $user->get($drupalField)->getString();
      match ($scimAttr) {
        'externalId'           => $externalId  = $fieldValue,
        'displayName'          => $displayName  = $fieldValue,
        'name.givenName'       => $givenName    = $fieldValue,
        'name.familyName'      => $familyName   = $fieldValue,
        'phoneNumbers[0].value'=> $phone        = $fieldValue,
        'title'                => $title        = $fieldValue,
        'addresses[0].locality'=> $city         = $fieldValue,
        'addresses[0].country' => $country      = $fieldValue,
        default                => null,
      };
    }

    return new ScimUser(
      id:           (string) $user->id(),
      externalId:   $externalId,
      userName:     $user->getAccountName(),
      displayName:  $displayName !== '' ? $displayName : $user->getDisplayName(),
      givenName:    $givenName,
      familyName:   $familyName,
      primaryEmail: $user->getEmail() ?? '',
      phoneNumber:  $phone,
      title:        $title,
      city:         $city,
      country:      $country,
      active:       $user->isActive(),
    );
  }

  /**
   * Applies scalar attributes from a ScimUser value object to a Drupal user.
   *
   * @param \Drupal\scim_bridge\Value\ScimUser $scimUser
   *   The SCIM User source data.
   * @param \Drupal\user\UserInterface $user
   *   The Drupal user entity to write to.
   */
  private function applyScimUserToEntity(ScimUser $scimUser, UserInterface $user): void {
    if ($scimUser->userName !== '') {
      $user->setUsername($scimUser->userName);
    }
    if ($scimUser->primaryEmail !== '') {
      $user->setEmail($scimUser->primaryEmail);
    }
    $user->setLastAccessTime(0);

    if ($scimUser->active) {
      $user->activate();
    }
    else {
      $user->block();
    }

    $attributeMap = $this->getAttributeMap();

    $writeMap = [
      'displayName'           => $scimUser->displayName,
      'name.givenName'        => $scimUser->givenName,
      'name.familyName'       => $scimUser->familyName,
      'phoneNumbers[0].value' => $scimUser->phoneNumber,
      'title'                 => $scimUser->title,
      'addresses[0].locality' => $scimUser->city,
      'addresses[0].country'  => $scimUser->country,
      'externalId'            => $scimUser->externalId,
    ];

    foreach ($writeMap as $scimAttr => $value) {
      if ($value === '') {
        continue;
      }
      $drupalField = $attributeMap[$scimAttr] ?? null;
      if ($drupalField === null || !$user->hasField($drupalField)) {
        continue;
      }
      $user->set($drupalField, $value);
    }
  }

  /**
   * Applies a single SCIM PATCH operation to the given Drupal user entity.
   *
   * @param \Drupal\scim_bridge\Value\ScimPatchOperation $op
   *   The patch operation to apply.
   * @param \Drupal\user\UserInterface $user
   *   The Drupal user entity to modify.
   * @param array<string, string> $attributeMap
   *   Current SCIM attribute → Drupal field mapping.
   */
  private function applyPatchOperation(ScimPatchOperation $op, UserInterface $user, array $attributeMap): void {
    $attr = $op->path;

    // Handle path-less operations where value is a map of attributes.
    if ($attr === '' && is_array($op->value)) {
      foreach ($op->value as $key => $val) {
        $subOp = new ScimPatchOperation($op->op, (string) $key, $val);
        $this->applyPatchOperation($subOp, $user, $attributeMap);
      }
      return;
    }

    // Normalise bracketed paths: emails[type eq "work"].value → emails[0].value
    $normAttr = (string) preg_replace('/\[[^\]]+\]/', '[0]', $attr);

    switch ($normAttr) {
      case 'active':
        $boolVal = $op->scalarBoolValue();
        if ($boolVal !== null) {
          $boolVal ? $user->activate() : $user->block();
        }
        break;

      case 'userName':
        $str = $op->scalarStringValue();
        if ($str !== null && $str !== '') {
          $user->setUsername($str);
        }
        break;

      case 'emails[0].value':
        $str = $op->scalarStringValue();
        if ($str !== null && $str !== '') {
          $user->setEmail($str);
        }
        break;

      default:
        $drupalField = $attributeMap[$normAttr] ?? $attributeMap[$attr] ?? null;
        if ($drupalField === null || !$user->hasField($drupalField)) {
          break;
        }
        if ($op->op === ScimPatchOperation::OP_REMOVE) {
          $user->set($drupalField, NULL);
        }
        else {
          $str = $op->scalarStringValue();
          if ($str !== null) {
            $user->set($drupalField, $str);
          }
        }
    }
  }

  /**
   * Attempts to find an existing Drupal user matching by userName or email.
   *
   * @param \Drupal\scim_bridge\Value\ScimUser $scimUser
   *   The incoming SCIM User.
   *
   * @return \Drupal\user\UserInterface|null
   *   An existing user or null.
   */
  private function findExistingUser(ScimUser $scimUser): ?UserInterface {
    $storage = $this->entityTypeManager->getStorage('user');

    if ($scimUser->userName !== '') {
      $ids = $storage->getQuery()
        ->accessCheck(FALSE)
        ->condition('name', $scimUser->userName)
        ->execute();
      if (!empty($ids)) {
        return $storage->load(reset($ids));
      }
    }

    if ($scimUser->primaryEmail !== '') {
      $ids = $storage->getQuery()
        ->accessCheck(FALSE)
        ->condition('mail', $scimUser->primaryEmail)
        ->execute();
      if (!empty($ids)) {
        return $storage->load(reset($ids));
      }
    }

    return null;
  }

  /**
   * Loads a Drupal user entity by ID, returning null on failure.
   *
   * @param string $id
   *   Drupal user ID (uid).
   *
   * @return \Drupal\user\UserInterface|null
   *   The loaded user or null.
   */
  private function loadDrupalUser(string $id): ?UserInterface {
    if (!ctype_digit($id) || $id === '0') {
      return null;
    }
    $user = $this->entityTypeManager->getStorage('user')->load((int) $id);
    if (!$user instanceof UserInterface) {
      return null;
    }
    return $user;
  }

  /**
   * Tests whether a ScimUser passes a raw filter string.
   *
   * Used for post-query filtering to handle operators not supported by entity
   * queries (ne, ew, pr, gt, lt, ge, le).
   *
   * @param \Drupal\scim_bridge\Value\ScimUser $scimUser
   *   The SCIM User to test.
   * @param string $filterStr
   *   The raw SCIM filter string.
   *
   * @return bool
   *   TRUE when the user satisfies the filter.
   */
  private function userMatchesFilter(ScimUser $scimUser, string $filterStr): bool {
    $criteria = $this->filterParser->parse($filterStr);
    if ($criteria === null) {
      return true;
    }
    return $this->evaluateCriteria($scimUser, $criteria);
  }

  /**
   * Recursively evaluates parsed filter criteria against a ScimUser.
   *
   * @param \Drupal\scim_bridge\Value\ScimUser $scimUser
   *   The SCIM User to test.
   * @param array<string, mixed> $criteria
   *   Parsed criteria from ScimFilterParser::parse().
   *
   * @return bool
   *   TRUE when the user satisfies the criteria.
   */
  private function evaluateCriteria(ScimUser $scimUser, array $criteria): bool {
    if (isset($criteria['logic'])) {
      $logic      = $criteria['logic'];
      $conditions = (array) ($criteria['conditions'] ?? []);
      if ($logic === 'not') {
        return !$this->evaluateCriteria($scimUser, $conditions[0] ?? []);
      }
      $results = array_map(
        fn(array $c): bool => $this->evaluateCriteria($scimUser, $c),
        $conditions,
      );
      return $logic === 'and' ? !in_array(false, $results, true) : in_array(true, $results, true);
    }

    $attr  = (string) ($criteria['attr'] ?? '');
    $value = $this->getScimUserAttributeValue($scimUser, $attr);
    return $this->filterParser->matchesSimple($value, $criteria);
  }

  /**
   * Returns the value of a SCIM attribute from a ScimUser object.
   *
   * @param \Drupal\scim_bridge\Value\ScimUser $scimUser
   *   The SCIM User.
   * @param string $attr
   *   The SCIM attribute path (dot notation).
   *
   * @return string
   *   The attribute value as a string, or empty string if not found.
   */
  private function getScimUserAttributeValue(ScimUser $scimUser, string $attr): string {
    return match ($attr) {
      'userName'              => $scimUser->userName,
      'emails[0].value',
      'emails.value'          => $scimUser->primaryEmail,
      'displayName'           => $scimUser->displayName,
      'name.givenName'        => $scimUser->givenName,
      'name.familyName'       => $scimUser->familyName,
      'phoneNumbers[0].value',
      'phoneNumbers.value'    => $scimUser->phoneNumber,
      'title'                 => $scimUser->title,
      'addresses[0].locality',
      'addresses.locality'    => $scimUser->city,
      'addresses[0].country',
      'addresses.country'     => $scimUser->country,
      'active'                => $scimUser->active ? 'true' : 'false',
      'externalId'            => $scimUser->externalId,
      'id'                    => $scimUser->id,
      default                 => '',
    };
  }

  /**
   * Returns the SCIM → Drupal attribute map from configuration.
   *
   * @return array<string, string>
   *   Map keyed by SCIM attribute path with Drupal field machine name as value.
   */
  private function getAttributeMap(): array {
    $map = (array) ($this->configFactory->get(self::MAPPING_CONFIG)->get('user_attribute_map') ?? []);
    return array_filter($map, static fn(mixed $v): bool => is_string($v) && $v !== '');
  }

  /**
   * Inverts the attribute map: Drupal field → SCIM attribute path.
   *
   * @param array<string, string> $map
   *   The standard SCIM→Drupal map.
   *
   * @return array<string, string>
   *   Inverted map.
   */
  private function invertAttributeMap(array $map): array {
    return array_flip($map);
  }

  /**
   * Resolves the requested page count against the configured maximum.
   *
   * @param int $requested
   *   The count requested by the IdP.
   *
   * @return int
   *   The effective page count, clamped to configured max_page_size.
   */
  private function resolvePageCount(int $requested): int {
    $max = (int) ($this->configFactory->get(self::SETTINGS_CONFIG)->get('max_page_size') ?? 100);
    $max = max(1, $max);
    if ($requested <= 0) {
      return $max;
    }
    return min($requested, $max);
  }

}
