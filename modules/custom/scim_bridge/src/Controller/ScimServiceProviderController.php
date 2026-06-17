<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * SCIM 2.0 discovery endpoints controller.
 *
 * Serves the ServiceProviderConfig, ResourceTypes, and Schemas endpoints that
 * Identity Providers use to discover what capabilities and attributes this
 * SCIM server supports.
 *
 * These endpoints are unauthenticated per the SCIM specification (RFC 7644
 * §4) so they can be reached during IdP configuration before tokens exist.
 */
final class ScimServiceProviderController extends ControllerBase {

  /**
   * SCIM Content-Type header value.
   */
  private const SCIM_CONTENT_TYPE = 'application/scim+json';

  /**
   * GET /scim/v2/ServiceProviderConfig.
   *
   * Advertises the SCIM features this server supports. IdPs use this to
   * determine which operations (e.g. bulk, etag, filter) are available.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   The ServiceProviderConfig JSON response.
   */
  public function serviceProviderConfig(): JsonResponse {
    $config = [
      'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      'documentationUri' => 'https://www.drupal.org',
      'patch' => ['supported' => true],
      'bulk'  => [
        'supported'      => false,
        'maxOperations'  => 0,
        'maxPayloadSize' => 0,
      ],
      'filter' => [
        'supported'  => true,
        'maxResults' => 200,
      ],
      'changePassword'    => ['supported' => false],
      'sort'              => ['supported' => false],
      'etag'              => ['supported' => false],
      'authenticationSchemes' => [
        [
          'type'             => 'oauthbearertoken',
          'name'             => 'OAuth Bearer Token',
          'description'      => 'Authentication using a Bearer token in the Authorization header.',
          'specUri'          => 'https://datatracker.ietf.org/doc/html/rfc6750',
          'documentationUri' => 'https://www.drupal.org',
          'primary'          => true,
        ],
      ],
      'meta' => [
        'resourceType' => 'ServiceProviderConfig',
        'location'     => '/scim/v2/ServiceProviderConfig',
      ],
    ];

    return new JsonResponse($config, Response::HTTP_OK, ['Content-Type' => self::SCIM_CONTENT_TYPE]);
  }

  /**
   * GET /scim/v2/ResourceTypes.
   *
   * Lists the resource types (User, Group) this SCIM server supports, along
   * with the schema URNs and endpoint paths for each.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   The ResourceTypes list JSON response.
   */
  public function resourceTypes(): JsonResponse {
    $types = [
      'schemas'      => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      'totalResults' => 2,
      'Resources'    => [
        [
          'schemas'          => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
          'id'               => 'User',
          'name'             => 'User',
          'endpoint'         => '/scim/v2/Users',
          'description'      => 'Drupal user accounts.',
          'schema'           => 'urn:ietf:params:scim:schemas:core:2.0:User',
          'schemaExtensions' => [],
          'meta' => [
            'resourceType' => 'ResourceType',
            'location'     => '/scim/v2/ResourceTypes/User',
          ],
        ],
        [
          'schemas'          => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
          'id'               => 'Group',
          'name'             => 'Group',
          'endpoint'         => '/scim/v2/Groups',
          'description'      => 'Drupal roles exposed as SCIM groups.',
          'schema'           => 'urn:ietf:params:scim:schemas:core:2.0:Group',
          'schemaExtensions' => [],
          'meta' => [
            'resourceType' => 'ResourceType',
            'location'     => '/scim/v2/ResourceTypes/Group',
          ],
        ],
      ],
    ];

    return new JsonResponse($types, Response::HTTP_OK, ['Content-Type' => self::SCIM_CONTENT_TYPE]);
  }

  /**
   * GET /scim/v2/Schemas.
   *
   * Returns the JSON Schema definitions for User and Group resources as
   * defined in RFC 7643 §§4 and 5. IdPs use this to understand the full
   * attribute set available for provisioning.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   The Schemas list JSON response.
   */
  public function schemas(): JsonResponse {
    $schemas = [
      'schemas'      => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      'totalResults' => 2,
      'Resources'    => [
        $this->userSchema(),
        $this->groupSchema(),
      ],
    ];

    return new JsonResponse($schemas, Response::HTTP_OK, ['Content-Type' => self::SCIM_CONTENT_TYPE]);
  }

  // ---------------------------------------------------------------------------
  // Schema definitions
  // ---------------------------------------------------------------------------

  /**
   * Returns the SCIM User schema definition (RFC 7643 §4.1).
   *
   * @return array<string, mixed>
   *   The User schema array.
   */
  private function userSchema(): array {
    return [
      'id'          => 'urn:ietf:params:scim:schemas:core:2.0:User',
      'name'        => 'User',
      'description' => 'User Account',
      'attributes'  => [
        ['name' => 'userName',     'type' => 'string',  'required' => true,  'uniqueness' => 'server', 'multiValued' => false, 'description' => 'Unique identifier for the user (maps to Drupal name).'],
        ['name' => 'displayName',  'type' => 'string',  'required' => false, 'uniqueness' => 'none',   'multiValued' => false, 'description' => 'Display name.'],
        ['name' => 'name',         'type' => 'complex', 'required' => false, 'uniqueness' => 'none',   'multiValued' => false, 'description' => 'Name components.',
          'subAttributes' => [
            ['name' => 'givenName',  'type' => 'string', 'required' => false, 'multiValued' => false],
            ['name' => 'familyName', 'type' => 'string', 'required' => false, 'multiValued' => false],
            ['name' => 'formatted',  'type' => 'string', 'required' => false, 'multiValued' => false],
          ],
        ],
        ['name' => 'emails',       'type' => 'complex', 'required' => false, 'uniqueness' => 'none', 'multiValued' => true,  'description' => 'Email addresses.',
          'subAttributes' => [
            ['name' => 'value',   'type' => 'string',  'required' => false, 'multiValued' => false],
            ['name' => 'type',    'type' => 'string',  'required' => false, 'multiValued' => false],
            ['name' => 'primary', 'type' => 'boolean', 'required' => false, 'multiValued' => false],
          ],
        ],
        ['name' => 'phoneNumbers', 'type' => 'complex', 'required' => false, 'uniqueness' => 'none', 'multiValued' => true,  'description' => 'Phone numbers.',
          'subAttributes' => [
            ['name' => 'value',   'type' => 'string',  'required' => false, 'multiValued' => false],
            ['name' => 'type',    'type' => 'string',  'required' => false, 'multiValued' => false],
            ['name' => 'primary', 'type' => 'boolean', 'required' => false, 'multiValued' => false],
          ],
        ],
        ['name' => 'addresses',    'type' => 'complex', 'required' => false, 'uniqueness' => 'none', 'multiValued' => true,  'description' => 'Addresses.',
          'subAttributes' => [
            ['name' => 'locality', 'type' => 'string', 'required' => false, 'multiValued' => false],
            ['name' => 'country',  'type' => 'string', 'required' => false, 'multiValued' => false],
            ['name' => 'primary',  'type' => 'boolean', 'required' => false, 'multiValued' => false],
          ],
        ],
        ['name' => 'title',     'type' => 'string',  'required' => false, 'uniqueness' => 'none', 'multiValued' => false, 'description' => 'Job title.'],
        ['name' => 'active',    'type' => 'boolean', 'required' => false, 'uniqueness' => 'none', 'multiValued' => false, 'description' => 'Whether the account is active.'],
        ['name' => 'locale',    'type' => 'string',  'required' => false, 'uniqueness' => 'none', 'multiValued' => false, 'description' => 'IETF locale tag.'],
        ['name' => 'timezone',  'type' => 'string',  'required' => false, 'uniqueness' => 'none', 'multiValued' => false, 'description' => 'IANA timezone name.'],
        ['name' => 'externalId','type' => 'string',  'required' => false, 'uniqueness' => 'none', 'multiValued' => false, 'description' => 'IdP-assigned external identifier.'],
      ],
      'meta' => [
        'resourceType' => 'Schema',
        'location'     => '/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User',
      ],
    ];
  }

  /**
   * Returns the SCIM Group schema definition (RFC 7643 §4.2).
   *
   * @return array<string, mixed>
   *   The Group schema array.
   */
  private function groupSchema(): array {
    return [
      'id'          => 'urn:ietf:params:scim:schemas:core:2.0:Group',
      'name'        => 'Group',
      'description' => 'Group (Drupal role)',
      'attributes'  => [
        ['name' => 'displayName', 'type' => 'string',  'required' => true,  'uniqueness' => 'server', 'multiValued' => false, 'description' => 'Human-readable group name (maps to Drupal role label).'],
        ['name' => 'members',     'type' => 'complex', 'required' => false, 'uniqueness' => 'none',   'multiValued' => true,  'description' => 'Group members.',
          'subAttributes' => [
            ['name' => 'value',   'type' => 'string', 'required' => false, 'multiValued' => false],
            ['name' => 'display', 'type' => 'string', 'required' => false, 'multiValued' => false],
          ],
        ],
        ['name' => 'externalId',  'type' => 'string',  'required' => false, 'uniqueness' => 'none',   'multiValued' => false, 'description' => 'IdP-assigned external identifier.'],
      ],
      'meta' => [
        'resourceType' => 'Schema',
        'location'     => '/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group',
      ],
    ];
  }

}
