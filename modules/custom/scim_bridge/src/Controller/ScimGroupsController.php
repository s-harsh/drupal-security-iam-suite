<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Controller;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\scim_bridge\Service\ScimAuthenticator;
use Drupal\scim_bridge\Service\ScimGroupMapper;
use Drupal\scim_bridge\Value\ScimGroup;
use Drupal\scim_bridge\Value\ScimPatchOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * SCIM 2.0 /Groups endpoint controller.
 *
 * Handles GET (list + get), POST (create), PUT (replace), PATCH, and DELETE
 * operations on Group resources (backed by Drupal roles) as defined in
 * RFC 7644 §3.
 */
final class ScimGroupsController extends ControllerBase {

  /**
   * SCIM Content-Type header value.
   */
  private const SCIM_CONTENT_TYPE = 'application/scim+json';

  /**
   * Constructs a ScimGroupsController.
   *
   * @param \Drupal\scim_bridge\Service\ScimAuthenticator $authenticator
   *   The SCIM Bearer token authenticator.
   * @param \Drupal\scim_bridge\Service\ScimGroupMapper $groupMapper
   *   The SCIM group mapper service.
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection for sync log writes.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   */
  public function __construct(
    private readonly ScimAuthenticator $authenticator,
    private readonly ScimGroupMapper $groupMapper,
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('scim_bridge.authenticator'),
      $container->get('scim_bridge.group_mapper'),
      $container->get('database'),
      $container->get('config.factory'),
    );
  }

  /**
   * Access callback for all /scim/v2/Groups routes.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function access(Request $request): AccessResultInterface {
    $idp = $this->authenticator->authenticate($request);
    return $idp !== null
      ? AccessResult::allowed()->setCacheMaxAge(0)
      : AccessResult::forbidden()->setCacheMaxAge(0);
  }

  /**
   * Handles GET /scim/v2/Groups and POST /scim/v2/Groups.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   A SCIM-formatted JSON response.
   */
  public function collection(Request $request): JsonResponse {
    $idp = $this->authenticator->authenticate($request);
    if ($idp === null) {
      return $this->scimError('Unauthorized', 'invalidCredentials', Response::HTTP_UNAUTHORIZED);
    }

    return match ($request->getMethod()) {
      'GET'   => $this->handleList($request, $idp),
      'POST'  => $this->handleCreate($request, $idp),
      default => $this->scimError('Method Not Allowed', 'invalidValue', Response::HTTP_METHOD_NOT_ALLOWED),
    };
  }

  /**
   * Handles GET /scim/v2/Groups/{id}, PUT, PATCH, and DELETE.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   * @param string $id
   *   The Drupal role machine name from the route.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   A SCIM-formatted JSON response.
   */
  public function item(Request $request, string $id): JsonResponse {
    $idp = $this->authenticator->authenticate($request);
    if ($idp === null) {
      return $this->scimError('Unauthorized', 'invalidCredentials', Response::HTTP_UNAUTHORIZED);
    }

    return match ($request->getMethod()) {
      'GET'    => $this->handleGet($id, $idp),
      'PUT'    => $this->handleReplace($request, $id, $idp),
      'PATCH'  => $this->handlePatch($request, $id, $idp),
      'DELETE' => $this->handleDelete($id, $idp),
      default  => $this->scimError('Method Not Allowed', 'invalidValue', Response::HTTP_METHOD_NOT_ALLOWED),
    };
  }

  // ---------------------------------------------------------------------------
  // Private dispatch methods
  // ---------------------------------------------------------------------------

  /**
   * Handles GET /scim/v2/Groups (list).
   */
  private function handleList(Request $request, string $idp): JsonResponse {
    $body = $this->groupMapper->listGroups($request);
    $this->log('list', 'Group', null, null, 200, $idp);
    return $this->scimResponse($body);
  }

  /**
   * Handles POST /scim/v2/Groups (create).
   */
  private function handleCreate(Request $request, string $idp): JsonResponse {
    $data = $this->parseJson($request);
    if ($data === null) {
      return $this->scimError('Invalid JSON body', 'invalidValue', Response::HTTP_BAD_REQUEST);
    }

    $scimGroup = ScimGroup::fromArray($data);
    if ($scimGroup->displayName === '') {
      return $this->scimError('displayName is required', 'invalidValue', Response::HTTP_BAD_REQUEST);
    }

    try {
      $result = $this->groupMapper->createGroup($scimGroup);
    }
    catch (\Throwable $e) {
      return $this->scimError('Internal Server Error', 'invalidValue', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    $status = $result['created'] ? Response::HTTP_CREATED : Response::HTTP_OK;
    $this->log('create', 'Group', $result['scimGroup']->externalId, $result['scimGroup']->id, $status, $idp);
    return $this->scimResponse($result['scimGroup']->toScimArray(), $status);
  }

  /**
   * Handles GET /scim/v2/Groups/{id}.
   */
  private function handleGet(string $id, string $idp): JsonResponse {
    $scimGroup = $this->groupMapper->getGroup($id);
    if ($scimGroup === null) {
      $this->log('get', 'Group', null, $id, 404, $idp);
      return $this->scimError('Group not found', 'notFound', Response::HTTP_NOT_FOUND);
    }
    $this->log('get', 'Group', $scimGroup->externalId, $id, 200, $idp);
    return $this->scimResponse($scimGroup->toScimArray());
  }

  /**
   * Handles PUT /scim/v2/Groups/{id} (replace).
   */
  private function handleReplace(Request $request, string $id, string $idp): JsonResponse {
    $data = $this->parseJson($request);
    if ($data === null) {
      return $this->scimError('Invalid JSON body', 'invalidValue', Response::HTTP_BAD_REQUEST);
    }

    try {
      $scimGroup = $this->groupMapper->replaceGroup($id, ScimGroup::fromArray($data));
    }
    catch (\Throwable) {
      return $this->scimError('Internal Server Error', 'invalidValue', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    if ($scimGroup === null) {
      $this->log('update', 'Group', null, $id, 404, $idp);
      return $this->scimError('Group not found', 'notFound', Response::HTTP_NOT_FOUND);
    }

    $this->log('update', 'Group', $scimGroup->externalId, $id, 200, $idp);
    return $this->scimResponse($scimGroup->toScimArray());
  }

  /**
   * Handles PATCH /scim/v2/Groups/{id}.
   */
  private function handlePatch(Request $request, string $id, string $idp): JsonResponse {
    $data = $this->parseJson($request);
    if ($data === null) {
      return $this->scimError('Invalid JSON body', 'invalidValue', Response::HTTP_BAD_REQUEST);
    }

    $rawOps = (array) ($data['Operations'] ?? []);
    if (empty($rawOps)) {
      return $this->scimError('No Operations provided', 'invalidValue', Response::HTTP_BAD_REQUEST);
    }

    $operations = array_map(
      static fn(mixed $o): ScimPatchOperation => ScimPatchOperation::fromArray(is_array($o) ? $o : []),
      $rawOps,
    );

    try {
      $scimGroup = $this->groupMapper->patchGroup($id, $operations);
    }
    catch (\Throwable) {
      return $this->scimError('Internal Server Error', 'invalidValue', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    if ($scimGroup === null) {
      $this->log('patch', 'Group', null, $id, 404, $idp);
      return $this->scimError('Group not found', 'notFound', Response::HTTP_NOT_FOUND);
    }

    $this->log('patch', 'Group', $scimGroup->externalId, $id, 200, $idp);
    return $this->scimResponse($scimGroup->toScimArray());
  }

  /**
   * Handles DELETE /scim/v2/Groups/{id}.
   */
  private function handleDelete(string $id, string $idp): JsonResponse {
    try {
      $deleted = $this->groupMapper->deleteGroup($id);
    }
    catch (\Throwable) {
      return $this->scimError('Internal Server Error', 'invalidValue', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    if (!$deleted) {
      $this->log('delete', 'Group', null, $id, 404, $idp);
      return $this->scimError('Group not found or cannot be deleted', 'notFound', Response::HTTP_NOT_FOUND);
    }

    $this->log('delete', 'Group', null, $id, 204, $idp);
    return new JsonResponse(null, Response::HTTP_NO_CONTENT, ['Content-Type' => self::SCIM_CONTENT_TYPE]);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Returns a successful SCIM JSON response.
   */
  private function scimResponse(array $data, int $status = Response::HTTP_OK): JsonResponse {
    return new JsonResponse($data, $status, ['Content-Type' => self::SCIM_CONTENT_TYPE]);
  }

  /**
   * Returns a SCIM error JSON response.
   */
  private function scimError(string $detail, string $scimType, int $status): JsonResponse {
    return new JsonResponse([
      'schemas'  => ['urn:ietf:params:scim:api:messages:2.0:Error'],
      'detail'   => $detail,
      'scimType' => $scimType,
      'status'   => (string) $status,
    ], $status, ['Content-Type' => self::SCIM_CONTENT_TYPE]);
  }

  /**
   * Decodes the JSON request body, returning null on failure.
   */
  private function parseJson(Request $request): ?array {
    $body = $request->getContent();
    if ($body === '') {
      return null;
    }
    try {
      $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    }
    catch (\JsonException) {
      return null;
    }
    return is_array($data) ? $data : null;
  }

  /**
   * Writes an entry to the SCIM sync log table.
   */
  private function log(
    string $operation,
    string $resourceType,
    ?string $scimId,
    ?string $drupalId,
    int $httpStatus,
    string $idpLabel,
    string $detail = '',
  ): void {
    $settings = $this->configFactory->get('scim_bridge.settings');
    if (!(bool) $settings->get('sync_log_enabled')) {
      return;
    }
    try {
      $this->database->insert('scim_bridge_sync_log')
        ->fields([
          'timestamp'     => time(),
          'operation'     => $operation,
          'resource_type' => $resourceType,
          'scim_id'       => $scimId,
          'drupal_id'     => $drupalId,
          'http_status'   => $httpStatus,
          'idp_label'     => $idpLabel,
          'detail'        => $detail,
        ])
        ->execute();
    }
    catch (\Throwable) {
      // Log failure must never break the SCIM response.
    }
  }

}
