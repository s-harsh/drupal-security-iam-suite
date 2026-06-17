<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Controller;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\scim_bridge\Service\ScimAuthenticator;
use Drupal\scim_bridge\Service\ScimUserMapper;
use Drupal\scim_bridge\Value\ScimPatchOperation;
use Drupal\scim_bridge\Value\ScimUser;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * SCIM 2.0 /Users endpoint controller.
 *
 * Handles GET (list + get), POST (create), PUT (replace), PATCH, and DELETE
 * operations on User resources as defined in RFC 7644 §3.
 *
 * All responses are JSON encoded with Content-Type: application/scim+json.
 * Error responses follow the SCIM Error schema (RFC 7644 §3.12).
 */
final class ScimUsersController extends ControllerBase {

  /**
   * SCIM Content-Type header value.
   */
  private const SCIM_CONTENT_TYPE = 'application/scim+json';

  /**
   * Constructs a ScimUsersController.
   *
   * @param \Drupal\scim_bridge\Service\ScimAuthenticator $authenticator
   *   The SCIM Bearer token authenticator.
   * @param \Drupal\scim_bridge\Service\ScimUserMapper $userMapper
   *   The SCIM user mapper service.
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection for sync log writes.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   */
  public function __construct(
    private readonly ScimAuthenticator $authenticator,
    private readonly ScimUserMapper $userMapper,
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('scim_bridge.authenticator'),
      $container->get('scim_bridge.user_mapper'),
      $container->get('database'),
      $container->get('config.factory'),
    );
  }

  /**
   * Access callback for all /scim/v2/Users routes.
   *
   * Returns AccessResult::allowed() when a valid Bearer token is presented,
   * AccessResult::forbidden() otherwise. This callback is called by Drupal's
   * access manager before the controller method is dispatched.
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
   * Handles GET /scim/v2/Users and POST /scim/v2/Users.
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
      'GET'  => $this->handleList($request, $idp),
      'POST' => $this->handleCreate($request, $idp),
      default => $this->scimError('Method Not Allowed', 'invalidValue', Response::HTTP_METHOD_NOT_ALLOWED),
    };
  }

  /**
   * Handles GET /scim/v2/Users/{id}, PUT, PATCH, and DELETE.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   * @param string $id
   *   The Drupal user ID from the route.
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
   * Handles GET /scim/v2/Users (list).
   */
  private function handleList(Request $request, string $idp): JsonResponse {
    $body   = $this->userMapper->listUsers($request);
    $status = Response::HTTP_OK;
    $this->log('list', 'User', null, null, $status, $idp);
    return $this->scimResponse($body, $status);
  }

  /**
   * Handles POST /scim/v2/Users (create).
   */
  private function handleCreate(Request $request, string $idp): JsonResponse {
    $data = $this->parseJson($request);
    if ($data === null) {
      return $this->scimError('Invalid JSON body', 'invalidValue', Response::HTTP_BAD_REQUEST);
    }

    $scimUser = ScimUser::fromArray($data);
    if ($scimUser->userName === '' && $scimUser->primaryEmail === '') {
      return $this->scimError('userName or email is required', 'invalidValue', Response::HTTP_BAD_REQUEST);
    }

    try {
      $result = $this->userMapper->createUser($scimUser);
    }
    catch (\Throwable $e) {
      $this->log('create', 'User', null, null, 500, $idp, $e->getMessage());
      return $this->scimError('Internal Server Error', 'invalidValue', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    $status = $result['conflict'] ? Response::HTTP_OK : Response::HTTP_CREATED;
    $this->log('create', 'User', $result['scimUser']->externalId, $result['scimUser']->id, $status, $idp);
    return $this->scimResponse($result['scimUser']->toScimArray(), $status);
  }

  /**
   * Handles GET /scim/v2/Users/{id} (get single).
   */
  private function handleGet(string $id, string $idp): JsonResponse {
    $scimUser = $this->userMapper->getUser($id);
    if ($scimUser === null) {
      $this->log('get', 'User', null, $id, 404, $idp);
      return $this->scimError('User not found', 'notFound', Response::HTTP_NOT_FOUND);
    }
    $this->log('get', 'User', $scimUser->externalId, $id, 200, $idp);
    return $this->scimResponse($scimUser->toScimArray());
  }

  /**
   * Handles PUT /scim/v2/Users/{id} (replace).
   */
  private function handleReplace(Request $request, string $id, string $idp): JsonResponse {
    $data = $this->parseJson($request);
    if ($data === null) {
      return $this->scimError('Invalid JSON body', 'invalidValue', Response::HTTP_BAD_REQUEST);
    }

    try {
      $scimUser = $this->userMapper->replaceUser($id, ScimUser::fromArray($data));
    }
    catch (\Throwable $e) {
      return $this->scimError('Internal Server Error', 'invalidValue', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    if ($scimUser === null) {
      $this->log('update', 'User', null, $id, 404, $idp);
      return $this->scimError('User not found', 'notFound', Response::HTTP_NOT_FOUND);
    }

    $this->log('update', 'User', $scimUser->externalId, $id, 200, $idp);
    return $this->scimResponse($scimUser->toScimArray());
  }

  /**
   * Handles PATCH /scim/v2/Users/{id}.
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
      $scimUser = $this->userMapper->patchUser($id, $operations);
    }
    catch (\Throwable $e) {
      return $this->scimError('Internal Server Error', 'invalidValue', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    if ($scimUser === null) {
      $this->log('patch', 'User', null, $id, 404, $idp);
      return $this->scimError('User not found', 'notFound', Response::HTTP_NOT_FOUND);
    }

    $this->log('patch', 'User', $scimUser->externalId, $id, 200, $idp);
    return $this->scimResponse($scimUser->toScimArray());
  }

  /**
   * Handles DELETE /scim/v2/Users/{id}.
   */
  private function handleDelete(string $id, string $idp): JsonResponse {
    try {
      $deleted = $this->userMapper->deleteUser($id);
    }
    catch (\Throwable $e) {
      return $this->scimError('Internal Server Error', 'invalidValue', Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    if (!$deleted) {
      $this->log('delete', 'User', null, $id, 404, $idp);
      return $this->scimError('User not found', 'notFound', Response::HTTP_NOT_FOUND);
    }

    $this->log('delete', 'User', null, $id, 204, $idp);
    return new JsonResponse(null, Response::HTTP_NO_CONTENT, ['Content-Type' => self::SCIM_CONTENT_TYPE]);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Returns a successful SCIM JSON response.
   *
   * @param array<string, mixed> $data
   *   The response data array.
   * @param int $status
   *   HTTP status code (default 200).
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   The JSON response.
   */
  private function scimResponse(array $data, int $status = Response::HTTP_OK): JsonResponse {
    return new JsonResponse($data, $status, ['Content-Type' => self::SCIM_CONTENT_TYPE]);
  }

  /**
   * Returns a SCIM error JSON response.
   *
   * @param string $detail
   *   Human-readable error message.
   * @param string $scimType
   *   SCIM error type (RFC 7644 §3.12).
   * @param int $status
   *   HTTP status code.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   The error JSON response.
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
   * Decodes the JSON request body.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   *
   * @return array<string, mixed>|null
   *   Decoded data array, or null on parse failure.
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
   *
   * @param string $operation
   *   The operation type (list, create, update, patch, delete, get).
   * @param string $resourceType
   *   'User' or 'Group'.
   * @param string|null $scimId
   *   The SCIM externalId or null.
   * @param string|null $drupalId
   *   The Drupal entity ID or null.
   * @param int $httpStatus
   *   HTTP response status code.
   * @param string $idpLabel
   *   The IdP label string.
   * @param string $detail
   *   Optional detail or error message.
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
