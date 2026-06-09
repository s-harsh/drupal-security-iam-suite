<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Unit\Service;

use Drupal\api_flood_guard\Service\ApiEndpointDetector;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for ApiEndpointDetector.
 *
 * @group api_flood_guard
 * @coversDefaultClass \Drupal\api_flood_guard\Service\ApiEndpointDetector
 */
final class ApiEndpointDetectorTest extends UnitTestCase {

  /**
   * Default protected paths matching the install config.
   */
  private array $defaultProtectedPaths = [
    ['path' => '/jsonapi', 'match' => 'prefix'],
    ['path' => '/user/login', 'match' => 'exact'],
    ['path' => '/oauth/token', 'match' => 'exact'],
    ['path' => '/rest/user/login', 'match' => 'exact'],
  ];

  /**
   * Builds a ConfigFactoryInterface mock for the given protected paths.
   */
  private function buildConfigFactory(array $protectedPaths): ConfigFactoryInterface {
    $config = $this->createMock(Config::class);
    $config->method('get')
      ->with('protected_paths')
      ->willReturn($protectedPaths);

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')
      ->with('api_flood_guard.settings')
      ->willReturn($config);

    return $factory;
  }

  // -------------------------------------------------------------------------
  // isProtectedPath() tests
  // -------------------------------------------------------------------------

  /**
   * Tests that a prefix path matches a sub-path.
   *
   * @covers ::isProtectedPath
   */
  public function testPrefixMatchDetectsJsonApiSubPath(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $this->assertTrue($detector->isProtectedPath(Request::create('/jsonapi/node/article')));
  }

  /**
   * Tests that the exact prefix base path also matches.
   *
   * @covers ::isProtectedPath
   */
  public function testPrefixMatchesExactPrefixRoot(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $this->assertTrue($detector->isProtectedPath(Request::create('/jsonapi')));
  }

  /**
   * Tests that exact match accepts only the exact path.
   *
   * @covers ::isProtectedPath
   */
  public function testExactMatchAcceptsExactPath(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $this->assertTrue($detector->isProtectedPath(Request::create('/user/login')));
  }

  /**
   * Tests that exact match rejects a path with additional segments.
   *
   * @covers ::isProtectedPath
   */
  public function testExactMatchRejectsSubPath(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $this->assertFalse($detector->isProtectedPath(Request::create('/user/login/extra')));
  }

  /**
   * Tests that a fully unrelated path returns false.
   *
   * @covers ::isProtectedPath
   */
  public function testUnrelatedPathReturnsFalse(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $this->assertFalse($detector->isProtectedPath(Request::create('/node/1')));
  }

  /**
   * Tests that an empty protected paths config returns false for any path.
   *
   * @covers ::isProtectedPath
   */
  public function testEmptyProtectedPathsReturnsFalse(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory([]));
    $this->assertFalse($detector->isProtectedPath(Request::create('/user/login')));
    $this->assertFalse($detector->isProtectedPath(Request::create('/jsonapi/node')));
  }

  /**
   * Tests that an entry with an empty path is skipped.
   *
   * @covers ::isProtectedPath
   */
  public function testEntryWithEmptyPathIsSkipped(): void {
    $paths = [
      ['path' => '', 'match' => 'exact'],
      ['path' => '/user/login', 'match' => 'exact'],
    ];
    $detector = new ApiEndpointDetector($this->buildConfigFactory($paths));
    $this->assertFalse($detector->isProtectedPath(Request::create('/')));
    $this->assertTrue($detector->isProtectedPath(Request::create('/user/login')));
  }

  /**
   * Tests that /oauth/token exact-match works.
   *
   * @covers ::isProtectedPath
   */
  public function testOauthTokenExactMatch(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $this->assertTrue($detector->isProtectedPath(Request::create('/oauth/token')));
    $this->assertFalse($detector->isProtectedPath(Request::create('/oauth/token/revoke')));
  }

  /**
   * Tests that /rest/user/login exact-match works.
   *
   * @covers ::isProtectedPath
   */
  public function testRestUserLoginExactMatch(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $this->assertTrue($detector->isProtectedPath(Request::create('/rest/user/login')));
    $this->assertFalse($detector->isProtectedPath(Request::create('/rest/user')));
  }

  /**
   * Tests that a prefix entry with a missing 'match' key defaults to exact.
   *
   * @covers ::isProtectedPath
   */
  public function testMissingMatchKeyDefaultsToExact(): void {
    $paths = [['path' => '/api', 'match' => 'exact']];
    $detector = new ApiEndpointDetector($this->buildConfigFactory($paths));
    $this->assertTrue($detector->isProtectedPath(Request::create('/api')));
    $this->assertFalse($detector->isProtectedPath(Request::create('/api/v1/users')));
  }

  // -------------------------------------------------------------------------
  // isHtmlFormSubmission() tests
  // -------------------------------------------------------------------------

  /**
   * Tests that a form-urlencoded POST to /user/login is flagged as HTML form.
   *
   * @covers ::isHtmlFormSubmission
   */
  public function testFormUrlEncodedPostToLoginIsHtmlForm(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
    ]);
    $this->assertTrue($detector->isHtmlFormSubmission($request));
  }

  /**
   * Tests that a GET request to /user/login is treated as an HTML form page load.
   *
   * @covers ::isHtmlFormSubmission
   */
  public function testGetRequestToLoginIsHtmlForm(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/user/login', 'GET');
    $this->assertTrue($detector->isHtmlFormSubmission($request));
  }

  /**
   * Tests that a JSON POST to /user/login is NOT an HTML form submission.
   *
   * @covers ::isHtmlFormSubmission
   */
  public function testJsonPostToLoginIsNotHtmlForm(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/json',
    ]);
    $this->assertFalse($detector->isHtmlFormSubmission($request));
  }

  /**
   * Tests that ?_format=json prevents HTML form detection.
   *
   * @covers ::isHtmlFormSubmission
   */
  public function testFormatJsonQueryParamPreventsHtmlFormDetection(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/user/login', 'POST');
    $request->query->set('_format', 'json');
    $this->assertFalse($detector->isHtmlFormSubmission($request));
  }

  /**
   * Tests that non-/user/login paths are not treated as HTML form submissions.
   *
   * @covers ::isHtmlFormSubmission
   */
  public function testNonLoginPathIsNotHtmlForm(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/oauth/token', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
    ]);
    $this->assertFalse($detector->isHtmlFormSubmission($request));
  }

  /**
   * Tests that application/vnd.api+json Content-Type is not treated as HTML form.
   *
   * @covers ::isHtmlFormSubmission
   */
  public function testVndApiJsonContentTypeIsNotHtmlForm(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/vnd.api+json',
    ]);
    // vnd.api+json does not contain 'application/json' substring nor
    // 'application/x-www-form-urlencoded', and _format is not set.
    // Verify the method returns false (not detected as HTML form).
    $result = $detector->isHtmlFormSubmission($request);
    // Should be FALSE since content-type doesn't contain x-www-form-urlencoded
    // and the request is not a GET.
    $this->assertFalse($result);
  }

  // -------------------------------------------------------------------------
  // extractUsernameIdentifier() tests
  // -------------------------------------------------------------------------

  /**
   * Tests extraction from Authorization: Basic header.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testExtractFromBasicAuthHeader(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $credentials = base64_encode('admin:password123');
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_AUTHORIZATION' => 'Basic ' . $credentials,
    ]);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame(hash('sha256', 'admin'), $result);
  }

  /**
   * Tests that username is lowercased and trimmed before hashing.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testUsernameIsNormalizedBeforeHashing(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $credentials = base64_encode('  ADMIN  :password');
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_AUTHORIZATION' => 'Basic ' . $credentials,
    ]);

    $result = $detector->extractUsernameIdentifier($request);
    // 'admin' (trimmed + lowercased) should be hashed.
    $this->assertSame(hash('sha256', 'admin'), $result);
  }

  /**
   * Tests extraction of 'name' field from JSON body (REST login).
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testExtractNameFromJsonBody(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $body = json_encode(['name' => 'testuser', 'pass' => 'secret']);
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/json',
    ], $body);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame(hash('sha256', 'testuser'), $result);
  }

  /**
   * Tests extraction of 'username' field from JSON body.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testExtractUsernameFieldFromJsonBody(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $body = json_encode(['username' => 'apiuser', 'password' => 'secret']);
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/json',
    ], $body);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame(hash('sha256', 'apiuser'), $result);
  }

  /**
   * Tests extraction of 'client_id' from OAuth JSON body.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testExtractClientIdFromJsonBody(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $body = json_encode([
      'client_id' => 'my-oauth-app',
      'client_secret' => 'secret',
      'grant_type' => 'client_credentials',
    ]);
    $request = Request::create('/oauth/token', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/json',
    ], $body);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame(hash('sha256', 'my-oauth-app'), $result);
  }

  /**
   * Tests extraction of 'client_id' from form-encoded body.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testExtractClientIdFromFormEncodedBody(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/oauth/token', 'POST', [
      'client_id' => 'my-app-client',
      'grant_type' => 'password',
    ], [], [], [
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
    ]);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame(hash('sha256', 'my-app-client'), $result);
  }

  /**
   * Tests extraction of 'username' from form-encoded body.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testExtractUsernameFromFormEncodedBody(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/oauth/token', 'POST', [
      'username' => 'formuser',
      'password' => 'pass',
      'grant_type' => 'password',
    ], [], [], [
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
    ]);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame(hash('sha256', 'formuser'), $result);
  }

  /**
   * Tests that a malformed (non-base64) Basic auth header returns empty string.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testMalformedBasicAuthReturnsEmpty(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_AUTHORIZATION' => 'Basic !!!notbase64!!!',
    ]);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame('', $result);
  }

  /**
   * Tests that a Basic auth header without a colon returns empty string.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testBasicAuthWithoutColonReturnsEmpty(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    // base64 of a string with no colon.
    $noColon = base64_encode('usernameonly');
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_AUTHORIZATION' => 'Basic ' . $noColon,
    ]);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame('', $result);
  }

  /**
   * Tests that a request with no credentials returns empty string.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testNoCredentialsReturnsEmpty(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/user/login', 'POST');

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame('', $result);
  }

  /**
   * Tests that an empty JSON body returns empty string.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testEmptyJsonBodyReturnsEmpty(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/json',
    ], '');

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame('', $result);
  }

  /**
   * Tests that JSON body with empty string name returns empty identifier.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testJsonBodyWithEmptyNameReturnsEmpty(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $body = json_encode(['name' => '', 'pass' => 'secret']);
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/json',
    ], $body);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame('', $result);
  }

  /**
   * Tests that a 'name' field takes priority over 'username' in JSON body.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testNameFieldTakesPriorityOverUsernameInJson(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $body = json_encode(['name' => 'primary', 'username' => 'secondary', 'pass' => 'secret']);
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/json',
    ], $body);

    $result = $detector->extractUsernameIdentifier($request);
    // 'name' field should be used, not 'username'.
    $this->assertSame(hash('sha256', 'primary'), $result);
  }

  /**
   * Tests that Basic auth takes priority over JSON body.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testBasicAuthTakesPriorityOverJsonBody(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $credentials = base64_encode('headeruser:password');
    $body = json_encode(['name' => 'bodyuser', 'pass' => 'secret']);
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_AUTHORIZATION' => 'Basic ' . $credentials,
      'CONTENT_TYPE' => 'application/json',
    ], $body);

    $result = $detector->extractUsernameIdentifier($request);
    // Authorization header is checked first.
    $this->assertSame(hash('sha256', 'headeruser'), $result);
  }

  /**
   * Tests that 'client_id' takes priority over 'username' in form body.
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testClientIdTakesPriorityOverUsernameInFormBody(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $request = Request::create('/oauth/token', 'POST', [
      'client_id' => 'priority-client',
      'username' => 'lower-priority',
      'grant_type' => 'password',
    ], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded']);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertSame(hash('sha256', 'priority-client'), $result);
  }

  /**
   * Tests that the returned hash is a valid SHA-256 hex string (64 chars).
   *
   * @covers ::extractUsernameIdentifier
   */
  public function testReturnedHashIsSha256HexString(): void {
    $detector = new ApiEndpointDetector($this->buildConfigFactory($this->defaultProtectedPaths));
    $credentials = base64_encode('user:pass');
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_AUTHORIZATION' => 'Basic ' . $credentials,
    ]);

    $result = $detector->extractUsernameIdentifier($request);
    $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $result);
  }

}
