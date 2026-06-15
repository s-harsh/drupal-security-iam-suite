<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\sbom_sentinel\Value\SbomComponent;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\TransferException;
use Psr\Log\LoggerInterface;

/**
 * Low-level HTTP wrapper for the OSV.dev Vulnerability Query API.
 *
 * Sends POST requests to {api_base_url}/query for each SBOM component,
 * returning the raw vulnerability list from OSV.dev. Network errors are
 * caught and logged without re-throwing so callers can degrade gracefully.
 *
 * API reference: https://google.github.io/osv.dev/post-v1-query/
 */
final class OsvApiClient {

  /**
   * The module settings config object name.
   */
  private const CONFIG_NAME = 'sbom_sentinel.settings';

  /**
   * Constructs an OsvApiClient.
   *
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   The Drupal HTTP client (Guzzle).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The module logger channel.
   */
  public function __construct(
    private readonly ClientInterface $httpClient,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Queries OSV.dev for known vulnerabilities affecting the given component.
   *
   * The query uses the package name and version. OSV.dev accepts Packagist
   * ecosystem ("Packagist") queries for Composer packages.
   *
   * @param \Drupal\sbom_sentinel\Value\SbomComponent $component
   *   The SBOM component to query.
   *
   * @return array{
   *   success: bool,
   *   vulnerabilities: array<int, array<string, mixed>>,
   *   error_message: string,
   * }
   *   An associative array with keys:
   *   - success: TRUE when the API call succeeded.
   *   - vulnerabilities: Raw OSV vulnerability array (may be empty).
   *   - error_message: Non-empty string on failure, empty string on success.
   */
  public function queryComponent(SbomComponent $component): array {
    $config = $this->configFactory->get(self::CONFIG_NAME);
    $baseUrl = rtrim((string) $config->get('osv_api_base_url'), '/');
    $timeout = (int) $config->get('http_timeout');

    $url = $baseUrl . '/query';

    $payload = [
      'version' => $component->version,
      'package' => [
        'name' => $component->name,
        'ecosystem' => 'Packagist',
      ],
    ];

    try {
      $response = $this->httpClient->post($url, [
        'json' => $payload,
        'headers' => [
          'Content-Type' => 'application/json',
          'Accept' => 'application/json',
        ],
        'timeout' => $timeout,
        'connect_timeout' => $timeout,
      ]);

      $statusCode = $response->getStatusCode();

      if ($statusCode !== 200) {
        $this->logger->notice(
          'OSV API returned non-200 status @status for package @package.',
          ['@status' => $statusCode, '@package' => $component->name],
        );
        return [
          'success' => FALSE,
          'vulnerabilities' => [],
          'error_message' => 'HTTP ' . $statusCode,
        ];
      }

      $body = $response->getBody()->getContents();
      $decoded = json_decode($body, associative: true);

      if (!is_array($decoded)) {
        $this->logger->notice(
          'OSV API returned non-JSON body for package @package.',
          ['@package' => $component->name],
        );
        return [
          'success' => FALSE,
          'vulnerabilities' => [],
          'error_message' => 'Invalid JSON response',
        ];
      }

      $vulns = $decoded['vulns'] ?? [];
      if (!is_array($vulns)) {
        $vulns = [];
      }

      return [
        'success' => TRUE,
        'vulnerabilities' => $vulns,
        'error_message' => '',
      ];
    }
    catch (ConnectException $e) {
      $this->logger->notice(
        'OSV API connection failed for package @package: @class',
        ['@package' => $component->name, '@class' => ConnectException::class],
      );
      return [
        'success' => FALSE,
        'vulnerabilities' => [],
        'error_message' => ConnectException::class,
      ];
    }
    catch (RequestException $e) {
      $statusCode = $e->hasResponse() ? $e->getResponse()->getStatusCode() : 0;
      $this->logger->notice(
        'OSV API request failed for package @package: @class HTTP @status',
        [
          '@package' => $component->name,
          '@class' => RequestException::class,
          '@status' => $statusCode,
        ],
      );
      return [
        'success' => FALSE,
        'vulnerabilities' => [],
        'error_message' => RequestException::class . ' HTTP ' . $statusCode,
      ];
    }
    catch (TransferException $e) {
      $this->logger->notice(
        'OSV API transfer exception for package @package: @class',
        ['@package' => $component->name, '@class' => $e::class],
      );
      return [
        'success' => FALSE,
        'vulnerabilities' => [],
        'error_message' => $e::class,
      ];
    }
  }

}
