<?php

declare(strict_types=1);

namespace Drupal\hibp_password_guard\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\hibp_password_guard\Value\HibpRangeResponse;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\TransferException;
use Psr\Log\LoggerInterface;

/**
 * Low-level HTTP wrapper for the HIBP Pwned Passwords Range API.
 *
 * Sends GET requests to {api_base_url}/range/{PREFIX} with the required
 * Add-Padding header. Returns a typed HibpRangeResponse value object.
 *
 * Security note: this class must never log the password, the full SHA-1
 * hash, or the 5-character prefix in association with any user identifier.
 * Log entries contain only exception class names and HTTP status codes.
 */
final class HibpApiClient {

  /**
   * The HIBP settings config object name.
   */
  private const CONFIG_NAME = 'hibp_password_guard.settings';

  /**
   * Constructs an HibpApiClient.
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
   * Fetches the HIBP range response for the given 5-character SHA-1 prefix.
   *
   * Only the prefix is transmitted over the network; no user identifier,
   * password, or full hash is included in the request.
   *
   * @param string $prefix
   *   Exactly 5 uppercase hexadecimal characters derived from a SHA-1 hash.
   *
   * @return \Drupal\hibp_password_guard\Value\HibpRangeResponse
   *   The parsed API response, or an error response on failure.
   */
  public function fetchRange(string $prefix): HibpRangeResponse {
    $config = $this->configFactory->get(self::CONFIG_NAME);
    $baseUrl = rtrim((string) $config->get('api_base_url'), '/');
    $timeout = (int) $config->get('http_timeout');

    $url = $baseUrl . '/range/' . strtoupper($prefix);

    try {
      $response = $this->httpClient->get($url, [
        'headers' => [
          'Add-Padding' => 'true',
        ],
        'timeout' => $timeout,
        'connect_timeout' => $timeout,
      ]);

      $statusCode = $response->getStatusCode();

      if ($statusCode !== 200) {
        $this->logger->notice(
          'HIBP API returned non-200 status @status for range request.',
          ['@status' => $statusCode],
        );
        return new HibpRangeResponse(
          success: false,
          statusCode: $statusCode,
          errorMessage: 'HTTP ' . $statusCode,
        );
      }

      $body = $response->getBody()->getContents();

      return new HibpRangeResponse(
        success: true,
        body: $body,
        statusCode: $statusCode,
      );
    }
    catch (ConnectException $e) {
      $this->logger->notice(
        'HIBP API connection failed: @class',
        ['@class' => ConnectException::class],
      );
      return new HibpRangeResponse(
        success: false,
        statusCode: 0,
        errorMessage: ConnectException::class,
      );
    }
    catch (RequestException $e) {
      $statusCode = $e->hasResponse() ? $e->getResponse()->getStatusCode() : 0;
      $this->logger->notice(
        'HIBP API request failed: @class, HTTP @status',
        ['@class' => RequestException::class, '@status' => $statusCode],
      );
      return new HibpRangeResponse(
        success: false,
        statusCode: $statusCode,
        errorMessage: RequestException::class . ' HTTP ' . $statusCode,
      );
    }
    catch (TransferException $e) {
      $this->logger->notice(
        'HIBP API transfer exception: @class',
        ['@class' => $e::class],
      );
      return new HibpRangeResponse(
        success: false,
        statusCode: 0,
        errorMessage: $e::class,
      );
    }
  }

}
