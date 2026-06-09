<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Plugin\IpReputation;

use Drupal\api_flood_guard\Annotation\IpReputationProvider;
use Drupal\api_flood_guard\Contract\IpReputationProviderInterface;
use Drupal\api_flood_guard\Value\IpReputationResult;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Plugin\PluginBase;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * AbuseIPDB v2 IP reputation provider plugin.
 *
 * Calls the AbuseIPDB v2 check API to evaluate the reputation of a client IP.
 * Responses are cached per-IP in the api_flood_guard cache bin. Fail-open on
 * any provider error: returns isBlocked = false rather than blocking legitimate
 * traffic due to provider unavailability.
 */
#[IpReputationProvider(
  id: 'abuseipdb',
  label: new TranslatableMarkup('AbuseIPDB'),
  description: new TranslatableMarkup('Checks IPs against the AbuseIPDB v2 API. Requires a free or paid API key from https://www.abuseipdb.com'),
  api_endpoint: 'https://api.abuseipdb.com/api/v2/check',
)]
class AbuseIpDb extends PluginBase implements IpReputationProviderInterface, ContainerFactoryPluginInterface {

  public function __construct(
    array $configuration,
    string $plugin_id,
    mixed $plugin_definition,
    private readonly ClientInterface $httpClient,
    private readonly CacheBackendInterface $cache,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('http_client'),
      $container->get('cache.api_flood_guard'),
      $container->get('config.factory'),
      $container->get('logger.channel.api_flood_guard'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function isConfigured(): bool {
    return $this->getApiKey() !== '';
  }

  /**
   * {@inheritdoc}
   */
  public function checkIp(string $ip): IpReputationResult {
    if (!$this->isConfigured()) {
      return IpReputationResult::allowed(providerName: 'abuseipdb');
    }

    $cacheId = 'abuseipdb:' . md5($ip);

    // Check the cache first.
    $cached = $this->cache->get($cacheId);
    if ($cached !== FALSE && isset($cached->data)) {
      $data = $cached->data;
      if ($data['blocked']) {
        return IpReputationResult::blocked(
          score: $data['score'],
          providerName: 'abuseipdb',
          categories: $data['categories'] ?? [],
          fromCache: TRUE,
        );
      }
      return IpReputationResult::allowed(
        score: $data['score'],
        providerName: 'abuseipdb',
        fromCache: TRUE,
      );
    }

    $config = $this->configFactory->get('api_flood_guard.settings');
    $providerConfig = $config->get('reputation_providers.abuseipdb') ?? [];
    $threshold = (int) ($providerConfig['threshold'] ?? 85);
    $maxAgeDays = (int) ($providerConfig['max_age_days'] ?? 30);
    $cacheTtl = (int) ($providerConfig['cache_ttl'] ?? 3600);

    try {
      $response = $this->httpClient->get('https://api.abuseipdb.com/api/v2/check', [
        'headers' => [
          'Key'    => $this->getApiKey(),
          'Accept' => 'application/json',
        ],
        'query' => [
          'ipAddress'    => $ip,
          'maxAgeInDays' => $maxAgeDays,
          'verbose'      => 'false',
        ],
        'timeout'         => 5,
        'connect_timeout' => 3,
      ]);
    }
    catch (GuzzleException $e) {
      $this->logger->warning(
        'AbuseIPDB provider error for IP @ip: @message (fail-open).',
        ['@ip' => $ip, '@message' => $e->getMessage()]
      );
      return IpReputationResult::failOpen('abuseipdb');
    }

    $statusCode = $response->getStatusCode();
    if ($statusCode !== 200) {
      $this->logger->warning(
        'AbuseIPDB returned HTTP @code for IP @ip (fail-open).',
        ['@code' => $statusCode, '@ip' => $ip]
      );
      return IpReputationResult::failOpen('abuseipdb');
    }

    $body = $response->getBody()->getContents();
    $decoded = json_decode($body, TRUE);

    if (!is_array($decoded) || !isset($decoded['data']['abuseConfidenceScore'])) {
      $this->logger->warning(
        'AbuseIPDB returned unexpected response format for IP @ip (fail-open).',
        ['@ip' => $ip]
      );
      return IpReputationResult::failOpen('abuseipdb');
    }

    $score = (int) $decoded['data']['abuseConfidenceScore'];
    $categories = $decoded['data']['reports'] ?? [];
    $isBlocked = $score >= $threshold;

    // Cache the result.
    if ($cacheTtl > 0) {
      $this->cache->set($cacheId, [
        'blocked'    => $isBlocked,
        'score'      => $score,
        'categories' => $categories,
        'timestamp'  => time(),
      ], time() + $cacheTtl);
    }

    if ($isBlocked) {
      return IpReputationResult::blocked(
        score: $score,
        providerName: 'abuseipdb',
        categories: $categories,
      );
    }

    return IpReputationResult::allowed(score: $score, providerName: 'abuseipdb');
  }

  /**
   * Retrieves the AbuseIPDB API key from config or Key module entity.
   */
  private function getApiKey(): string {
    $config = $this->configFactory->get('api_flood_guard.settings');
    $providerConfig = $config->get('reputation_providers.abuseipdb') ?? [];

    // Prefer Key module entity if configured.
    $keyId = $providerConfig['api_key_id'] ?? '';
    if ($keyId !== '' && \Drupal::hasService('key.repository')) {
      /** @var \Drupal\key\KeyRepositoryInterface $keyRepository */
      $keyRepository = \Drupal::service('key.repository');
      $keyEntity = $keyRepository->getKey($keyId);
      if ($keyEntity !== NULL) {
        return (string) $keyEntity->getKeyValue();
      }
    }

    return (string) ($providerConfig['api_key'] ?? '');
  }

}
