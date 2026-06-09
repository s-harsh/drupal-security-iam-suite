<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Plugin\IpReputation;

use Drupal\api_flood_guard\Annotation\IpReputationProvider;
use Drupal\api_flood_guard\Contract\IpReputationProviderInterface;
use Drupal\api_flood_guard\Value\IpReputationResult;
use Drupal\Core\Plugin\PluginBase;
use Drupal\Core\StringTranslation\TranslatableMarkup;

/**
 * No-op IP reputation provider used when reputation checks are disabled.
 *
 * Always returns isBlocked = false. Active when no provider is configured.
 */
#[IpReputationProvider(
  id: 'null_provider',
  label: new TranslatableMarkup('None (disabled)'),
  description: new TranslatableMarkup('Disables IP reputation checking. All IPs proceed to flood checks.'),
  api_endpoint: '',
)]
class NullProvider extends PluginBase implements IpReputationProviderInterface {

  /**
   * {@inheritdoc}
   */
  public function checkIp(string $ip): IpReputationResult {
    return IpReputationResult::allowed(providerName: 'null_provider');
  }

  /**
   * {@inheritdoc}
   */
  public function isConfigured(): bool {
    return FALSE;
  }

}
