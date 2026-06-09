<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Annotation;

use Drupal\Component\Annotation\Plugin;
use Drupal\Core\StringTranslation\TranslatableMarkup;

/**
 * Defines the IpReputationProvider annotation for plugin discovery.
 *
 * @Annotation
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
class IpReputationProvider extends Plugin {

  /**
   * The plugin ID.
   */
  public string $id;

  /**
   * A human-readable label for the provider.
   */
  public TranslatableMarkup|string $label;

  /**
   * A human-readable description of the provider.
   */
  public TranslatableMarkup|string $description = '';

  /**
   * The external API endpoint URL (for documentation purposes).
   */
  public string $api_endpoint = '';

}
