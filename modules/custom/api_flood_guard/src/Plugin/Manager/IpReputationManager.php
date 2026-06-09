<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Plugin\Manager;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Plugin\DefaultPluginManager;

/**
 * Plugin manager for IpReputationProvider plugins.
 *
 * Discovers plugins in Plugin/IpReputation/ directories of all enabled modules
 * using the @IpReputationProvider annotation. Fires the alter hook
 * api_flood_guard_ip_reputation_provider_info_alter after discovery.
 */
class IpReputationManager extends DefaultPluginManager {

  /**
   * Constructs the IpReputationManager.
   *
   * @param string $subdir
   *   The plugin subdirectory; e.g. 'Plugin/IpReputation'.
   * @param \Traversable $namespaces
   *   An object that implements \Traversable which contains the root paths
   *   keyed by the corresponding namespace to look for plugin implementations.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache_backend
   *   Cache backend instance to use.
   * @param string $interface
   *   The interface each plugin must implement.
   * @param string $annotation
   *   The annotation class that contains the plugin definition.
   */
  public function __construct(
    string $subdir,
    \Traversable $namespaces,
    ModuleHandlerInterface $module_handler,
    CacheBackendInterface $cache_backend,
    string $interface,
    string $annotation,
  ) {
    parent::__construct(
      $subdir,
      $namespaces,
      $module_handler,
      $interface,
      $annotation,
    );

    $this->alterInfo('api_flood_guard_ip_reputation_provider_info');
    $this->setCacheBackend($cache_backend, 'api_flood_guard_ip_reputation_plugins', ['api_flood_guard_ip_reputation_plugins']);
  }

}
