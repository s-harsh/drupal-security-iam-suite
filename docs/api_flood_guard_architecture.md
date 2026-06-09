# API Flood Guard — Architecture

## Module Structure

```
api_flood_guard/
├── api_flood_guard.info.yml                          # Module metadata, dependencies, configure route
├── api_flood_guard.module                            # Procedural stub delegating hook_help to HibpFloodGuardHooks
├── api_flood_guard.services.yml                      # Full service container definitions
├── api_flood_guard.routing.yml                       # Admin routes for settings, flood state, log view
├── api_flood_guard.permissions.yml                   # 'administer api flood guard' permission declaration
├── api_flood_guard.links.menu.yml                    # Admin menu links under admin/config/security
├── api_flood_guard.drush.yml                         # Drush command registration metadata
├── composer.json                                     # Module-level composer metadata
├── config/
│   ├── install/
│   │   └── api_flood_guard.settings.yml              # Default config values shipped with the module
│   └── schema/
│       └── api_flood_guard.schema.yml                # Config schema for api_flood_guard.settings
├── js/
│   └── flood-state-refresh.js                        # Auto-refresh logic for the flood state dashboard
└── src/
    ├── Hook/
    │   └── ApiFloodGuardHooks.php                    # OOP hook implementations (help, cache_bin_info, cron)
    ├── EventSubscriber/
    │   └── ApiFloodSubscriber.php                    # KernelEvents::REQUEST (priority 300) and KernelEvents::RESPONSE
    ├── Service/
    │   ├── ApiEndpointDetector.php                   # Path and Content-Type detection for protected API paths
    │   └── ApiFloodManager.php                       # Orchestrates flood checks, allowlist, reputation, and counters
    ├── Plugin/
    │   ├── Manager/
    │   │   └── IpReputationManager.php               # DefaultPluginManager subclass for IpReputationProvider plugins
    │   └── IpReputation/
    │       ├── AbuseIpDb.php                         # Built-in AbuseIPDB v2 reputation provider plugin
    │       └── NullProvider.php                      # No-op provider used when reputation checks are disabled
    ├── Annotation/
    │   └── IpReputationProvider.php                  # @IpReputationProvider annotation class
    ├── Contract/
    │   └── IpReputationProviderInterface.php         # Plugin contract defining checkIp() and isConfigured()
    ├── Value/
    │   └── IpReputationResult.php                    # Typed value object returned by reputation provider plugins
    ├── Form/
    │   ├── ApiFloodGuardSettingsForm.php             # ConfigFormBase admin settings form
    │   └── ApiFloodStateForm.php                     # Flood state dashboard with active-entries table and clear actions
    ├── Controller/
    │   └── ApiFloodStatusController.php              # Renders the recent block events log page
    └── Drush/
        └── Commands/
            └── ApiFloodGuardCommands.php             # Drush 12 command file (status, clear, allowlist-add, test-ip)
```

### File-by-File Responsibilities

| File | Responsibility |
|---|---|
| `api_flood_guard.info.yml` | Declares name, type, description, `core_version_requirement: ^11 \|\| ^10.4`, `package: Security`, zero hard dependencies (optional integrations with `key`, `simple_oauth`, `flood_control` detected at runtime), and `configure: api_flood_guard.settings`. |
| `api_flood_guard.module` | Minimal procedural stub. Contains only a `hook_help` delegation: `return \Drupal::service('api_flood_guard.hooks')->help($route_name, $route_match)`. No other procedural code. |
| `api_flood_guard.services.yml` | Defines all services: event subscriber, endpoint detector, flood manager, plugin manager, AbuseIPDB plugin, logger channel, cache bin, and hook class. |
| `api_flood_guard.routing.yml` | Declares four routes: settings form, flood state dashboard, block events log, and the Drush-supporting AJAX clear endpoint. |
| `api_flood_guard.permissions.yml` | Declares `administer api flood guard` with `restrict access: true`. |
| `api_flood_guard.links.menu.yml` | Three menu links under `system.admin_config_security`: main settings entry, flood state sub-link, and log sub-link. |
| `api_flood_guard.drush.yml` | Points Drush to the `ApiFloodGuardCommands` commandfile via PSR-4 autoloading. |
| `composer.json` | `name: drupal/api_flood_guard`, `type: drupal-module`, `license: GPL-2.0-or-later`, `require: {drupal/core: ^11 \|\| ^10.4}`. PSR-4 autoload maps `Drupal\api_flood_guard\` to `src/`. |
| `config/install/api_flood_guard.settings.yml` | Ships default values for all configurable options including protected paths, thresholds, allowlist, reputation provider settings, and response options. |
| `config/schema/api_flood_guard.schema.yml` | `config_object` schema covering the complete settings mapping with typed keys. |
| `js/flood-state-refresh.js` | Vanilla JS attached to the flood state dashboard. Polls `/admin/config/security/api-flood-guard/flood-state/data` every 30 seconds and replaces the table body without a full page reload. Uses Drupal's `drupalSettings` for configurable poll interval. |
| `src/Hook/ApiFloodGuardHooks.php` | OOP hook class tagged `drupal.hook`. Implements `#[Hook('help')]`, `#[Hook('cache_bin_info')]`, and `#[Hook('cron')]`. |
| `src/EventSubscriber/ApiFloodSubscriber.php` | Core module logic. Subscribes to `KernelEvents::REQUEST` at priority 300 and `KernelEvents::RESPONSE` at priority -100. Delegates detection and flood management to injected services. Builds and terminates blocked responses. |
| `src/Service/ApiEndpointDetector.php` | Encapsulates path matching and Content-Type detection. Determines whether a request targets a protected API path and whether it is an HTML form submission (which should be skipped). Extracts username or `client_id` from request body and `Authorization` headers. |
| `src/Service/ApiFloodManager.php` | Orchestrates the full multi-stage decision pipeline: allowlist check, IP reputation check, per-IP flood check, per-username flood check, flood registration, and flood clearing on success. Holds `FloodInterface` and `IpReputationManager` references. |
| `src/Plugin/Manager/IpReputationManager.php` | `DefaultPluginManager` subclass with annotation discovery, `api_flood_guard_ip_reputation_provider_info_alter` hook, and 1-hour cache on discovered definitions. |
| `src/Plugin/IpReputation/AbuseIpDb.php` | `IpReputationProviderInterface` plugin. Calls `https://api.abuseipdb.com/api/v2/check` via `http_client` (Guzzle). Caches responses per-IP in `cache.api_flood_guard`. Fail-open on provider error. |
| `src/Plugin/IpReputation/NullProvider.php` | Stub plugin that always returns `isBlocked: false`. Active when no provider is configured. |
| `src/Annotation/IpReputationProvider.php` | `@Annotation` class extending `Drupal\Component\Annotation\Plugin`. Fields: `id`, `label`, `description`, `api_endpoint`. |
| `src/Contract/IpReputationProviderInterface.php` | Defines `checkIp(string $ip): IpReputationResult`, `isConfigured(): bool`, `getPluginId(): string`, `getPluginDefinition(): array`. |
| `src/Value/IpReputationResult.php` | Readonly value object: `isBlocked: bool`, `confidenceScore: int`, `abuseCategories: array`, `providerName: string`, `fromCache: bool`. |
| `src/Form/ApiFloodGuardSettingsForm.php` | `ConfigFormBase`. Renders all configurable options. Detects Key module availability and conditionally renders a key-entity selector for the AbuseIPDB API key field. |
| `src/Form/ApiFloodStateForm.php` | Queries the `flood` table for `api_flood_guard.*` entries. Renders them in a `#type: table` element with per-row clear actions and a bulk "Clear all" submit. Attaches `flood-state-refresh.js`. |
| `src/Controller/ApiFloodStatusController.php` | Renders a pre-filtered view of watchdog entries with `type = 'api_flood_guard'`. Supports severity filter and pagination. |
| `src/Drush/Commands/ApiFloodGuardCommands.php` | Drush 12 commandfile using `AutowireTrait`. Implements `api-flood-guard:status`, `api-flood-guard:clear`, `api-flood-guard:allowlist-add`, and `api-flood-guard:test-ip`. |

---

## Service Definitions

### `api_flood_guard.subscriber`

| Property | Value |
|---|---|
| Class | `Drupal\api_flood_guard\EventSubscriber\ApiFloodSubscriber` |
| Constructor args | `@api_flood_guard.flood_manager`, `@api_flood_guard.endpoint_detector`, `@config.factory`, `@logger.channel.api_flood_guard` |
| Tags | `{name: event_subscriber}` |
| Responsibility | Subscribes to `KernelEvents::REQUEST` at priority 300 and `KernelEvents::RESPONSE` at priority -100. On REQUEST: delegates detection to `ApiEndpointDetector`, delegates blocking decision to `ApiFloodManager`, terminates the request with a `429`/`503` `JsonResponse` or plain-text `Response` if blocked. On RESPONSE: clears per-username flood counter when a protected path returns HTTP 200. |

```yaml
api_flood_guard.subscriber:
  class: Drupal\api_flood_guard\EventSubscriber\ApiFloodSubscriber
  arguments:
    - '@api_flood_guard.flood_manager'
    - '@api_flood_guard.endpoint_detector'
    - '@config.factory'
    - '@logger.channel.api_flood_guard'
  tags:
    - { name: event_subscriber }
```

### `api_flood_guard.endpoint_detector`

| Property | Value |
|---|---|
| Class | `Drupal\api_flood_guard\Service\ApiEndpointDetector` |
| Constructor args | `@config.factory` |
| Responsibility | Reads `protected_paths` from config. Matches `Request::getPathInfo()` against path entries using exact or prefix mode. Detects HTML form submission (Content-Type `application/x-www-form-urlencoded` without `_format=json`). Extracts username from `Authorization: Basic` header (base64-decode, split on first colon, normalize to lowercase). Extracts username from JSON request body (`username` field for `/user/login`, `client_id` for `/oauth/token`). Hashes the extracted identifier with `hash('sha256', strtolower(trim($identifier)))` before returning it. |

```yaml
api_flood_guard.endpoint_detector:
  class: Drupal\api_flood_guard\Service\ApiEndpointDetector
  arguments:
    - '@config.factory'
```

### `api_flood_guard.flood_manager`

| Property | Value |
|---|---|
| Class | `Drupal\api_flood_guard\Service\ApiFloodManager` |
| Constructor args | `@flood`, `@config.factory`, `@logger.channel.api_flood_guard`, `@plugin.manager.ip_reputation_provider`, `@request_stack` |
| Responsibility | Implements the full multi-stage pipeline: (1) CIDR allowlist check using native `inet_pton()` bitwise matching; (2) IP reputation check via plugin manager with fail-open; (3) per-IP flood check via `FloodInterface::isAllowed('api_flood_guard.ip', ...)` and `FloodInterface::register(...)`; (4) per-username flood check and registration; (5) counter clearing on 200 responses. Returns a typed `FloodDecision` value (allow/block + reason) to the subscriber. |

```yaml
api_flood_guard.flood_manager:
  class: Drupal\api_flood_guard\Service\ApiFloodManager
  arguments:
    - '@flood'
    - '@config.factory'
    - '@logger.channel.api_flood_guard'
    - '@plugin.manager.ip_reputation_provider'
    - '@request_stack'
```

### `plugin.manager.ip_reputation_provider`

| Property | Value |
|---|---|
| Class | `Drupal\api_flood_guard\Plugin\Manager\IpReputationManager` |
| Constructor args | `'Plugin/IpReputation'`, `@container.namespaces`, `@module_handler`, `@cache.discovery`, `'Drupal\api_flood_guard\Contract\IpReputationProviderInterface'`, `'Drupal\api_flood_guard\Annotation\IpReputationProvider'` |
| Tags | (none — DefaultPluginManager handles its own wiring) |
| Responsibility | Discovers `IpReputationProvider` plugins in all modules' `src/Plugin/IpReputation/` directories via annotation. Fires `api_flood_guard_ip_reputation_provider_info_alter` after discovery. Caches discovered definitions in `cache.discovery` for 1 hour. Instantiates the configured provider on demand. |

```yaml
plugin.manager.ip_reputation_provider:
  class: Drupal\api_flood_guard\Plugin\Manager\IpReputationManager
  arguments:
    - 'Plugin/IpReputation'
    - '@container.namespaces'
    - '@module_handler'
    - '@cache.discovery'
    - 'Drupal\api_flood_guard\Contract\IpReputationProviderInterface'
    - 'Drupal\api_flood_guard\Annotation\IpReputationProvider'
```

### `cache.api_flood_guard`

| Property | Value |
|---|---|
| Interface | `Drupal\Core\Cache\CacheBackendInterface` |
| Factory | `cache_factory:get` with argument `api_flood_guard` |
| Tags | `{name: cache.bin}` |
| Responsibility | Dedicated cache bin for AbuseIPDB response caching, keyed by `abuseipdb:{md5($ip)}`. TTL is set per-item from config (`reputation_providers.abuseipdb.cache_ttl`, default 3600 seconds). Also used by the plugin manager for discovered plugin definitions. |

```yaml
cache.api_flood_guard:
  class: Drupal\Core\Cache\CacheBackendInterface
  tags:
    - { name: cache.bin }
  factory: cache_factory:get
  arguments: [api_flood_guard]
```

### `logger.channel.api_flood_guard`

| Property | Value |
|---|---|
| Parent | `logger.channel_base` |
| Constructor args | `api_flood_guard` (channel name string) |
| Responsibility | Named log channel for all watchdog entries emitted by the module. Enables site builders to route API Flood Guard entries to separate syslog streams or contrib logging destinations. |

```yaml
logger.channel.api_flood_guard:
  parent: logger.channel_base
  arguments: ['api_flood_guard']
```

### `api_flood_guard.hooks`

| Property | Value |
|---|---|
| Class | `Drupal\api_flood_guard\Hook\ApiFloodGuardHooks` |
| Constructor args | `@config.factory`, `@logger.channel.api_flood_guard`, `@database` |
| Tags | `{name: drupal.hook}` |
| Responsibility | OOP hook implementations for `hook_help`, `hook_cache_bin_info`, and `hook_cron`. The cron implementation queries the `flood` table to count `api_flood_guard.*` events blocked in the last 24 hours and logs a summary to watchdog for monitoring dashboards. |

```yaml
api_flood_guard.hooks:
  class: Drupal\api_flood_guard\Hook\ApiFloodGuardHooks
  arguments:
    - '@config.factory'
    - '@logger.channel.api_flood_guard'
    - '@database'
  tags:
    - { name: drupal.hook }
```

### Full `api_flood_guard.services.yml`

```yaml
services:
  api_flood_guard.subscriber:
    class: Drupal\api_flood_guard\EventSubscriber\ApiFloodSubscriber
    arguments:
      - '@api_flood_guard.flood_manager'
      - '@api_flood_guard.endpoint_detector'
      - '@config.factory'
      - '@logger.channel.api_flood_guard'
    tags:
      - { name: event_subscriber }

  api_flood_guard.endpoint_detector:
    class: Drupal\api_flood_guard\Service\ApiEndpointDetector
    arguments:
      - '@config.factory'

  api_flood_guard.flood_manager:
    class: Drupal\api_flood_guard\Service\ApiFloodManager
    arguments:
      - '@flood'
      - '@config.factory'
      - '@logger.channel.api_flood_guard'
      - '@plugin.manager.ip_reputation_provider'
      - '@request_stack'

  plugin.manager.ip_reputation_provider:
    class: Drupal\api_flood_guard\Plugin\Manager\IpReputationManager
    arguments:
      - 'Plugin/IpReputation'
      - '@container.namespaces'
      - '@module_handler'
      - '@cache.discovery'
      - 'Drupal\api_flood_guard\Contract\IpReputationProviderInterface'
      - 'Drupal\api_flood_guard\Annotation\IpReputationProvider'

  cache.api_flood_guard:
    class: Drupal\Core\Cache\CacheBackendInterface
    tags:
      - { name: cache.bin }
    factory: cache_factory:get
    arguments: [api_flood_guard]

  logger.channel.api_flood_guard:
    parent: logger.channel_base
    arguments: ['api_flood_guard']

  api_flood_guard.hooks:
    class: Drupal\api_flood_guard\Hook\ApiFloodGuardHooks
    arguments:
      - '@config.factory'
      - '@logger.channel.api_flood_guard'
      - '@database'
    tags:
      - { name: drupal.hook }
```

---

## Plugin System

### Plugin Type: `IpReputationProvider`

Plugin discovery directory: `src/Plugin/IpReputation/` within any enabled module.

Manager: `Drupal\api_flood_guard\Plugin\Manager\IpReputationManager` (extends `DefaultPluginManager`)

Annotation class: `Drupal\api_flood_guard\Annotation\IpReputationProvider`

Interface: `Drupal\api_flood_guard\Contract\IpReputationProviderInterface`

Alter hook: `api_flood_guard_ip_reputation_provider_info_alter(array &$definitions)`

#### Annotation Class

```php
namespace Drupal\api_flood_guard\Annotation;

use Drupal\Component\Annotation\Plugin;

/**
 * @Annotation
 */
class IpReputationProvider extends Plugin {
    public string $id;
    public TranslatableMarkup|string $label;
    public TranslatableMarkup|string $description = '';
    public string $api_endpoint = '';
}
```

#### Interface

```php
namespace Drupal\api_flood_guard\Contract;

interface IpReputationProviderInterface {
    public function checkIp(string $ip): IpReputationResult;
    public function isConfigured(): bool;
    public function getPluginId(): string;
    public function getPluginDefinition(): array;
}
```

Interface method signatures:

| Method | Signature | Purpose |
|---|---|---|
| `checkIp` | `checkIp(string $ip): IpReputationResult` | Check a single IP against the provider. Must be fail-open: return `isBlocked: false` on provider error. |
| `isConfigured` | `isConfigured(): bool` | Return `true` only if the plugin has the necessary credentials/config to make real checks. |
| `getPluginId` | `getPluginId(): string` | Inherited from Drupal plugin system; returns the plugin's `id` annotation value. |
| `getPluginDefinition` | `getPluginDefinition(): array` | Inherited from Drupal plugin system; returns the full annotation data array. |

#### Value Object: `IpReputationResult`

```php
// src/Value/IpReputationResult.php
final readonly class IpReputationResult {
    public function __construct(
        public readonly bool $isBlocked,
        public readonly int $confidenceScore,
        public readonly array $abuseCategories,
        public readonly string $providerName,
        public readonly bool $fromCache = false,
        public readonly bool $providerError = false,
    ) {}
}
```

#### Concrete Plugin: `AbuseIpDb`

| Property | Value |
|---|---|
| Class | `Drupal\api_flood_guard\Plugin\IpReputation\AbuseIpDb` |
| Plugin ID | `abuseipdb` |
| File | `src/Plugin/IpReputation/AbuseIpDb.php` |
| Annotation | `#[IpReputationProvider(id: 'abuseipdb', label: new TranslatableMarkup('AbuseIPDB'), description: new TranslatableMarkup('Checks IPs against the AbuseIPDB v2 API.'), api_endpoint: 'https://api.abuseipdb.com/api/v2/check')]` |
| Injected services | `http_client`, `cache.api_flood_guard`, `config.factory` (via `ContainerFactoryPluginInterface::create()`) |

`checkIp()` flow:

1. Build cache ID: `abuseipdb:` + `md5($ip)`.
2. Check `cache.api_flood_guard` for a cached result. If hit and `$cacheItem->data['blocked']` is set, return a result with `fromCache: true`.
3. Read `api_key` from config (or Key module entity if configured).
4. If `api_key` is empty, return `isBlocked: false`, `providerError: false` (not configured; `isConfigured()` returned false — caller should skip).
5. Make GET request to `https://api.abuseipdb.com/api/v2/check` with query params `ipAddress`, `maxAgeInDays`, `verbose=false`. Header: `Key: {api_key}`, `Accept: application/json`.
6. Wrap in try/catch for `GuzzleException`. On exception: log `warning`, return `IpReputationResult(isBlocked: false, providerError: true)`.
7. On non-200 response: log `warning` with status code, return fail-open result.
8. Parse JSON body. Extract `data.abuseConfidenceScore` and `data.usageType`.
9. Write result to `cache.api_flood_guard` with TTL from `reputation_providers.abuseipdb.cache_ttl`.
10. Return `IpReputationResult(isBlocked: $score >= $threshold, confidenceScore: $score, ...)`.

#### Concrete Plugin: `NullProvider`

| Property | Value |
|---|---|
| Class | `Drupal\api_flood_guard\Plugin\IpReputation\NullProvider` |
| Plugin ID | `null_provider` |
| Annotation | `#[IpReputationProvider(id: 'null_provider', label: new TranslatableMarkup('None (disabled)'))]` |
| Responsibility | Always returns `IpReputationResult(isBlocked: false, confidenceScore: 0, ...)`. `isConfigured()` returns `false`. Used as the default when no provider is selected in config. |

#### Third-Party Plugin Integration

Any module can add a custom provider by placing a class in its `src/Plugin/IpReputation/` directory that implements `IpReputationProviderInterface` and carries the `@IpReputationProvider` annotation. The plugin manager discovers it automatically via Drupal's annotation discovery, and the admin settings form presents it in the provider selector.

---

## Database Schema

API Flood Guard creates **no custom database tables**. All persistent state relies on existing Drupal infrastructure:

| Storage | Purpose |
|---|---|
| Drupal `flood` table (core) | Per-IP and per-username flood counters under `api_flood_guard.ip` and `api_flood_guard.user` event namespaces. Managed entirely by `FloodInterface` (DatabaseBackend). Garbage-collected by core cron. |
| `cache_api_flood_guard` table | Backing table for the `cache.api_flood_guard` bin when the site uses DatabaseBackend. Created automatically by Drupal's cache factory; no `hook_schema()` declaration is needed. Holds AbuseIPDB per-IP response cache. |
| `watchdog` table | Receives structured log entries from `logger.channel.api_flood_guard` via dblog module. All block events are written here with `type = 'api_flood_guard'`. |
| `config` table | Stores `api_flood_guard.settings` config object via the Config API. |

### Flood Table Usage Reference

The module uses the standard Drupal `flood` table with the following event namespace conventions:

| Event Name | Identifier | Threshold Config Key | Window Config Key | Default |
|---|---|---|---|---|
| `api_flood_guard.ip` | Raw client IP string | `ip_threshold` | `ip_window` | 100 / 3600 s |
| `api_flood_guard.user` | `hash('sha256', strtolower(trim($username)))` | `user_threshold` | `user_window` | 20 / 900 s |

There is no `hook_schema()` implementation.

---

## Config Schema

### `api_flood_guard.settings`

File: `config/schema/api_flood_guard.schema.yml`

```yaml
api_flood_guard.settings:
  type: config_object
  label: 'API Flood Guard settings'
  mapping:
    protected_paths:
      type: sequence
      label: 'Protected API paths'
      sequence:
        type: mapping
        mapping:
          path:
            type: string
            label: 'Path'
          match:
            type: string
            label: 'Match type (prefix or exact)'
    ip_threshold:
      type: integer
      label: 'Per-IP attempt threshold'
    ip_window:
      type: integer
      label: 'Per-IP time window in seconds'
    user_threshold:
      type: integer
      label: 'Per-username attempt threshold'
    user_window:
      type: integer
      label: 'Per-username time window in seconds'
    response_code:
      type: integer
      label: 'HTTP response code for blocked requests (429 or 503)'
    block_message:
      type: string
      label: 'Block response detail message'
    allowlist:
      type: sequence
      label: 'IP allowlist in CIDR notation'
      sequence:
        type: string
    reputation_providers:
      type: mapping
      label: 'IP reputation provider settings'
      mapping:
        enabled_provider:
          type: string
          label: 'Active provider plugin ID (empty string to disable)'
        abuseipdb:
          type: mapping
          label: 'AbuseIPDB provider settings'
          mapping:
            api_key:
              type: string
              label: 'AbuseIPDB v2 API key (use Key module in production)'
            api_key_id:
              type: string
              label: 'Key module entity ID (overrides api_key when Key module is present)'
            threshold:
              type: integer
              label: 'Confidence score threshold 0-100 (block if score >= threshold)'
            max_age_days:
              type: integer
              label: 'Maximum report age in days for AbuseIPDB query'
            cache_ttl:
              type: integer
              label: 'Per-IP AbuseIPDB response cache TTL in seconds'
    debug_logging:
      type: boolean
      label: 'Enable debug-level logging for allowed requests'
```

### Config Install Defaults

File: `config/install/api_flood_guard.settings.yml`

```yaml
protected_paths:
  - path: /jsonapi
    match: prefix
  - path: /user/login
    match: exact
  - path: /oauth/token
    match: exact
  - path: /rest/user/login
    match: exact
ip_threshold: 100
ip_window: 3600
user_threshold: 20
user_window: 900
response_code: 429
block_message: 'Too many authentication requests. Please wait before trying again.'
allowlist: []
reputation_providers:
  enabled_provider: ''
  abuseipdb:
    api_key: ''
    api_key_id: ''
    threshold: 85
    max_age_days: 30
    cache_ttl: 3600
debug_logging: false
```

### Config Key Reference

| Key | Type | Default | Allowed Values | Description |
|---|---|---|---|---|
| `protected_paths` | sequence | See above | List of `{path, match}` maps | API paths subject to flood control. Each entry has a `path` string and `match` of `prefix` or `exact`. |
| `ip_threshold` | integer | `100` | 1 – 10000 | Max authentication attempts from one IP per `ip_window` before blocking. |
| `ip_window` | integer | `3600` | 60 – 86400 | Sliding window duration in seconds for the IP flood counter. |
| `user_threshold` | integer | `20` | 1 – 1000 | Max authentication attempts per username per `user_window` before blocking. |
| `user_window` | integer | `900` | 60 – 86400 | Sliding window duration in seconds for the username flood counter. |
| `response_code` | integer | `429` | `429` / `503` | HTTP status code returned in block responses. |
| `block_message` | string | See default | Any string | Human-readable detail in the error response body. Not exposed as an HTML error to browsers. |
| `allowlist` | sequence | `[]` | IPv4/IPv6 or CIDR | IPs or ranges exempt from all flood checks. One entry per CIDR string. |
| `reputation_providers.enabled_provider` | string | `''` | Any registered plugin ID or `''` | Plugin ID of the active reputation provider. Empty string disables reputation checking entirely. |
| `reputation_providers.abuseipdb.api_key` | string | `''` | Any string | Raw AbuseIPDB v2 API key. Prefer `api_key_id` when Key module is present. |
| `reputation_providers.abuseipdb.api_key_id` | string | `''` | Key entity machine name | Key module entity ID. When non-empty and Key module is installed, this takes precedence over `api_key`. |
| `reputation_providers.abuseipdb.threshold` | integer | `85` | 0 – 100 | Confidence score at or above which an IP is blocked. |
| `reputation_providers.abuseipdb.max_age_days` | integer | `30` | 1 – 365 | Passed as `maxAgeInDays` to the AbuseIPDB API query. |
| `reputation_providers.abuseipdb.cache_ttl` | integer | `3600` | 0 – 86400 | Per-IP cache TTL in seconds. `0` disables caching (not recommended in production). |
| `debug_logging` | boolean | `false` | `true` / `false` | When `true`, logs a DEBUG entry for every allowed request through the protected path detection. High-volume; use for troubleshooting only. |

---

## Routes

File: `api_flood_guard.routing.yml`

### `api_flood_guard.settings`

```yaml
api_flood_guard.settings:
  path: '/admin/config/security/api-flood-guard'
  defaults:
    _form: '\Drupal\api_flood_guard\Form\ApiFloodGuardSettingsForm'
    _title: 'API Flood Guard Settings'
  requirements:
    _permission: 'administer api flood guard'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Handler | `ApiFloodGuardSettingsForm` (ConfigFormBase) |
| Access | `administer api flood guard` |
| Theme | Claro admin (via `_admin_route: true`) |

### `api_flood_guard.flood_state`

```yaml
api_flood_guard.flood_state:
  path: '/admin/config/security/api-flood-guard/flood-state'
  defaults:
    _form: '\Drupal\api_flood_guard\Form\ApiFloodStateForm'
    _title: 'API Flood Guard — Flood State'
  requirements:
    _permission: 'administer api flood guard'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Handler | `ApiFloodStateForm` (FormBase with table and clear actions) |
| Access | `administer api flood guard` |

### `api_flood_guard.log`

```yaml
api_flood_guard.log:
  path: '/admin/config/security/api-flood-guard/log'
  defaults:
    _controller: '\Drupal\api_flood_guard\Controller\ApiFloodStatusController::logPage'
    _title: 'API Flood Guard — Recent Block Events'
  requirements:
    _permission: 'administer api flood guard'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Handler | `ApiFloodStatusController::logPage()` |
| Access | `administer api flood guard` |

### `api_flood_guard.flood_state.data`

```yaml
api_flood_guard.flood_state.data:
  path: '/admin/config/security/api-flood-guard/flood-state/data'
  defaults:
    _controller: '\Drupal\api_flood_guard\Controller\ApiFloodStatusController::floodStateData'
    _title: ''
  requirements:
    _permission: 'administer api flood guard'
    _format: json
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Handler | `ApiFloodStatusController::floodStateData()` — returns a `JsonResponse` consumed by `flood-state-refresh.js` for the 30-second auto-refresh |
| Access | `administer api flood guard` |
| Notes | Only accessible to admin users; not a public endpoint |

### Route Summary Table

| Route ID | Path | Handler | Permission |
|---|---|---|---|
| `api_flood_guard.settings` | `/admin/config/security/api-flood-guard` | `ApiFloodGuardSettingsForm` | `administer api flood guard` |
| `api_flood_guard.flood_state` | `/admin/config/security/api-flood-guard/flood-state` | `ApiFloodStateForm` | `administer api flood guard` |
| `api_flood_guard.log` | `/admin/config/security/api-flood-guard/log` | `ApiFloodStatusController::logPage` | `administer api flood guard` |
| `api_flood_guard.flood_state.data` | `/admin/config/security/api-flood-guard/flood-state/data` | `ApiFloodStatusController::floodStateData` | `administer api flood guard` |

---

## Hook Implementations

All hooks follow Drupal 11's OOP `#[Hook]` attribute pattern. The single procedural stub in `api_flood_guard.module` contains only the `hook_help` delegation line.

### `hook_help` — `ApiFloodGuardHooks::help()`

File: `src/Hook/ApiFloodGuardHooks.php`

```php
#[Hook('help')]
public function help(string $route_name, RouteMatchInterface $route_match): string|array
```

Triggered by: `api_flood_guard.module` procedural stub.

Behaviour: When `$route_name === 'help.page.api_flood_guard'`, returns a render array containing a description of the module's purpose, links to the settings form, flood state dashboard, and a reference to the Drupal.org project page.

### `hook_cache_bin_info` — `ApiFloodGuardHooks::cacheBinInfo()`

File: `src/Hook/ApiFloodGuardHooks.php`

```php
#[Hook('cache_bin_info')]
public function cacheBinInfo(): array
```

Returns:

```php
[
  'api_flood_guard' => [
    'label' => $this->t('API Flood Guard IP reputation cache'),
    'description' => $this->t('Caches AbuseIPDB and other reputation provider responses per IP address.'),
  ],
]
```

This declaration registers the cache bin so site builders can configure a specific cache backend for it in `settings.php` (e.g., map it to Redis while keeping the default bin on the database).

### `hook_cron` — `ApiFloodGuardHooks::cron()`

File: `src/Hook/ApiFloodGuardHooks.php`

```php
#[Hook('cron')]
public function cron(): void
```

Behaviour:

1. Query the `flood` table for all entries with `event LIKE 'api_flood_guard.%'` and `expiration > UNIX_TIMESTAMP()` (active, non-expired entries).
2. Count entries grouped by event namespace.
3. Query `watchdog` for `type = 'api_flood_guard'` and `severity = RfcLogLevel::WARNING` entries in the past 24 hours.
4. Log a single `INFO`-level watchdog entry summarising: active flood entry count by namespace, total blocks in last 24 hours. This summary entry provides cron-driven monitoring data for external log aggregators and dashboards without requiring them to parse individual block entries.

### `api_flood_guard_ip_reputation_provider_info_alter`

Fired by `IpReputationManager` after annotation discovery. Other modules implement this to:
- Remove a provider from the discovered definitions.
- Override `api_endpoint` or `label` fields.
- Add programmatically constructed provider definitions that cannot be expressed via annotation.

This is a standard Drupal `alter` hook; no OOP attribute is needed in the altering module — it can use a procedural `function mymodule_api_flood_guard_ip_reputation_provider_info_alter(array &$definitions): void` or the OOP `#[Hook]` equivalent.

---

## Event Subscribers

### `ApiFloodSubscriber`

File: `src/EventSubscriber/ApiFloodSubscriber.php`

```php
public static function getSubscribedEvents(): array {
    return [
        KernelEvents::REQUEST  => [['onRequest',  300]],
        KernelEvents::RESPONSE => [['onResponse', -100]],
    ];
}
```

#### `onRequest(RequestEvent $event)` — Priority 300

Priority 300 places this subscriber before:
- Route matching (priority 32)
- Page cache (priority 27)
- Authentication (priority 8)
- Session (priority 128, but after the subscriber)

This ensures the flood check runs before any Drupal system that itself consumes resources (session bootstrap, routing resolution, authentication framework) and before the page cache could serve a cached response to an attacker.

Decision pipeline within `onRequest()`:

1. Call `ApiEndpointDetector::isProtectedPath($request)`. If false, return immediately (no overhead for non-API traffic).
2. Call `ApiEndpointDetector::isHtmlFormSubmission($request)`. If true (Content-Type `application/x-www-form-urlencoded` without `_format=json`), skip — handled by core's form flood.
3. Extract client IP: `$request->getClientIp()` (respects Drupal's `trusted_proxies` setting).
4. Delegate to `ApiFloodManager::evaluate($request, $clientIp)` which returns a `FloodDecision` object with `allowed: bool`, `reason: string ('ip'|'user'|'reputation'|'allowed')`, `identifier: string`, `retryAfter: int`.
5. If `FloodDecision::allowed === false`: build a response (JSON:API error object or plain text based on `Accept` header), set status code from config (429/503), set `Retry-After: {seconds}` header, set `Content-Type` header, call `$event->setResponse($response)` to terminate Symfony's request handling pipeline.
6. If `FloodDecision::allowed === true` and debug logging is enabled: log a DEBUG entry.

#### `onResponse(ResponseEvent $event)` — Priority -100

Runs after the primary response is built (low priority ensures the final response status is known).

Behaviour:

1. Call `ApiEndpointDetector::isProtectedPath($event->getRequest())`. If false, return.
2. Check `$event->getResponse()->getStatusCode() === 200`.
3. If 200: call `ApiEndpointDetector::extractUsernameIdentifier($event->getRequest())` to get the hashed identifier.
4. If identifier is non-empty: call `ApiFloodManager::clearUserFlood($identifier)` which delegates to `FloodInterface::clear('api_flood_guard.user', $identifier)`.
5. This prevents legitimate users from accumulating flood counts across successful authentication sessions (e.g., a mobile app that authenticates repeatedly without being blocked).

---

## Entity Definitions

API Flood Guard defines **no custom entity types**. The module interacts with existing Drupal entities and infrastructure only:

| Entity / Infrastructure | Interaction |
|---|---|
| Core `flood` table (not a config entity) | Read/write via `FloodInterface` (`@flood` service) under the `api_flood_guard.*` event namespaces. |
| Core `watchdog` table | Write-only via `logger.channel.api_flood_guard`. All block events are appended; the module never reads back from watchdog except in the admin log controller. |
| `key` entity (Key module, optional) | Read-only. When Key module is installed and `api_key_id` config is set, the AbuseIPDB plugin retrieves the API key via `Drupal\key\KeyRepositoryInterface::getKey($id)->getKeyValue()`. |

---

## External API Integrations

### AbuseIPDB v2 Check API

| Property | Value |
|---|---|
| Provider | AbuseIPDB (https://www.abuseipdb.com) |
| Endpoint | `GET https://api.abuseipdb.com/api/v2/check` |
| Authentication | Header: `Key: {api_key}` (API key from config or Key module entity) |
| TLS | Required. Guzzle enforces certificate verification by default; not exposed as a configurable option. |
| Query parameters | `ipAddress={ip}`, `maxAgeInDays={max_age_days}`, `verbose=false` |
| Request headers | `Key: {api_key}`, `Accept: application/json` |
| Response format | JSON. Key field: `data.abuseConfidenceScore` (integer 0-100), `data.usageType` (string), `data.isTor` (boolean). |
| Error responses | 401 (invalid key), 422 (invalid IP), 429 (AbuseIPDB rate limit exceeded). All non-200 responses trigger fail-open: log `warning`, return `isBlocked: false`. |
| Rate limits | AbuseIPDB v2 free tier: 1000 checks/day. The per-IP cache (`cache_ttl` default 3600 s) ensures each unique IP is checked at most once per hour, making quota consumption proportional to unique attacker IPs rather than total request volume. |
| Privacy | Only the client IP is sent to AbuseIPDB. No user credentials, usernames, or request body content are transmitted. |

#### Request Construction

```php
$response = $this->httpClient->get('https://api.abuseipdb.com/api/v2/check', [
    'headers' => [
        'Key'    => $this->getApiKey(),
        'Accept' => 'application/json',
    ],
    'query' => [
        'ipAddress'    => $ip,
        'maxAgeInDays' => $config->get('reputation_providers.abuseipdb.max_age_days'),
        'verbose'      => 'false',
    ],
    'timeout' => 5,
    'connect_timeout' => 3,
]);
```

#### Response Parsing

```php
$data = json_decode($response->getBody()->getContents(), true);
$score = (int) ($data['data']['abuseConfidenceScore'] ?? 0);
$isBlocked = $score >= $threshold;
```

#### Cache Integration

```
Cache key:   abuseipdb:{md5($ip)}
Cache bin:   cache.api_flood_guard
Cache TTL:   reputation_providers.abuseipdb.cache_ttl (default 3600 seconds)
Cache value: Array with keys: blocked (bool), score (int), categories (array), timestamp (int)
```

On cache hit: return cached `IpReputationResult` with `fromCache: true`, skipping HTTP call.
On API error: nothing is cached (no negative caching of provider failures).
On successful API response: write to cache before returning.

---

## Security Design

### Access Control

| Resource | Protection Mechanism |
|---|---|
| Settings form at `/admin/config/security/api-flood-guard` | Route requirement `_permission: administer api flood guard`; permission declared with `restrict access: true`. |
| Flood state dashboard | Same permission as settings form. |
| Block events log | Same permission as settings form. |
| AJAX flood state data endpoint | Same permission; requires `_format: json` route requirement to prevent HTML rendering. |
| Flood check logic (KernelEvents::REQUEST) | Runs before authentication; the flood check itself requires no Drupal user session. Applies to all requests regardless of authentication state. |
| `FloodInterface::clear()` calls in the admin form | Protected by `administer api flood guard` permission on the form route. |
| Drush commands | CLI-only; require OS-level shell access. No additional permission check needed. |

### Input Validation

| Input | Validation Approach |
|---|---|
| `protected_paths` (settings form) | Each path validated as beginning with `/`. Trailing whitespace trimmed. Empty entries rejected. |
| `ip_threshold`, `user_threshold` | Validated as positive integers >= 1 in `validateForm()`. |
| `ip_window`, `user_window` | Validated as integers in range 60–86400 (seconds). |
| `response_code` | Validated against allowed set `[429, 503]`. |
| `allowlist` CIDR entries | Each entry passed through `inet_pton()` to validate format; entries that fail parsing are reported as form errors. |
| `reputation_providers.abuseipdb.threshold` | Validated as integer 0–100. |
| Username extracted from `Authorization: Basic` | Base64 decoded; if decoding fails, identifier extraction returns empty string (no flood tracking for malformed headers). |
| `client_id` extracted from POST body | Read only if Content-Type is `application/x-www-form-urlencoded` or `application/json`; only the `client_id` field is read; value is passed through `strtolower(trim(...))` before hashing. |
| Client IP for allowlist matching | Validated through `inet_pton()` in the CIDR matching logic; invalid IP strings return no match (fail-open for the allowlist). |
| AbuseIPDB API endpoint URL | Hardcoded in the plugin annotation; not user-configurable. |

### Output Encoding

| Output Location | Encoding Approach |
|---|---|
| JSON block response body | `JsonResponse` with controlled array structure. `block_message` value is included in `detail` field; passed through `Html::escape()` before inclusion even though it goes into JSON (defense in depth). |
| Plain-text block response body | Returned as `Response` with `Content-Type: text/plain`. No HTML rendering. |
| Admin settings form fields | All labels use `$this->t()`. `#title`, `#description` keys use TranslatableMarkup. Twig auto-escapes all rendered values. |
| Flood state table | IP identifiers are raw IP strings displayed in a `#type: table`; rendered via Twig which auto-escapes. |
| Block events log | Watchdog variables (`%ip`, `%path`, `%rule`) are rendered using Drupal's watchdog message formatter which passes variables through `Html::escape()`. |
| `hook_help` output | Render array with `#markup` using `Markup::create($this->t(...))`. |

### Flood Namespace Isolation

API Flood Guard uses `api_flood_guard.ip` and `api_flood_guard.user` as flood event names. These are completely separate from Drupal core's `user.failed_login_ip` and `user.failed_login_user` namespaces used by form-based login. Benefits:
- Brute-force attacks via REST/JSON:API do not consume HTML form flood slots and vice versa.
- Thresholds for API paths and HTML paths can be tuned independently.
- Admin clearing of API flood entries (via the admin UI or Drush) does not affect form-login flood state.

### IP Spoofing Mitigation

The module reads the client IP exclusively from `Request::getClientIp()`, which Symfony's HttpFoundation computes from `REMOTE_ADDR` unless the source proxy IP is listed in Drupal's `$settings['trusted_proxies']`. The module does not add any new trust to forwarding headers. Sites that have not configured `trusted_proxies` always use the direct TCP connection IP (`REMOTE_ADDR`), which cannot be spoofed at the application layer. This prevents attackers from bypassing flood controls via `X-Forwarded-For` header manipulation on sites without trusted proxy configuration.

### Fail-Open vs. Fail-Closed

| Check Type | Failure Behaviour | Rationale |
|---|---|---|
| IP reputation (AbuseIPDB) | Fail-open: allow request, log warning | Provider outages must not cause site-wide authentication denial. Reputation checks are advisory. |
| IP reputation cache read | Fail-open: proceed to live API call | Cache unavailability causes a performance degradation, not a block. |
| Per-IP flood check (FloodInterface) | Fail-closed: Drupal's DatabaseBackend is local and highly available. If the database is down, the entire site is non-functional regardless. | No special handling needed. |
| Per-username flood check | Same as per-IP. | Same rationale. |
| CIDR allowlist matching | Fail-open: if `inet_pton()` fails on the IP, no allowlist entry matches. The IP proceeds to flood checks. | Malformed IP addresses (should not occur in practice) do not bypass protection. |

### Username Hashing and Privacy

Usernames are never stored in plaintext in the `flood` table or in log messages. The flood identifier is `hash('sha256', strtolower(trim($username)))`. Log entries for user-based blocks include the first 8 characters of this hash as an opaque reference (enough to correlate events without revealing the username). Passwords and the `Authorization` header password portion are discarded immediately after extracting the username; they are never logged, never cached, and never passed to any service other than the credential extraction method.

### Response Information Disclosure

Block responses do not reveal:
- The current flood counter value.
- The exact remaining window duration (only `Retry-After` seconds are exposed, which is RFC 6585-required information).
- Whether the block was triggered by IP flood, username flood, or reputation check.
- The reputation confidence score.

The `Retry-After` value is calculated as the flood window duration (config value), not the actual remaining time, to avoid leaking information about when an attack started.

### AbuseIPDB API Key Storage

The API key is stored in `api_flood_guard.settings:reputation_providers.abuseipdb.api_key`. This config value is exportable via `drush config:export`. To avoid exporting secrets to YAML:
- Use the Key module integration: set `api_key_id` to a Key entity machine name. The Key entity stores the secret separately and is not exported in config YAML.
- Override via `settings.php`: `$config['api_flood_guard.settings']['reputation_providers']['abuseipdb']['api_key'] = getenv('ABUSEIPDB_KEY');`.

### OWASP Alignment

| OWASP Top 10 Category | How API Flood Guard Addresses It |
|---|---|
| A07:2021 Identification and Authentication Failures | Direct rate-limiting of all API authentication endpoints before Drupal processes credentials. |
| A05:2021 Security Misconfiguration | Secure defaults (429 response, 100/20 thresholds, fail-open reputation) that protect out of the box. |
| A09:2021 Security Logging and Monitoring Failures | Structured watchdog entries on every block event with IP, path, rule, and identifier. Admin log view. Cron summary for monitoring dashboards. |

---

## Test Strategy

### Unit Tests

Location: `tests/src/Unit/`
Namespace: `Drupal\Tests\api_flood_guard\Unit\`
Base class: `Drupal\Tests\UnitTestCase`
Framework: PHPUnit 10+

| Test Class | File | What It Tests |
|---|---|---|
| `ApiEndpointDetectorTest` | `tests/src/Unit/Service/ApiEndpointDetectorTest.php` | Protected path matching for prefix entries (`/jsonapi/node/article` matches `/jsonapi`). Exact match entries (reject `/user/login/extra` for exact `/user/login`). HTML form detection: returns `true` for `Content-Type: application/x-www-form-urlencoded` without `_format=json`. Returns `false` for same URL with `_format=json`. Username extraction from `Authorization: Basic` header (base64-encoded `user:pass`). Username extraction from JSON body (`{"username":"admin"}`). `client_id` extraction from OAuth token POST body. Hashed identifier is SHA-256 of lowercased trimmed input. Returns empty string for malformed `Authorization` headers. |
| `ApiFloodManagerTest` | `tests/src/Unit/Service/ApiFloodManagerTest.php` | Allowlist hit bypasses all flood checks (mock FloodInterface never called). Allowlist CIDR range matching for IPv4 (`10.0.0.0/8`). Allowlist CIDR range matching for IPv6 (`::1/128`). Reputation plugin blocked triggers immediate block decision (FloodInterface not consulted). Reputation plugin fail-open (providerError = true) proceeds to flood checks. Per-IP flood check: `isAllowed()` returns false → block decision returned. Per-username flood check: `isAllowed()` returns false → block decision returned. Both checks pass → `register()` called for both namespaces, allow decision returned. `clearUserFlood()` calls `FloodInterface::clear('api_flood_guard.user', $id)`. |
| `AbuseIpDbPluginTest` | `tests/src/Unit/Plugin/IpReputation/AbuseIpDbPluginTest.php` | `isConfigured()` returns false when `api_key` is empty. Cache hit returns `IpReputationResult` with `fromCache: true` without making HTTP call. `abuseConfidenceScore >= threshold` returns `isBlocked: true`. `abuseConfidenceScore < threshold` returns `isBlocked: false`. GuzzleException returns `IpReputationResult(isBlocked: false, providerError: true)`. Non-200 HTTP response returns fail-open result. Cache write is called after successful API response. |
| `IpReputationResultTest` | `tests/src/Unit/Value/IpReputationResultTest.php` | `readonly` property constraints; value object immutability. Default values for `fromCache` and `providerError`. |
| `ApiFloodGuardHooksTest` | `tests/src/Unit/Hook/ApiFloodGuardHooksTest.php` | `cacheBinInfo()` returns array with key `api_flood_guard`. `cron()` queries database and logs a summary INFO entry (mock database connection). |

### Functional Tests (BrowserTestBase)

Location: `tests/src/Functional/`
Namespace: `Drupal\Tests\api_flood_guard\Functional\`
Base class: `Drupal\Tests\BrowserTestBase`

| Test Class | File | What It Tests |
|---|---|---|
| `ApiFloodGuardSettingsFormTest` | `tests/src/Functional/Form/ApiFloodGuardSettingsFormTest.php` | Admin user (with `administer api flood guard`) can load the settings page (200). Anonymous user receives 403. Form saves `ip_threshold` and `user_threshold` correctly. Invalid CIDR in allowlist (`999.999.0.0/8`) produces a form validation error. `response_code` accepts only 429 or 503. Saving the form displays a Drupal status message "The configuration options have been saved." |
| `ApiFloodSubscriberRequestTest` | `tests/src/Functional/EventSubscriber/ApiFloodSubscriberRequestTest.php` | Request to `/user/login?_format=json` (non-form) with IP exceeding `ip_threshold` receives 429 response. Response body is JSON with `errors[0].status === '429'`. `Retry-After` header is present. HTML form POST to `/user/login` without `_format=json` is NOT blocked by API Flood Guard (core form flood applies instead). Request from a CIDR-allowlisted IP is never blocked regardless of request count. Username-based blocking: repeat requests with same username credential exceed `user_threshold` and receive 429. Successful 200 login (mock downstream) clears the username flood counter. |
| `ApiFloodStateFormTest` | `tests/src/Functional/Form/ApiFloodStateFormTest.php` | Dashboard page loads for admin user. Active flood entries from `api_flood_guard.ip` namespace are listed in the table. "Clear" action on a single row removes that flood entry from the table on reload. "Clear all" bulk action removes all `api_flood_guard.*` entries. |
| `ApiFloodStatusControllerTest` | `tests/src/Functional/Controller/ApiFloodStatusControllerTest.php` | Log page loads for admin user. Block event watchdog entries (pre-seeded via `\Drupal::logger`) appear in the table with correct IP and path values. Entries with `type != 'api_flood_guard'` are not shown. |
| `AbuseIpDbIntegrationTest` | `tests/src/Functional/Plugin/IpReputation/AbuseIpDbIntegrationTest.php` | Uses a mock `http_client` middleware that returns a controlled AbuseIPDB-style JSON response with `abuseConfidenceScore: 90`. Configures `threshold: 85` and `enabled_provider: abuseipdb`. Sends a request to `/user/login?_format=json` from a non-allowlisted IP. Asserts 429 response. Sends same request with `abuseConfidenceScore: 70` (below threshold) — asserts request passes to downstream. Tests fail-open: middleware throws `ConnectException` — asserts request passes through (not blocked). |

### Drush Command Tests

Location: `tests/src/Functional/Drush/`

| Test Class | What It Tests |
|---|---|
| `ApiFloodGuardCommandsTest` | Uses `Drush\TestTraits\DrushTestTrait`. `api-flood-guard:status` outputs count of active `api_flood_guard.ip` and `api_flood_guard.user` entries. `api-flood-guard:clear --all` removes all `api_flood_guard.*` flood entries; subsequent `status` shows zero counts. `api-flood-guard:clear --ip=192.168.1.1` removes only the matching IP entry. `api-flood-guard:allowlist-add 10.0.0.0/8` adds the CIDR to config and the next request from that range is not blocked. `api-flood-guard:test-ip` with a mock HTTP middleware that returns score 90 outputs "BLOCKED (score: 90)". `api-flood-guard:test-ip` when reputation check disabled outputs "Reputation check disabled; IP would pass to flood checks". |

### Playwright / End-to-End Tests

Location: `playwright/` (project-level)

| Test File | What It Tests |
|---|---|
| `api-flood-guard-settings.spec.ts` | Navigates to `/admin/config/security/api-flood-guard`. Fills `ip_threshold` with `50`, submits. Asserts success message. Navigates back and asserts saved value is `50`. Tests CIDR validation: enters `999.0.0.0/8` in allowlist, submits, asserts inline validation error. |
| `api-flood-guard-flood-state.spec.ts` | Seeds flood entries via Drush. Navigates to `/admin/config/security/api-flood-guard/flood-state`. Asserts the seeded entries appear in the table. Clicks "Clear" on a single row and asserts it is removed from the table. Clicks "Clear all" and asserts the table becomes empty. Waits 35 seconds and asserts the auto-refresh interval fires (table row count changes after new entries are seeded via Drush in the background). |
| `api-flood-guard-log.spec.ts` | Triggers a blocked request via Drush test helper. Navigates to `/admin/config/security/api-flood-guard/log`. Asserts the block event row is visible with correct severity badge and path. |
| `api-flood-guard-block-response.spec.ts` | Sends a raw `fetch()` request (via Playwright `page.evaluate()`) to `/user/login?_format=json` with a credential header, from an IP that has been pre-blocked via Drush. Asserts the response status is 429. Asserts `Retry-After` header is present. Asserts response body `Content-Type` is `application/vnd.api+json` or `application/json`. Asserts `errors[0].status === '429'`. |

### Test Coverage Goals

| Coverage Area | Target |
|---|---|
| `ApiEndpointDetector` | 100% branch coverage — all path match modes, form detection, credential extraction variants |
| `ApiFloodManager` | 100% branch coverage — allowlist (hit/miss), reputation (blocked/allowed/error), IP flood (blocked/allowed), user flood (blocked/allowed), register, clear |
| `AbuseIpDb` plugin | 100% line coverage — cache hit, cache miss + success, cache miss + API error, miss + non-200 |
| `ApiFloodSubscriber` | onRequest block and allow paths; onResponse clear path |
| `ApiFloodGuardSettingsForm` | All validation rules and save path (functional) |
| `ApiFloodStateForm` | Table rendering, per-row clear, bulk clear (functional) |
| End-to-end block enforcement | Full request lifecycle (Playwright) |

---

## Appendix: Value Objects

### `IpReputationResult`

```php
// src/Value/IpReputationResult.php
declare(strict_types=1);

namespace Drupal\api_flood_guard\Value;

final readonly class IpReputationResult {
    public function __construct(
        public readonly bool $isBlocked,
        public readonly int $confidenceScore,
        public readonly array $abuseCategories = [],
        public readonly string $providerName = '',
        public readonly bool $fromCache = false,
        public readonly bool $providerError = false,
    ) {}
}
```

### `FloodDecision`

```php
// src/Value/FloodDecision.php
declare(strict_types=1);

namespace Drupal\api_flood_guard\Value;

final readonly class FloodDecision {
    public function __construct(
        public readonly bool $allowed,
        public readonly string $reason,        // 'ip' | 'user' | 'reputation' | 'allowlist' | 'passed'
        public readonly string $identifier,    // IP string or hashed username
        public readonly int $retryAfter = 0,   // seconds until retry is permitted
    ) {}
}
```

These classes require no Drupal service registration. They are plain PHP 8.2 readonly objects used as typed return values.

---

## Appendix: Full File Manifest

```
api_flood_guard/
├── api_flood_guard.info.yml
├── api_flood_guard.module
├── api_flood_guard.services.yml
├── api_flood_guard.routing.yml
├── api_flood_guard.permissions.yml
├── api_flood_guard.links.menu.yml
├── api_flood_guard.drush.yml
├── composer.json
├── config/
│   ├── install/
│   │   └── api_flood_guard.settings.yml
│   └── schema/
│       └── api_flood_guard.schema.yml
├── js/
│   └── flood-state-refresh.js
└── src/
    ├── Annotation/
    │   └── IpReputationProvider.php
    ├── Contract/
    │   └── IpReputationProviderInterface.php
    ├── Controller/
    │   └── ApiFloodStatusController.php
    ├── Drush/
    │   └── Commands/
    │       └── ApiFloodGuardCommands.php
    ├── EventSubscriber/
    │   └── ApiFloodSubscriber.php
    ├── Form/
    │   ├── ApiFloodGuardSettingsForm.php
    │   └── ApiFloodStateForm.php
    ├── Hook/
    │   └── ApiFloodGuardHooks.php
    ├── Plugin/
    │   ├── IpReputation/
    │   │   ├── AbuseIpDb.php
    │   │   └── NullProvider.php
    │   └── Manager/
    │       └── IpReputationManager.php
    ├── Service/
    │   ├── ApiEndpointDetector.php
    │   └── ApiFloodManager.php
    └── Value/
        ├── FloodDecision.php
        └── IpReputationResult.php
```

---

*Architecture document version 1.0 — API Flood Guard for Drupal 11*
