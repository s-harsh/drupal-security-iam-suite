# API Flood Guard — Design Document

## Problem Statement

Drupal sites increasingly serve as headless or hybrid backends, exposing JSON:API, REST, and OAuth token endpoints to external consumers including mobile apps, single-page applications, and third-party integrations. These API entry points are systematically targeted by credential-stuffing bots, brute-force tools, and distributed scanning campaigns that probe authentication endpoints thousands of times per minute across rotating IP pools.

Drupal core's built-in flood protection (`FloodInterface`) addresses login attempts submitted through the standard HTML form (`/user/login` with form submit), but this protection does not extend uniformly to:

- **JSON:API** endpoints (`/jsonapi/*`) accepting `Authorization` headers with Basic or Bearer credentials.
- **REST user login** (`/user/login?_format=json`) handled by `UserAuthenticationController`.
- **OAuth2 token** endpoints (`/oauth/token`) provided by contrib modules such as Simple OAuth.
- **Custom authentication** endpoints registered by contrib or custom modules.

A long-standing Drupal core issue ([#2160021](https://www.drupal.org/project/drupal/issues/2160021)) confirmed that Basic Auth has no flood control. The Simple OAuth module (SA-CONTRIB-2025-114) had a critical access bypass, illustrating the fragility of relying on individual authentication modules to self-police rate limiting. The `rate_limits` contrib module applies route-level throttling but can permanently lock legitimate API users until manual admin intervention; `flood_control` contrib improves the admin UI for form login but does not cover API paths.

The result is a systematic security gap: API authentication endpoints are effectively unguarded against automated credential attacks, leaving sites vulnerable to account takeover and data exfiltration while consuming server resources and generating noise that drowns out legitimate monitoring signals.

API Flood Guard fills this gap with a dedicated, API-endpoint-aware flood control layer that sits at the earliest possible request interception point, applies configurable per-IP and per-username thresholds, integrates with an extensible IP reputation plugin system, maintains an IP allowlist, and surfaces flood state visibility through an admin UI backed by structured database logging.

---

## Solution Overview

API Flood Guard is a Drupal 11 contributed module that registers a high-priority `KernelEvents::REQUEST` event subscriber. For every incoming HTTP request, the subscriber identifies whether the request targets a protected API authentication path, then applies a multi-stage decision pipeline:

1. **Path detection** — The subscriber checks the request path against a configurable set of prefixes and exact paths (`/jsonapi`, `/user/login`, `/oauth/token`, `/rest/user/login`), applying protection only to matched paths to avoid adding latency to non-API traffic.

2. **Allowlist check** — The client IP is compared against a configurable CIDR-aware allowlist. Requests from trusted ranges (e.g., internal networks, monitoring services) bypass all flood checks and proceed immediately.

3. **IP reputation check** — If an IP reputation provider plugin is configured and enabled, the client IP is checked against that provider (e.g., AbuseIPDB). IPs whose confidence score exceeds the configured threshold are immediately blocked, without consuming a flood counter slot.

4. **Per-IP flood check** — The client IP is checked against the IP-based flood counter using `FloodInterface::isAllowed()`. If the IP has exceeded the configured threshold within the time window, the request is immediately terminated.

5. **Per-username flood check** — For requests carrying credentials in the request body or `Authorization` header, the username or client ID is extracted and checked against the username-based flood counter. If the threshold is exceeded, the request is blocked.

6. **Flood registration** — For requests that pass all checks, a flood event is registered using `FloodInterface::register()` to count this attempt toward future threshold evaluations.

7. **Response** — Blocked requests receive a configurable HTTP response (default: `429 Too Many Requests`) with a `Retry-After` header. The response body is either JSON or plain text depending on the request's `Accept` header, ensuring API clients receive machine-parseable error payloads.

8. **Logging** — Every block event is logged to Drupal's watchdog system (dblog) at `warning` severity with structured context: client IP, targeted path, matched flood rule, username (if extracted), and IP reputation data.

9. **Success clearing** — On a successful authentication (detected via response status 200 from downstream), the per-username flood counter is cleared, preventing legitimate users from being permanently locked out after a period of testing.

The module exposes a plugin manager (`IpReputationProvider`) using Drupal's annotation-based discovery, allowing contrib and custom modules to add reputation providers without modifying API Flood Guard's core code. A built-in `AbuseIpDbProvider` plugin ships with the module.

An admin UI at `/admin/config/security/api-flood-guard` provides real-time visibility into current flood state (active blocks, counters, top blocked IPs) and allows administrators to manually clear individual or bulk flood entries without Drush access.

---

## User Stories

**As a site security administrator, I want** API authentication endpoints to be rate-limited independently of the HTML login form, **so that** credential-stuffing bots targeting JSON:API or OAuth endpoints do not bypass the protections that apply to form-based logins.

**As a site security administrator, I want** to configure separate flood thresholds for IP-based and username-based limits, **so that** I can apply stricter controls on repeated attempts against a single account while remaining tolerant of transient surges from shared NAT addresses.

**As a site security administrator, I want** a CIDR-aware IP allowlist, **so that** internal services, monitoring tools, and CI/CD pipelines are never blocked by flood controls, regardless of request volume.

**As a site security administrator, I want** integration with AbuseIPDB (and other IP reputation providers via plugin), **so that** IPs with documented abuse histories are blocked before consuming flood counter slots, reducing the window of attack.

**As a site security administrator, I want** an admin UI showing current flood state and blocked IPs, **so that** I can identify active attacks, confirm protection is working, and manually unblock legitimate users who were incorrectly flagged.

**As a site security administrator, I want** all block events logged to Drupal's database log with structured context, **so that** I can correlate blocked API attempts with other security events, generate reports, and feed data to SIEM pipelines.

**As a developer integrating third-party services, I want** my service's IP to be added to the module allowlist via a simple config form, **so that** automated integration tests and scheduled API calls are never interrupted by flood controls.

**As a module developer, I want** to implement the `IpReputationProviderInterface` and annotate my class as an `@IpReputationProvider` plugin, **so that** I can add a custom reputation source (e.g., a local threat feed, Cloudflare, Tor exit node list) without forking API Flood Guard.

**As an API consumer (mobile app or SPA), I want** to receive a standards-compliant `429 Too Many Requests` response with a `Retry-After` header and a JSON error body when I exceed limits, **so that** my client can implement exponential backoff without parsing HTML error pages.

**As a DevOps engineer, I want** Drush commands to inspect and clear flood entries, **so that** I can integrate flood management into automated runbooks and incident response scripts.

---

## Feature List

### Core Flood Protection

- **KernelEvents::REQUEST subscriber at priority 300** — Executes before Drupal's routing, authentication, and session systems to intercept requests with minimal overhead. Priority 300 places it after Drupal's maintenance mode subscriber (priority 30) but well before route matching and authentication subscribers.
- **Configurable protected paths** — Default set: `/jsonapi` (prefix), `/user/login` (exact, non-HTML), `/oauth/token` (exact), `/rest/user/login` (exact). Administrators can add, remove, or adjust path matching rules (prefix vs. exact match).
- **Per-IP flood threshold** — Tracks authentication attempts from a given IP using `FloodInterface::register('api_flood_guard.ip', $window, $ip)`. Configurable limit (default: 100 attempts) and window (default: 1 hour). Uses a separate flood event name space from core's login form to avoid cross-contamination.
- **Per-username flood threshold** — Extracts username or OAuth `client_id` from request body or `Authorization: Basic` header and tracks with `FloodInterface::register('api_flood_guard.user', $window, $identifier)`. Configurable limit (default: 20 attempts) and window (default: 15 minutes).
- **Configurable response code** — Default `429 Too Many Requests`. Alternatively configurable as `503 Service Unavailable` for edge cases where downstream proxies must handle throttling differently.
- **Retry-After header** — All 429 responses include a `Retry-After` header calculated as the remaining seconds in the current flood window, compliant with RFC 6585 and RFC 9110.
- **Content-negotiated response body** — If the request `Accept` header includes `application/json` or `application/vnd.api+json`, the block response body is a JSON object `{"errors": [{"status": "429", "title": "Too Many Requests", "detail": "..."}]}` following JSON:API error format. Otherwise, a plain-text body is returned.
- **Flood counter clearing on successful auth** — A `KernelEvents::RESPONSE` subscriber (low priority) inspects responses from protected paths. When a 200 response is detected, the per-username flood counter for that identifier is cleared using `FloodInterface::clear()`.

### IP Allowlist

- **CIDR notation support** — Allowlist entries accept individual IPv4/IPv6 addresses and CIDR ranges (e.g., `10.0.0.0/8`, `192.168.1.0/24`, `::1`).
- **Config-stored list** — Allowlist is stored in module configuration (`api_flood_guard.settings`) and editable through the admin UI without code deployment.
- **Request-stack IP extraction** — Uses `\Symfony\Component\HttpFoundation\Request::getClientIp()` respecting `trusted_proxies` and `trusted_headers` already configured in `settings.php`, ensuring correctness behind load balancers.
- **Allowlist bypass is total** — Allowlisted IPs skip IP reputation checks, per-IP flood checks, and per-username flood checks. They are still logged at `debug` level if debug logging is enabled.

### IP Reputation Plugin System

- **`IpReputationProviderInterface`** — Defines the plugin contract: `checkIp(string $ip): IpReputationResult`. The result object carries `isBlocked(): bool`, `confidenceScore(): int`, `abuseCategories(): array`, and `providerName(): string`.
- **`@IpReputationProvider` annotation** — Custom annotation class extending `\Drupal\Component\Annotation\Plugin` with fields: `id`, `label`, `description`, `api_endpoint`.
- **`IpReputationProviderManager`** — Extends `DefaultPluginManager` with annotation-based discovery in `Plugin/IpReputationProvider/` namespaces, alter hook `api_flood_guard_ip_reputation_provider_info_alter`, and 1-hour cache bin.
- **AbuseIPDB built-in plugin** — `AbuseIpDbProvider` implements `IpReputationProviderInterface` using Drupal's `http_client` (Guzzle) service to call `https://api.abuseipdb.com/api/v2/check` with `Key: {api_key}` header. Returns blocked if `abuseConfidenceScore` exceeds configured threshold (default: 85). Response is cached per-IP in a dedicated cache bin (`cache.api_flood_guard`) with TTL equal to the configured cache duration (default: 1 hour).
- **Fail-open behavior** — If the reputation provider returns an error (network timeout, API key invalid, rate limit from the provider itself), the request is allowed through and the failure is logged at `warning` level. Reputation checks never block legitimate traffic due to provider unavailability.
- **Provider enable/disable** — Each configured provider can be individually enabled or disabled without removing its configuration.

### Admin UI

- **Settings form** at `/admin/config/security/api-flood-guard` (permission: `administer api flood guard`):
  - Protected paths list (add/remove entries, set prefix vs. exact match mode per entry).
  - Per-IP threshold and window.
  - Per-username threshold and window.
  - Response code selector (429 / 503).
  - IP allowlist textarea (one CIDR per line).
  - IP reputation provider selector and per-provider settings sub-form (API key, confidence threshold, cache TTL, max age in days for AbuseIPDB).
  - Debug logging toggle.
- **Flood state dashboard** at `/admin/config/security/api-flood-guard/flood-state` (permission: `administer api flood guard`):
  - Table of active flood entries from `flood` database table filtered to `api_flood_guard.*` event namespaces.
  - Columns: event name, identifier (IP or username hash), request count, window expiry, actions.
  - "Clear" action per row and bulk "Clear all API flood entries" operation.
  - Top-10 blocked IPs and top-10 blocked usernames in the current window (sortable).
  - Auto-refresh every 30 seconds via JavaScript without full page reload.
- **Recent block events log** at `/admin/config/security/api-flood-guard/log` — Pre-filtered view of dblog entries with `type = 'api_flood_guard'`, paginated, with severity filter.

### Logging and Observability

- **Structured dblog entries** — Every block event logged with: `type = 'api_flood_guard'`, `severity = RfcLogLevel::WARNING`, variables including `%ip`, `%path`, `%rule` (ip|username|reputation), `%identifier`, `%score` (for reputation blocks), `%provider`.
- **Logger channel** — Registers `logger.channel.api_flood_guard` service allowing site builders to route API Flood Guard logs separately in syslog or external logging modules.
- **Drush commands**:
  - `drush api-flood-guard:status` — Shows current active flood entry counts by namespace.
  - `drush api-flood-guard:clear [--ip=<ip>] [--user=<name>] [--all]` — Clears flood entries matching filters.
  - `drush api-flood-guard:allowlist-add <cidr>` — Adds CIDR to allowlist without admin UI access.
  - `drush api-flood-guard:test-ip <ip>` — Checks a given IP against the configured reputation provider and prints results.

### Compatibility and Integration

- **Simple OAuth (`simple_oauth`)** — Detects `/oauth/token` requests and extracts `client_id` from POST body for per-username tracking. Compatible with Simple OAuth 6.x (Drupal 11 support).
- **JSON:API core module** — Detects `/jsonapi` prefix; extracts `Authorization: Basic` credentials for per-username tracking when present.
- **REST module** — Detects `/user/login` with `?_format=json` or `Content-Type: application/json` and `/rest/user/login`.
- **Flood Control contrib module** (`flood_control`) — Coexists without conflict; operates on separate event namespaces (`api_flood_guard.*` vs. `user.*`).
- **Rate Limits contrib module** (`rate_limits`) — Can run alongside for route-level rate limiting on non-auth API routes; API Flood Guard focuses exclusively on authentication paths.
- **Login Security module** — Coexists; Login Security operates on form submit hooks, API Flood Guard operates on kernel request events for non-form paths.

---

## Security Considerations

### Separate Flood Namespace

API Flood Guard uses flood event names prefixed with `api_flood_guard.` (e.g., `api_flood_guard.ip`, `api_flood_guard.user`) to maintain complete independence from Drupal core's form-login flood entries (`user.failed_login_ip`, `user.failed_login_user`). This prevents cross-contamination: a brute-force attack via the REST endpoint cannot exhaust the HTML form's flood slots, and vice versa. Administrators can tune thresholds for API vs. form login independently based on their actual risk profiles.

### Username Extraction and Canonicalization

When extracting a username from the request for per-username flood tracking, the raw value is normalized to lowercase and trimmed before use as the flood identifier. This prevents trivial bypass via `Admin` vs. `admin` vs. `ADMIN`. For `Authorization: Basic` headers, the base64-decoded credential pair is split on the first colon only; the username portion is used and the password portion is discarded immediately without being stored or logged. Usernames are never written to log messages directly; log entries reference a truncated identifier hash to prevent credential leakage.

### IP Spoofing Mitigation

The module relies on `Request::getClientIp()` from Symfony's HttpFoundation, which respects the `trusted_proxies` setting already required by Drupal for correct behavior behind reverse proxies. Sites that have not configured `trusted_proxies` will use the direct TCP connection IP (i.e., `REMOTE_ADDR`), which cannot be spoofed at the application layer. The module does not trust `X-Forwarded-For` or `X-Real-IP` headers on its own; those are only respected when the source proxy IP is in Drupal's trusted proxy list. This prevents IP spoofing via manipulated headers.

### Fail-Open for Reputation Checks, Fail-Closed for Flood Checks

IP reputation checks (AbuseIPDB and any third-party plugins) use fail-open behavior: if the external API is unreachable or returns an error, the check is skipped and the request proceeds. This prevents a reputation provider outage from causing a denial-of-service on the Drupal site itself. In contrast, flood checks use Drupal's built-in `flood` table which is local and highly available; these checks fail-closed (the threshold evaluation is performed and a block is applied if the count is exceeded).

### Cache Timing Attack Prevention

Flood check responses are returned in constant time regardless of whether the IP is blocked or the threshold check involves a database query. The `FloodInterface` implementation uses indexed database queries on the `flood` table; no timing side-channel information is exposed by the response time difference between blocked and allowed requests (both involve the same flood table read).

### Allowlist Security

The IP allowlist is stored in Drupal configuration, which requires `administer api flood guard` permission to modify (mapped to `administer site configuration` by default). Allowlist changes are tracked in Drupal's configuration management system, so they appear in `drush config:status` and can be reviewed in configuration export diffs, preventing unauthorized changes from going unnoticed.

### Response Body Information Disclosure

Error responses do not include internal details such as the flood counter value, the remaining window duration (beyond the `Retry-After` seconds), or the specific rule that triggered the block. The JSON error `detail` field contains only a generic human-readable message configurable by the administrator, defaulting to "Too many authentication requests. Please wait before trying again."

### AbuseIPDB API Key Storage

The AbuseIPDB API key is stored in Drupal's configuration system under `api_flood_guard.settings:reputation_providers.abuseipdb.api_key`. This field is marked `type: string` in the config schema but should be stored using the Key module (`key`) integration when available, keeping the raw secret out of the exported configuration YAML. The admin form detects the presence of the Key module and offers a key entity selector as an alternative to a plain-text field.

### Flood Table Cleanup

Drupal's `flood` table is cleaned by cron automatically via `Drupal\Core\Flood\DatabaseBackend::garbageCollection()`. API Flood Guard entries participate in this cleanup without additional configuration. The module does not create a separate persistence layer for flood data, ensuring consistency with core's flood management practices.

### OWASP Alignment

The design addresses the following OWASP categories:
- **A07:2021 Identification and Authentication Failures** — Rate-limiting authentication endpoints directly.
- **A05:2021 Security Misconfiguration** — Sensible defaults that protect out of the box without requiring complex setup.
- **A09:2021 Security Logging and Monitoring Failures** — Structured logging of every block event to enable detection and incident response.

---

## Drupal Implementation Notes

### Module Structure

```
api_flood_guard/
├── api_flood_guard.info.yml
├── api_flood_guard.services.yml
├── api_flood_guard.routing.yml
├── api_flood_guard.permissions.yml
├── api_flood_guard.links.menu.yml
├── api_flood_guard.drush.yml
├── config/
│   ├── install/
│   │   └── api_flood_guard.settings.yml
│   └── schema/
│       └── api_flood_guard.schema.yml
├── src/
│   ├── EventSubscriber/
│   │   └── ApiFloodGuardSubscriber.php
│   ├── Plugin/
│   │   └── IpReputationProvider/
│   │       ├── AbuseIpDbProvider.php
│   │       └── NullProvider.php
│   ├── Annotation/
│   │   └── IpReputationProvider.php
│   ├── IpReputationProviderInterface.php
│   ├── IpReputationResult.php
│   ├── IpReputationProviderManager.php
│   ├── IpAddressHelper.php
│   ├── Form/
│   │   ├── ApiFloodGuardSettingsForm.php
│   │   └── ApiFloodGuardFloodStateForm.php
│   └── Controller/
│       └── ApiFloodGuardLogController.php
└── js/
    └── flood-state-refresh.js
```

### EventSubscriber Registration

```yaml
# api_flood_guard.services.yml
services:
  api_flood_guard.subscriber:
    class: Drupal\api_flood_guard\EventSubscriber\ApiFloodGuardSubscriber
    arguments:
      - '@flood'
      - '@config.factory'
      - '@logger.channel.api_flood_guard'
      - '@plugin.manager.ip_reputation_provider'
      - '@request_stack'
    tags:
      - { name: event_subscriber }

  plugin.manager.ip_reputation_provider:
    class: Drupal\api_flood_guard\IpReputationProviderManager
    parent: default_plugin_manager

  logger.channel.api_flood_guard:
    parent: logger.channel_base
    arguments: ['api_flood_guard']
```

### EventSubscriber Priority

```php
public static function getSubscribedEvents(): array {
    return [
        KernelEvents::REQUEST => [['onRequest', 300]],
        KernelEvents::RESPONSE => [['onResponse', -100]],
    ];
}
```

Priority 300 on `KernelEvents::REQUEST` ensures execution before route matching (priority 32), authentication (priority 8), and page cache (priority 27). The `onResponse` subscriber at priority -100 runs after the primary response is built, to detect successful authentications and clear flood counters.

### FloodInterface Usage Pattern

```php
// Registration (counting the attempt):
$this->flood->register(
    'api_flood_guard.ip',
    $ipWindow,
    $clientIp
);

// Checking the threshold:
if (!$this->flood->isAllowed('api_flood_guard.ip', $ipThreshold, $ipWindow, $clientIp)) {
    return $this->buildBlockResponse($request, 'ip', $clientIp);
}

// Clearing on success:
$this->flood->clear('api_flood_guard.user', $usernameIdentifier);
```

The `identifier` parameter for per-username tracking must be unique and consistent. The module uses `hash('sha256', strtolower(trim($username)))` as the identifier to avoid storing raw usernames in the flood table while still providing consistent cross-request tracking.

### Path Detection Logic

```php
private function isProtectedPath(Request $request): bool {
    $path = $request->getPathInfo();
    $config = $this->configFactory->get('api_flood_guard.settings');
    foreach ($config->get('protected_paths') as $entry) {
        if ($entry['match'] === 'prefix' && str_starts_with($path, $entry['path'])) {
            return true;
        }
        if ($entry['match'] === 'exact' && $path === $entry['path']) {
            return true;
        }
    }
    return false;
}
```

For `/user/login`, the module additionally checks that the request is not an HTML form submission by inspecting the `Content-Type` request header and `_format` query parameter. Requests with `Content-Type: application/x-www-form-urlencoded` targeting `/user/login` without `_format=json` are skipped (they are handled by core's form flood protection).

### IpReputationProviderInterface

```php
namespace Drupal\api_flood_guard;

interface IpReputationProviderInterface {
    public function checkIp(string $ip): IpReputationResult;
    public function isConfigured(): bool;
    public function getPluginId(): string;
    public function getPluginDefinition(): array;
}
```

### Plugin Annotation Class

```php
namespace Drupal\api_flood_guard\Annotation;

use Drupal\Component\Annotation\Plugin;

/**
 * @Annotation
 */
class IpReputationProvider extends Plugin {
    public string $id;
    public string $label;
    public string $description = '';
    public string $api_endpoint = '';
}
```

### AbuseIPDB Plugin Implementation

The `AbuseIpDbProvider` plugin:
- Uses `@inject`-compatible constructor receiving `http_client`, `cache.api_flood_guard`, and `config.factory`.
- Calls `GET https://api.abuseipdb.com/api/v2/check` with headers `Key: {api_key}`, `Accept: application/json` and query params `ipAddress`, `maxAgeInDays` (default: 30), `verbose` (false).
- Caches the response in `cache.api_flood_guard` bin with cache ID `abuseipdb:{md5($ip)}` and TTL from config.
- Returns `IpReputationResult` with `isBlocked = ($response['data']['abuseConfidenceScore'] >= $threshold)`.

### Admin Form and Permissions

```yaml
# api_flood_guard.permissions.yml
administer api flood guard:
  title: 'Administer API Flood Guard'
  description: 'Configure flood thresholds, manage allowlists, and view flood state.'
  restrict access: true
```

The settings form extends `ConfigFormBase`. The flood state dashboard at `/admin/config/security/api-flood-guard/flood-state` queries the `flood` table directly via Database API using `\Drupal::database()->select('flood', 'f')->condition('f.event', 'api_flood_guard.%', 'LIKE')`.

### Configuration Schema

```yaml
# config/schema/api_flood_guard.schema.yml
api_flood_guard.settings:
  type: config_object
  label: 'API Flood Guard settings'
  mapping:
    protected_paths:
      type: sequence
      label: 'Protected paths'
      sequence:
        type: mapping
        mapping:
          path:
            type: string
            label: 'Path'
          match:
            type: string
            label: 'Match type (prefix|exact)'
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
      label: 'HTTP response code for blocked requests'
    block_message:
      type: string
      label: 'Block response message'
    allowlist:
      type: sequence
      label: 'IP allowlist (CIDR)'
      sequence:
        type: string
    reputation_providers:
      type: mapping
      label: 'IP reputation provider settings'
      mapping:
        enabled_provider:
          type: string
          label: 'Active provider plugin ID'
        abuseipdb:
          type: mapping
          mapping:
            api_key:
              type: string
              label: 'AbuseIPDB API key'
            threshold:
              type: integer
              label: 'Confidence score threshold (0-100)'
            max_age_days:
              type: integer
              label: 'Maximum report age in days'
            cache_ttl:
              type: integer
              label: 'Cache TTL in seconds'
    debug_logging:
      type: boolean
      label: 'Enable debug-level logging'
```

### Hooks Used

- **`hook_cache_bin_info()`** — Declares the `cache.api_flood_guard` bin for IP reputation response caching.
- **`hook_help()`** — Provides admin help text at `admin/help/api_flood_guard`.
- **`api_flood_guard_ip_reputation_provider_info_alter()`** — Allows other modules to alter the discovered plugin definitions.
- **`hook_cron()`** — Optional: logs a summary of flood activity (total blocks in last 24h) to dblog for monitoring dashboards.

---

## Configuration Options

| Config key | Type | Default | Description |
|---|---|---|---|
| `protected_paths` | sequence | See below | List of path entries with `path` and `match` (prefix/exact) keys |
| `ip_threshold` | integer | `100` | Max API auth attempts per IP per window before blocking |
| `ip_window` | integer | `3600` | IP flood window in seconds (default: 1 hour) |
| `user_threshold` | integer | `20` | Max API auth attempts per username per window before blocking |
| `user_window` | integer | `900` | Username flood window in seconds (default: 15 minutes) |
| `response_code` | integer | `429` | HTTP status code returned to blocked requests (429 or 503) |
| `block_message` | string | `"Too many authentication requests. Please wait before trying again."` | Human-readable detail in error response body |
| `allowlist` | sequence | `[]` | CIDR ranges exempt from all flood checks |
| `reputation_providers.enabled_provider` | string | `""` | Plugin ID of active reputation provider; empty string disables reputation checking |
| `reputation_providers.abuseipdb.api_key` | string | `""` | AbuseIPDB v2 API key |
| `reputation_providers.abuseipdb.threshold` | integer | `85` | Abuse confidence score (0-100) above which an IP is blocked |
| `reputation_providers.abuseipdb.max_age_days` | integer | `30` | Maximum age of abuse reports to consider (AbuseIPDB `maxAgeInDays` param) |
| `reputation_providers.abuseipdb.cache_ttl` | integer | `3600` | Seconds to cache AbuseIPDB responses per IP |
| `debug_logging` | boolean | `false` | Log debug-level entries for allowed requests (high volume; use only for troubleshooting) |

**Default `protected_paths` value** (installed via `config/install/api_flood_guard.settings.yml`):

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
```

---

## Composer Dependencies

| Package | Version | Purpose |
|---|---|---|
| `drupal/core` | `^11.0` | Core Drupal framework (FloodInterface, EventSubscriber, Plugin API) |

**No third-party PHP library dependencies** — The AbuseIPDB HTTP call is made via Drupal's built-in `http_client` service (a pre-configured Guzzle instance). CIDR matching for the allowlist is implemented using native PHP `inet_pton()` and bitwise operations, avoiding the need for a CIDR library. This keeps the Composer footprint minimal and avoids dependency conflicts.

**Optional integration dependencies** (detected at runtime, not required in `composer.json`):

| Package | Purpose if present |
|---|---|
| `drupal/key` | Store AbuseIPDB API key as a Key entity rather than plain config |
| `drupal/simple_oauth` | Enables `/oauth/token` client_id extraction for per-username tracking |
| `drupal/flood_control` | Coexists; API Flood Guard's admin UI links to Flood Control's unblock UI for form-login entries |

---

## Integration Points

### Drupal Core JSON:API Module

When `jsonapi` module is enabled, requests to `/jsonapi/*` are protected. The subscriber detects the `_is_jsonapi` request attribute (set by JSON:API's route enhancer) as a secondary confirmation, but path prefix matching is the primary detection method to intercept requests before route matching runs.

### Drupal Core REST Module

For `/user/login?_format=json` handled by `UserAuthenticationController::login()`, API Flood Guard supplements (not replaces) the flood control already present in that controller. Core's `floodControl()` check in `UserAuthenticationController` runs after the subscriber has already enforced the API-specific threshold; if API Flood Guard clears the request, core's flood check then applies its own (typically form-oriented) thresholds. The two systems use different flood event names and do not interfere.

### Simple OAuth Module (`simple_oauth`)

Detects POST requests to `/oauth/token` with `grant_type=password` or `grant_type=client_credentials` in the POST body. Extracts `client_id` for per-username (per-client) flood tracking. For `grant_type=authorization_code`, the `code` parameter is not used as an identifier (codes are single-use and cannot be brute-forced the same way); IP-only tracking applies for authorization code exchanges.

### Dblog Module

API Flood Guard logs to the watchdog system using `LoggerChannelFactoryInterface`. The `api_flood_guard` logger channel maps to a `logger.channel.api_flood_guard` service. The admin log view at `/admin/config/security/api-flood-guard/log` wraps a database query against `watchdog` filtered by `type = 'api_flood_guard'` for quick access without navigating through the full dblog report.

### Flood Control Contrib Module (`flood_control`)

API Flood Guard's admin UI references the Flood Control module's unblock interface (`/admin/config/people/flood-control`) for form-login flood entries. If Flood Control is not installed, this link is omitted. The two modules use entirely separate flood event namespaces and do not share configuration.

### Key Module (`key`)

When `key` module is installed, the AbuseIPDB API key field in the settings form renders as a Key entity selector rather than a plain text field. The plugin's `getApiKey()` method checks for the Key service and retrieves the value through it if a key entity ID is stored in config, falling back to the raw string otherwise.

### Syslog / External Logging Modules

Because API Flood Guard registers its own `logger.channel.api_flood_guard` service, site builders using `syslog` module or contrib logging modules (e.g., `monolog`, `papertrail`) can route API Flood Guard entries to separate destinations by adding the channel to their logging configuration, enabling dedicated security log streams without filtering noise from the main Drupal log.

### Configuration Management

All settings are exportable via `drush config:export` / `drush config:import` and deployable through standard CI/CD pipelines. The `allowlist` and `protected_paths` values are part of `api_flood_guard.settings` config object, making per-environment overrides possible via `$config['api_flood_guard.settings']['allowlist']` in `settings.php` or environment-specific config splits.

---

*Design document version 1.0 — API Flood Guard for Drupal 11*
