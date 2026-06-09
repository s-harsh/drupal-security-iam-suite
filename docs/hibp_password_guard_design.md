# HIBP Password Guard — Design Document

## Problem Statement

Drupal sites routinely allow users to set passwords that have already appeared in known data breaches. A password such as "Summer2024!" may satisfy typical complexity rules (uppercase, lowercase, digits, symbols) while having been exposed in millions of breach records. Standard Drupal password validation has no mechanism to detect this class of weak credential.

The "Have I Been Pwned" (HIBP) Pwned Passwords service, maintained by security researcher Troy Hunt and now operated by the HIBP Foundation, exposes a freely available API that holds over 10 billion breached password hashes. Using a k-anonymity model, clients can query this API without ever transmitting the candidate password or its full hash to a remote server. Only the first 5 hexadecimal characters of the SHA-1 hash (a 5-character prefix out of 40) are sent; the server returns all matching hash suffixes for that prefix, and the full comparison happens entirely on the client side.

Without a well-integrated Drupal 11 module implementing this check, site administrators must choose between:

- Accepting insecure passwords that meet only syntactic complexity rules.
- Building custom, ad-hoc integrations that lack caching, graceful degradation, status reporting, and administrative controls.
- Relying on older contributed modules (`password_hibp`, `pwned_passwords`, `password_haveibeenpwned`) that target Drupal 8/9 and do not follow Drupal 11 plugin conventions or Password Policy module 4.x integration patterns.

This module fills that gap with a production-grade, security-first, Drupal 11-native implementation.

---

## Solution Overview

HIBP Password Guard is a Drupal 11 contributed module that integrates with the [Password Policy](https://www.drupal.org/project/password_policy) module as a first-class `PasswordConstraint` plugin. When a user sets or changes a password, the plugin:

1. Computes the SHA-1 hash of the candidate password entirely in PHP (no network call needed at this step).
2. Takes the uppercase first 5 hex characters of that hash as the **k-anonymity prefix**.
3. Issues a GET request to `https://api.pwnedpasswords.com/range/{PREFIX}` via Drupal's Guzzle-backed `http_client` service.
4. Parses the response: a list of `SUFFIX:COUNT` pairs separated by CRLF.
5. Checks whether the remaining 35 characters of the local SHA-1 hash appear among the returned suffixes.
6. If a match is found (COUNT > 0), the password is rejected with a configurable violation message.

The full plaintext password is never transmitted, stored in a log, or persisted anywhere beyond normal PHP call stack memory.

A dedicated cache bin stores responses keyed by the 5-character prefix with a configurable TTL (default 24 hours). Because the prefix space is large (16^5 = 1,048,576 unique prefixes) but any single site queries only a small subset, the cache is shallow and memory-efficient.

When the HIBP API is unreachable, the module supports two operator-configured degradation modes:

- **Fail open** (default): the constraint is skipped and the password is accepted. Suitable for sites that prioritise availability over strict security enforcement.
- **Fail closed**: the constraint blocks the password change with a message informing the user to try again later. Suitable for high-security environments.

A `hook_requirements()` implementation surfaces HIBP API reachability on the Drupal Status Report page (`admin/reports/status`). A Drush command `hibp:check-user` allows administrators to test whether a specific user's stored password hash (or a provided plaintext password) would be flagged, without triggering a form submission.

---

## User Stories

1. As a **site administrator**, I want to enable a "not pwned" password constraint in my site's password policy so that users cannot choose passwords that appear in known breach databases.
2. As a **site administrator**, I want to configure the cache TTL for HIBP API responses so that I can balance freshness against outbound HTTP request volume.
3. As a **site administrator**, I want to choose between fail-open and fail-closed degradation so that I can prioritise either availability or strict enforcement when HIBP is unreachable.
4. As a **site administrator**, I want to see the HIBP API reachability status on the Drupal Status Report so that I know immediately if outbound connectivity to the API is broken.
5. As a **developer or site administrator**, I want a Drush command to check whether a given username's password (or a supplied plaintext) is pwned so that I can audit accounts without forcing a password reset UI flow.
6. As an **end user**, I want to receive a clear, non-technical error message when my chosen password is known to be compromised so that I understand why my password was rejected and can choose a better one.
7. As an **end user**, I want my password to never be transmitted over the network in any recognisable form so that the security check itself does not create a new exposure risk.
8. As a **security auditor**, I want to verify through documentation and code that only a 5-character SHA-1 prefix is sent to the HIBP API so that I can confirm the k-anonymity guarantee holds.

---

## Feature List

### Core Constraint Plugin
- Implements `PasswordConstraintBase` from the Password Policy module (namespace: `Drupal\password_policy\Plugin\PasswordConstraint`).
- Declared via PHP 8 `#[Attribute]` annotation (`#[PasswordConstraint]`) with a human-readable label "Not Pwned Password".
- Exposes a `validate(string $password, PasswordPolicyEntity $policy): PasswordPolicyResult` method.
- Computes SHA-1 hash using PHP built-in `hash('sha1', $password)` — no external library needed for hashing.
- Sends only the 5-character uppercase prefix to the API endpoint `https://api.pwnedpasswords.com/range/{PREFIX}`.
- Parses the `SUFFIX:COUNT` response lines (CRLF-delimited); ignores padding lines where COUNT == 0.
- Performs a case-insensitive suffix match against the remaining 35 characters of the local hash.
- Returns a failing result with a translatable violation message if the password hash is found with COUNT >= 1.
- Respects the per-policy plugin configuration (see Configuration Options).

### HTTP Service Layer
- Dedicated PHP service class `HibpClient` (`Drupal\hibp_password_guard\HibpClient`) wrapping the injected `http_client` (Guzzle) service.
- Constructs the request with the `Add-Padding: true` header to receive padded responses (mitigates traffic analysis).
- Enforces a short connect/read timeout (default 5 seconds, configurable).
- Catches `GuzzleHttp\Exception\RequestException` and `GuzzleHttp\Exception\ConnectException` for graceful degradation.
- Does not log raw error bodies that might contain sensitive metadata; logs only status code and exception class.

### Response Caching
- Uses a dedicated Drupal cache bin `cache.hibp_password_guard` backed by `cache_factory`.
- Cache key: `hibp_range:{PREFIX}` where PREFIX is the 5-character uppercase SHA-1 prefix.
- TTL sourced from module configuration (`hibp_password_guard.settings:cache_ttl`, default 86400 seconds / 24 hours).
- Cache is populated on first successful API response and invalidated on expiry.
- Cache miss on API failure: no stale-on-error serving of incorrect data.
- On cache hit, HTTP request is skipped entirely; violation check runs against cached suffix list.

### Graceful Degradation
- Two modes: `fail_open` (default) and `fail_closed`.
- `fail_open`: API unavailability causes the constraint to return a passing result with an optional watchdog warning.
- `fail_closed`: API unavailability causes the constraint to return a failing result with a user-facing message: "Password breach check is temporarily unavailable. Please try again later."
- Both modes log a `NOTICE`-level Watchdog entry when degradation occurs, including the HTTP status code or exception type (never the password or hash).

### Admin Settings Form
- Route: `admin/config/security/hibp-password-guard`
- Permission: `administer hibp password guard` (new permission declared in `hibp_password_guard.permissions.yml`).
- Fields:
  - Enable/disable the module's constraint globally (boolean toggle; individual constraint instances are also toggle-able via Password Policy UI).
  - Cache TTL (integer, seconds, default 86400).
  - Fail open / Fail closed (radio group, default fail open).
  - HTTP request timeout (integer, seconds, default 5).
  - HIBP API base URL (text field, default `https://api.pwnedpasswords.com`; allows override for self-hosted or proxied instances).
- Form backed by `hibp_password_guard.settings` config object; schema defined in `config/schema/hibp_password_guard.schema.yml`.

### hook_requirements() — Status Report
- Implemented in `hibp_password_guard.install`.
- On `$phase == 'runtime'`:
  - Issues a lightweight probe request to `https://api.pwnedpasswords.com/range/00000` (a valid, innocuous prefix).
  - Reports `REQUIREMENT_OK` if HTTP 200 is returned.
  - Reports `REQUIREMENT_WARNING` if the request times out or returns a non-200 status.
  - Reports `REQUIREMENT_ERROR` if a connection exception is thrown.
  - Caches the probe result for 5 minutes to avoid hammering the API on repeated page loads of the Status Report.

### Drush Command: hibp:check-user
- Class: `Drupal\hibp_password_guard\Drush\Commands\HibpCommands` in `src/Drush/Commands/HibpCommands.php`.
- PHP 8 attribute: `#[CLI\Command(name: 'hibp:check-user', aliases: ['hibp-cu'])]`.
- Arguments: `username` (required string).
- Options:
  - `--plaintext=VALUE`: supply a plaintext password to test directly instead of looking up the user's stored hash.
  - `--bypass-cache`: skip the cache and force a fresh API call.
- Behaviour:
  - Without `--plaintext`: loads the user entity by name, reads the stored hashed password field, extracts the raw hash value (not the plain password, which Drupal never stores), and attempts to resolve it to a SHA-1 for comparison. If the stored hash algorithm is not SHA-1 (Drupal uses PHPass by default), warns the operator that direct hash comparison is not possible and exits cleanly.
  - With `--plaintext`: computes the SHA-1 directly and performs the HIBP check.
- Outputs a plain-language result: `[OK]` or `[WARNING]` with the breach count.
- Uses `AutowireTrait` for dependency injection of `HibpClient` and `entity_type.manager`.

### Access Controls
- New Drupal permission `administer hibp password guard` gates the settings form.
- The constraint plugin itself runs in the context of the existing Password Policy evaluation, which is already protected by Drupal's user account edit access control.
- No sensitive data is exposed via the admin UI or Drush output.

---

## Security Considerations

### K-Anonymity Guarantee
The k-anonymity model ensures that any single query to the HIBP API reveals a prefix shared by at least `k` distinct password hashes in the database (empirically several hundred to several thousand per prefix). The API operator cannot determine which specific password within that prefix was being tested. This is a cryptographic privacy guarantee backed by the design of the SHA-1 prefix space: 5 hex characters yield 16^5 = 1,048,576 possible prefixes over ~10 billion stored hashes, averaging ~10,000 hashes per prefix.

### No Plaintext Transmission
The plaintext password exists only in PHP memory during the request lifecycle. The SHA-1 hash is computed in-process via `hash('sha1', $password)`. Only the 5-character prefix is placed on the wire. The `HibpClient` service must not log the prefix in conjunction with any user identifier, to prevent prefix disclosure from logs.

### TLS Enforcement
All requests to `https://api.pwnedpasswords.com` use HTTPS. Guzzle's default behaviour enforces TLS certificate verification. This must not be disabled in configuration. If an operator overrides the base URL (e.g., for a self-hosted proxy), they are responsible for TLS on that endpoint.

### Cache Key Non-Sensitivity
The cache key `hibp_range:{PREFIX}` reveals only a 5-character hex prefix. It does not reveal the full hash, the password, or the user who triggered the lookup. This is acceptable: the same prefix is shared by thousands of distinct passwords and multiple users.

### Timing Side Channels
PHP's string comparison for suffix matching uses `strtoupper()` and `strpos()` / explicit iteration; no secret-comparison countermeasures are needed here because the suffix being searched is a hash (not a secret value that must be protected from timing oracle attacks in this context). The k-anonymity model already prevents the prefix from being sensitive.

### Fail Closed vs. Fail Open Trade-offs
Fail closed is more secure but degrades user experience during HIBP outages. Fail open maintains availability but means a window during outages where pwned passwords could be set. The default is fail open to avoid locking out users from account management during transient API issues; high-security deployments should switch to fail closed.

### Logging Discipline
- Log messages must never include: the candidate password, the full SHA-1 hash, or even the 5-character prefix in combination with a username or user ID.
- Acceptable log content: module name, operation type (cache hit/miss, API success/failure), HTTP status code, exception class name, timestamp.

### No Stored Credentials
The module does not require an HIBP API key. The Pwned Passwords Range API is freely available without authentication. No credentials are stored or managed.

### Dependency Supply Chain
The module relies only on `guzzlehttp/guzzle`, which is already a Drupal core dependency and is audited as part of Drupal's release process. No additional third-party PHP packages that could introduce supply chain risk are required.

---

## Drupal Implementation Notes

### Module Structure

```
hibp_password_guard/
  hibp_password_guard.info.yml
  hibp_password_guard.install
  hibp_password_guard.module
  hibp_password_guard.permissions.yml
  hibp_password_guard.routing.yml
  hibp_password_guard.services.yml
  hibp_password_guard.links.menu.yml
  config/
    install/
      hibp_password_guard.settings.yml
    schema/
      hibp_password_guard.schema.yml
  src/
    HibpClient.php
    Form/
      HibpSettingsForm.php
    Plugin/
      PasswordConstraint/
        NotPwnedPassword.php
    Drush/
      Commands/
        HibpCommands.php
```

### Password Policy Plugin

The Password Policy module (4.x) defines a plugin type `PasswordConstraint` with a base class at `Drupal\password_policy\Plugin\PasswordConstraint\PasswordConstraintBase`. Each constraint plugin:

- Annotates itself with `#[PasswordConstraint]` (PHP 8 attribute) or the older `@PasswordConstraint` docblock annotation (for Drupal 10 backward compat).
- Declares `id`, `label`, and `description` in the attribute/annotation.
- Implements `validate(string $password, PasswordPolicyEntity $policy): PasswordPolicyResult`.
- Optionally implements `buildConfigurationForm()` and `submitConfigurationForm()` if per-policy UI configuration is needed.
- The plugin is discovered in `src/Plugin/PasswordConstraint/`.

The `PasswordPolicyResult` object has `setErrorMessage(string $message)` and `isValid(): bool`. A result with no error message set is considered passing.

### Services Definition (`hibp_password_guard.services.yml`)

```yaml
services:
  hibp_password_guard.hibp_client:
    class: Drupal\hibp_password_guard\HibpClient
    arguments:
      - '@http_client'
      - '@config.factory'
      - '@cache.hibp_password_guard'
      - '@logger.factory'

  cache.hibp_password_guard:
    class: Drupal\Core\Cache\CacheBackendInterface
    tags:
      - { name: cache.bin }
    factory: cache_factory:get
    arguments: [hibp_password_guard]
```

### Plugin Constructor Dependency Injection

Because `PasswordConstraintBase` extends `PluginBase`, dependency injection is done via `create()` static factory method:

```php
public static function create(
    ContainerInterface $container,
    array $configuration,
    $plugin_id,
    $plugin_definition
): static {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->hibpClient = $container->get('hibp_password_guard.hibp_client');
    return $instance;
}
```

### Hook Implementations (`hibp_password_guard.module`)

- `hook_help()`: provides a brief description on the module help page.

### Hook Requirements (`hibp_password_guard.install`)

```php
function hibp_password_guard_requirements(string $phase): array {
    $requirements = [];
    if ($phase === 'runtime') {
        // Probe HIBP API with innocuous prefix '00000'.
        // Cache probe result in cache.default for 300 seconds.
        // Set severity based on HTTP response.
    }
    return $requirements;
}
```

### Drush Command Location

Drush 12+ discovers commandfiles in `src/Drush/Commands/`. The class must use `\Drush\Commands\AutowireTrait` or declare a static `create()` factory. No `drush.services.yml` is required for Drush 12 autowired commands.

### Routing and Menu

The admin settings form is registered in `hibp_password_guard.routing.yml` under `hibp_password_guard.settings` route, protected by `_permission: 'administer hibp password guard'`. A menu link is added under `admin/config/security` via `hibp_password_guard.links.menu.yml`.

### Config Install Defaults (`config/install/hibp_password_guard.settings.yml`)

```yaml
enabled: true
cache_ttl: 86400
fail_mode: fail_open
http_timeout: 5
api_base_url: 'https://api.pwnedpasswords.com'
```

### Config Schema (`config/schema/hibp_password_guard.schema.yml`)

```yaml
hibp_password_guard.settings:
  type: config_object
  label: 'HIBP Password Guard settings'
  mapping:
    enabled:
      type: boolean
      label: 'Module enabled'
    cache_ttl:
      type: integer
      label: 'Cache TTL (seconds)'
    fail_mode:
      type: string
      label: 'Degradation mode (fail_open or fail_closed)'
    http_timeout:
      type: integer
      label: 'HTTP request timeout (seconds)'
    api_base_url:
      type: string
      label: 'HIBP API base URL'
```

### Drupal 11 Compatibility Notes

- Requires Drupal `^11.0`.
- Requires PHP `^8.1` (for named arguments and intersection types).
- Requires `drupal/password_policy:^4.0`.
- All deprecated Drupal 9/10 APIs (`\Drupal::service()` in plugin constructors, `t()` in non-procedural code without `StringTranslationTrait`) are avoided.
- Translatable strings use `$this->t()` from `StringTranslationTrait` or the `TranslatableMarkup` constructor.
- The module declares `package: Security` and `configure: hibp_password_guard.settings` in its `.info.yml`.

---

## Configuration Options

| Setting | Config Key | Type | Default | Description |
|---|---|---|---|---|
| Module enabled | `enabled` | boolean | `true` | Global on/off switch. When `false`, the constraint plugin always returns a passing result without making any HTTP call. |
| Cache TTL | `cache_ttl` | integer (seconds) | `86400` (24 h) | How long a successful HIBP API response is cached per 5-character prefix. Set to `0` to disable caching (not recommended for production). |
| Degradation mode | `fail_mode` | string enum | `fail_open` | `fail_open`: API unavailability allows the password. `fail_closed`: API unavailability blocks the password. |
| HTTP timeout | `http_timeout` | integer (seconds) | `5` | Maximum wall-clock time for a single HIBP API request (connect + read combined). |
| API base URL | `api_base_url` | string (URL) | `https://api.pwnedpasswords.com` | Base URL for the Pwned Passwords Range API. Override to use a local mirror, corporate proxy, or self-hosted instance. |

---

## Composer Dependencies

| Package | Version Constraint | Reason |
|---|---|---|
| `guzzlehttp/guzzle` | `^7.0` | HTTP client for HIBP API requests. Already a Drupal core dependency; no additional installation required. |
| `drupal/password_policy` | `^4.0` | Provides `PasswordConstraintBase`, `PasswordPolicyResult`, and the plugin discovery system this module extends. Listed as a Composer dependency and a Drupal module dependency in `.info.yml`. |

No additional PHP packages are required. SHA-1 hashing uses PHP's built-in `hash()` function. String parsing of the API response uses PHP standard library functions (`explode`, `strtoupper`, `strpos`).

**`composer.json` (module-level, for packaging on Drupal.org):**

```json
{
  "name": "drupal/hibp_password_guard",
  "type": "drupal-module",
  "require": {
    "drupal/password_policy": "^4.0",
    "guzzlehttp/guzzle": "^7.0"
  }
}
```

---

## Integration Points

### Password Policy Module (Required)
The primary integration. `hibp_password_guard` declares `password_policy` as a dependency in its `.info.yml`. The `NotPwnedPassword` plugin appears in the Password Policy constraint selection UI under any policy and can be added to one or more policies. Each policy instance of the plugin shares the global module configuration (TTL, fail mode, timeout) but can be independently enabled or disabled within a policy via the Password Policy module's policy edit form.

### Drupal Core Cache API
Uses `cache.hibp_password_guard` bin, a custom bin registered via the services file. Falls back to the default cache backend unless the site's `settings.php` overrides the `hibp_password_guard` bin specifically (e.g., to use Redis or Memcached for this bin independently).

### Drupal Core HTTP Client (`http_client`)
Uses the standard `http_client` Guzzle service, which respects any site-level middleware (e.g., `http_client_middleware` tagged services) such as request logging, proxy configuration set via `$settings['http_client_config']` in `settings.php`, and SSL certificate overrides. This means operators can route HIBP traffic through an outbound HTTP proxy by setting `$settings['http_client_config']['proxy']` in `settings.php` without modifying the module.

### Drupal Watchdog / Logging
Uses `logger.factory` to obtain a channel-specific logger (`hibp_password_guard`). Log entries are visible in `admin/reports/dblog` (when `dblog` is enabled) and forwarded to any configured logging backends (syslog, external log aggregators).

### Drupal Status Report (`admin/reports/status`)
The `hook_requirements()` implementation in `hibp_password_guard.install` adds a row to the Status Report showing HIBP API reachability. This integrates with monitoring tools that parse the Drupal Status Report (e.g., Nagios plugins that check for `REQUIREMENT_ERROR` rows).

### Drush 12+
The `hibp:check-user` command integrates with any Drush 12-compatible Drupal installation. It respects the module's configuration (including the `api_base_url` override) and uses the same `HibpClient` service used by the constraint plugin, ensuring consistent behaviour between the Drush check and the live form validation.

### Potential Future Integrations
- **Password Reset Flow**: A future sub-module or hook implementation could block the use of a pwned password during the core `user_pass_rehash` / password reset form flow, independent of the Password Policy module, broadening coverage to sites that do not use Password Policy.
- **User Bulk Audit**: A future Drush command `hibp:audit-users` could iterate all user accounts and report which accounts have stored hashes that appear in breach data (requires Drupal's password hashing to be SHA-1-based, or requires the operator to supply plaintext passwords, which is not feasible at scale — this feature is therefore limited in scope).
- **Rate Limiting**: If the site has very high user account creation volume, a leaky-bucket rate limiter (using Drupal's `flood` service or a custom service) could be added to the `HibpClient` to avoid exceeding HIBP's recommended request rate.

---

## Appendix: HIBP Range API Reference

- **Endpoint**: `GET https://api.pwnedpasswords.com/range/{prefix}`
- **Prefix**: 5 uppercase hexadecimal characters (first 5 chars of SHA-1 hash).
- **Request header**: `Add-Padding: true` (recommended; pads response to a consistent size to mitigate traffic analysis).
- **Response**: HTTP 200, `Content-Type: text/plain`. Body is a list of lines, each `SUFFIX:COUNT` (CRLF-delimited). SUFFIX is 35 uppercase hex characters. COUNT is the number of times the full hash (`prefix + suffix`) appears in the HIBP breach corpus. Padded entries have COUNT of 0.
- **No API key required** for the Pwned Passwords Range endpoint.
- **Rate limiting**: HIBP recommends reasonable use. The module's caching strategy (default 24-hour TTL per prefix) significantly reduces outbound request volume.
- **CDN-backed**: The API is served via Cloudflare, providing high availability and global low latency.
