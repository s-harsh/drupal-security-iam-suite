# HIBP Password Guard — Architecture

## Module Structure

```
hibp_password_guard/
├── hibp_password_guard.info.yml                  # Module metadata, dependencies, configure route
├── hibp_password_guard.install                   # hook_requirements() OOP delegation via HibpPasswordGuardHooks
├── hibp_password_guard.module                    # hook_help() OOP delegation via HibpPasswordGuardHooks (minimal stub)
├── hibp_password_guard.permissions.yml           # 'administer hibp password guard' permission declaration
├── hibp_password_guard.routing.yml               # Admin settings form route
├── hibp_password_guard.services.yml              # Service container definitions, cache bin, hook tag
├── hibp_password_guard.links.menu.yml            # Admin menu link under admin/config/security
├── composer.json                                 # Module-level composer metadata and require declarations
├── config/
│   ├── install/
│   │   └── hibp_password_guard.settings.yml      # Default config values shipped with the module
│   └── schema/
│       └── hibp_password_guard.schema.yml        # Config schema for hibp_password_guard.settings
└── src/
    ├── Hook/
    │   └── HibpPasswordGuardHooks.php            # OOP hook implementations (hook_help, hook_requirements)
    ├── Service/
    │   ├── HibpApiClient.php                     # Low-level HTTP wrapper around Guzzle http_client
    │   └── HibpPasswordCheckerService.php        # Orchestrates hash computation, cache lookup, API call, result parsing
    ├── Plugin/
    │   └── PasswordConstraint/
    │       └── HibpCompromised.php               # PasswordConstraint plugin; delegates to HibpPasswordCheckerService
    ├── Form/
    │   └── HibpPasswordGuardSettingsForm.php     # ConfigFormBase admin settings form
    └── Drush/
        └── Commands/
            └── HibpCommands.php                  # Drush 12 command hibp:check-user (AutowireTrait DI)
```

### File-by-File Responsibilities

| File | Responsibility |
|---|---|
| `hibp_password_guard.info.yml` | Declares module name, type, description, `core_version_requirement: ^11 \|\| ^10.4`, `package: Security`, dependencies (`password_policy`), and `configure: hibp_password_guard.settings`. |
| `hibp_password_guard.install` | Contains no procedural logic. Calls `\Drupal::service('hibp_password_guard.hooks')->requirements($phase)` to delegate `hook_requirements` to the OOP class while preserving the `.install` file contract Drupal expects. |
| `hibp_password_guard.module` | Contains no procedural logic beyond `hook_help` delegation. Calls `\Drupal::service('hibp_password_guard.hooks')->help($route_name, $route_match)`. |
| `hibp_password_guard.permissions.yml` | Declares `administer hibp password guard` permission with `restrict access: true`. |
| `hibp_password_guard.routing.yml` | Route `hibp_password_guard.settings` at `admin/config/security/hibp-password-guard`, `_form: HibpPasswordGuardSettingsForm`, `_permission: administer hibp password guard`, `_admin_route: true`. |
| `hibp_password_guard.services.yml` | Defines all services: `hibp_password_guard.api_client`, `hibp_password_guard.checker`, `hibp_password_guard.hooks`, `cache.hibp_password_guard` bin, and `logger.channel.hibp_password_guard`. |
| `hibp_password_guard.links.menu.yml` | Menu link `hibp_password_guard.settings` placed under `system.admin_config_security`, weight 10. |
| `composer.json` | `name: drupal/hibp_password_guard`, `type: drupal-module`, `license: GPL-2.0-or-later`, requires `drupal/core: ^11 \|\| ^10.4`, `drupal/password_policy: ^4.0`, `guzzlehttp/guzzle: ^7.0`. PSR-4 autoload maps `Drupal\hibp_password_guard\` to `src/`. |
| `config/install/hibp_password_guard.settings.yml` | Ships default values: `enabled: true`, `cache_ttl: 86400`, `fail_mode: fail_open`, `http_timeout: 5`, `api_base_url: https://api.pwnedpasswords.com`. |
| `config/schema/hibp_password_guard.schema.yml` | `config_object` schema mapping all five settings keys with types `boolean`, `integer`, `string`. |
| `src/Hook/HibpPasswordGuardHooks.php` | OOP hook class tagged `drupal.hook`. Implements `#[Hook('requirements')]` and `#[Hook('help')]`. Receives `HibpApiClient` via constructor DI to probe the API in `requirements()`. |
| `src/Service/HibpApiClient.php` | Wraps injected `http_client` (Guzzle). Constructs GET request to `{api_base_url}/range/{PREFIX}` with `Add-Padding: true` header. Enforces configurable timeout. Catches `GuzzleException` variants and returns a typed result object. Never logs passwords or full hashes. |
| `src/Service/HibpPasswordCheckerService.php` | Computes `hash('sha1', $password)`, extracts prefix/suffix, checks `cache.hibp_password_guard`, calls `HibpApiClient` on miss, parses `SUFFIX:COUNT` lines, returns `HibpCheckResult` value object. Handles fail-open/fail-closed logic. |
| `src/Plugin/PasswordConstraint/HibpCompromised.php` | `#[PasswordConstraint]` plugin. `validate()` delegates to `HibpPasswordCheckerService`. Returns `PasswordPolicyResult` with error message on breach. Uses `ContainerFactory`/`create()` for DI. |
| `src/Form/HibpPasswordGuardSettingsForm.php` | `ConfigFormBase`. Renders five settings fields in a `details` element. `submitForm()` persists values to `hibp_password_guard.settings`. Provides admin feedback via `MessengerInterface`. |
| `src/Drush/Commands/HibpCommands.php` | Drush 12 commandfile. `#[CLI\Command('hibp:check-user')]`. `AutowireTrait` injects `HibpPasswordCheckerService` and `entity_type.manager`. Supports `--plaintext` and `--bypass-cache` options. |

---

## Service Definitions

### `hibp_password_guard.api_client`

| Property | Value |
|---|---|
| Class | `Drupal\hibp_password_guard\Service\HibpApiClient` |
| Constructor args | `@http_client`, `@config.factory`, `@logger.channel.hibp_password_guard` |
| Responsibility | Executes the single GET request to `https://api.pwnedpasswords.com/range/{PREFIX}`. Adds the `Add-Padding: true` header. Reads `http_timeout` and `api_base_url` from config. Catches `GuzzleHttp\Exception\TransferException` subclasses. Returns a typed `HibpRangeResponse` value object (raw suffix-list string on success, error flag on failure). Never logs request parameters alongside user identifiers. |

```yaml
hibp_password_guard.api_client:
  class: Drupal\hibp_password_guard\Service\HibpApiClient
  arguments:
    - '@http_client'
    - '@config.factory'
    - '@logger.channel.hibp_password_guard'
```

### `hibp_password_guard.checker`

| Property | Value |
|---|---|
| Class | `Drupal\hibp_password_guard\Service\HibpPasswordCheckerService` |
| Constructor args | `@hibp_password_guard.api_client`, `@cache.hibp_password_guard`, `@config.factory`, `@logger.channel.hibp_password_guard` |
| Responsibility | Orchestrates the full check pipeline: SHA-1 hash computation, prefix/suffix split, cache read, optional API call via `HibpApiClient`, SUFFIX:COUNT line parsing, suffix match (case-insensitive), and degradation-mode decision. Returns a `HibpCheckResult` value object. Supports a `bypassCache` flag for Drush use. |

```yaml
hibp_password_guard.checker:
  class: Drupal\hibp_password_guard\Service\HibpPasswordCheckerService
  arguments:
    - '@hibp_password_guard.api_client'
    - '@cache.hibp_password_guard'
    - '@config.factory'
    - '@logger.channel.hibp_password_guard'
```

### `hibp_password_guard.hooks`

| Property | Value |
|---|---|
| Class | `Drupal\hibp_password_guard\Hook\HibpPasswordGuardHooks` |
| Constructor args | `@hibp_password_guard.api_client`, `@config.factory` |
| Responsibility | Implements `hook_requirements` (probes API with prefix `00000`, returns `REQUIREMENT_OK/WARNING/ERROR`) and `hook_help` (returns module description markup). Tagged `drupal.hook` so Drupal's hook system discovers the `#[Hook]` attributes at compile time. |
| Tags | `{name: drupal.hook}` |

```yaml
hibp_password_guard.hooks:
  class: Drupal\hibp_password_guard\Hook\HibpPasswordGuardHooks
  arguments:
    - '@hibp_password_guard.api_client'
    - '@config.factory'
  tags:
    - { name: drupal.hook }
```

### `cache.hibp_password_guard`

| Property | Value |
|---|---|
| Interface | `Drupal\Core\Cache\CacheBackendInterface` |
| Factory | `cache_factory:get` with argument `hibp_password_guard` |
| Responsibility | Dedicated cache bin for storing HIBP range API responses keyed by `hibp_range:{PREFIX}`. Backed by whatever `$settings['cache']['bins']['hibp_password_guard']` resolves to in `settings.php` (defaults to the site's default cache backend). TTL sourced from `hibp_password_guard.settings:cache_ttl` at write time. |
| Tags | `{name: cache.bin}` |

```yaml
cache.hibp_password_guard:
  class: Drupal\Core\Cache\CacheBackendInterface
  tags:
    - { name: cache.bin }
  factory: cache_factory:get
  arguments: [hibp_password_guard]
```

### `logger.channel.hibp_password_guard`

| Property | Value |
|---|---|
| Parent | `logger.channel_base` |
| Constructor args | `hibp_password_guard` (channel name string) |
| Responsibility | Named log channel for all watchdog entries emitted by the module. Visible under the `hibp_password_guard` channel in `admin/reports/dblog`. |

```yaml
logger.channel.hibp_password_guard:
  parent: logger.channel_base
  arguments: ['hibp_password_guard']
```

---

## Plugin System

### Plugin Type: `PasswordConstraint`

Provided by the `drupal/password_policy` module (^4.x). Plugin discovery path: `src/Plugin/PasswordConstraint/` within any module that declares `password_policy` as a dependency.

Base class: `Drupal\password_policy\Plugin\PasswordConstraint\PasswordConstraintBase`

Interface: `Drupal\password_policy\Plugin\PasswordConstraint\PasswordConstraintInterface`

Key interface methods:

| Method | Signature | Purpose |
|---|---|---|
| `validate` | `validate(string $password, PasswordPolicyEntity $policy): PasswordPolicyResult` | Core validation logic; returns a result with optional error message. |
| `buildConfigurationForm` | `buildConfigurationForm(array $form, FormStateInterface $form_state): array` | Per-instance configuration within a policy. Optional. |
| `submitConfigurationForm` | `submitConfigurationForm(array &$form, FormStateInterface $form_state): void` | Persists per-instance config. Optional. |
| `getSummary` | `getSummary(): string` | Human-readable one-line summary shown in the policy admin UI. |

### Concrete Plugin: `HibpCompromised`

| Property | Value |
|---|---|
| Class | `Drupal\hibp_password_guard\Plugin\PasswordConstraint\HibpCompromised` |
| Plugin ID | `hibp_compromised` |
| File | `src/Plugin/PasswordConstraint/HibpCompromised.php` |
| Attribute | `#[PasswordConstraint(id: 'hibp_compromised', label: new TranslatableMarkup('Not Pwned Password'), description: new TranslatableMarkup('Rejects passwords found in the Have I Been Pwned breach database using k-anonymity.'))]` |
| Extends | `PasswordConstraintBase` |
| Injected service | `hibp_password_guard.checker` (via `create()` static factory) |

Validation flow inside `validate()`:

1. Check if module is globally enabled via config; return passing result if disabled.
2. Call `HibpPasswordCheckerService::check(string $password, bool $bypassCache = false)`.
3. If result indicates `isPwned === true`: call `$result->setErrorMessage($this->t('This password has appeared in a data breach. Please choose a different password.'))`.
4. If result indicates API failure: apply fail_open (pass) or fail_closed (block with degradation message) based on config.
5. Return `PasswordPolicyResult`.

`getSummary()` returns: `"Password must not appear in the Have I Been Pwned breach database."`.

No per-plugin configuration form is implemented in v1.0; all settings are global via the admin settings form.

---

## Database Schema

HIBP Password Guard creates **no custom database tables**. All persistent state is handled through:

- **Drupal Config API** (`hibp_password_guard.settings` config object) for module settings.
- **Drupal Cache API** (`cache.hibp_password_guard` bin, backed by the site's configured cache backend) for HIBP range API responses.

The cache bin storage is managed entirely by Drupal's cache backend infrastructure (database `cache_hibp_password_guard` table when using DatabaseBackend, or equivalent in Redis/Memcached). No schema declaration in `hook_schema()` is required for cache bins — they are created automatically by the cache factory.

There is no `hook_schema()` implementation in `hibp_password_guard.install`.

---

## Config Schema

### `hibp_password_guard.settings`

File: `config/schema/hibp_password_guard.schema.yml`

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
      label: 'Cache TTL in seconds'
    fail_mode:
      type: string
      label: 'Degradation mode'
    http_timeout:
      type: integer
      label: 'HTTP request timeout in seconds'
    api_base_url:
      type: string
      label: 'HIBP API base URL'
```

### Config Install Defaults

File: `config/install/hibp_password_guard.settings.yml`

```yaml
enabled: true
cache_ttl: 86400
fail_mode: fail_open
http_timeout: 5
api_base_url: 'https://api.pwnedpasswords.com'
```

### Config Key Reference

| Key | Type | Default | Allowed Values / Range | Description |
|---|---|---|---|---|
| `enabled` | boolean | `true` | `true` / `false` | Global on/off. When `false`, the constraint plugin always passes without any HTTP call. |
| `cache_ttl` | integer | `86400` | `0` – `2147483647` | Seconds to cache a range API response per 5-character prefix. `0` disables caching (not recommended). |
| `fail_mode` | string | `fail_open` | `fail_open` / `fail_closed` | Behaviour when HIBP API is unreachable: accept (`fail_open`) or reject (`fail_closed`) the candidate password. |
| `http_timeout` | integer | `5` | `1` – `30` | Wall-clock seconds for Guzzle connect + read timeout on each range API request. |
| `api_base_url` | string | `https://api.pwnedpasswords.com` | Valid HTTPS URL | Base URL for the Pwned Passwords Range API. Override for proxies or self-hosted mirrors. |

---

## Routes

### `hibp_password_guard.settings`

File: `hibp_password_guard.routing.yml`

```yaml
hibp_password_guard.settings:
  path: '/admin/config/security/hibp-password-guard'
  defaults:
    _form: '\Drupal\hibp_password_guard\Form\HibpPasswordGuardSettingsForm'
    _title: 'HIBP Password Guard Settings'
  requirements:
    _permission: 'administer hibp password guard'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Path | `/admin/config/security/hibp-password-guard` |
| Handler | `HibpPasswordGuardSettingsForm` (ConfigFormBase) |
| HTTP method | GET (render form), POST (submit form — handled by FormAPI) |
| Access | `administer hibp password guard` permission |
| Theme | Claro admin theme (via `_admin_route: true`) |

### Menu Link

File: `hibp_password_guard.links.menu.yml`

```yaml
hibp_password_guard.settings:
  title: 'HIBP Password Guard'
  description: 'Configure HIBP Pwned Passwords breach checking.'
  route_name: hibp_password_guard.settings
  parent: system.admin_config_security
  weight: 10
```

No API routes are defined. All API interaction is outbound (server-to-HIBP); there are no inbound REST or JSON:API endpoints.

---

## Hook Implementations

All hooks follow Drupal 11's OOP `#[Hook]` attribute pattern. The procedural stubs in `.install` and `.module` contain only a single delegating line each.

### `hook_requirements` — `HibpPasswordGuardHooks::requirements()`

File: `src/Hook/HibpPasswordGuardHooks.php`

```php
#[Hook('requirements')]
public function requirements(string $phase): array
```

Triggered by: `hibp_password_guard.install` stub during Drupal's status report and install-time checks.

Behaviour (phase `runtime`):

1. Attempt to retrieve a cached probe result from `cache.default` under key `hibp_password_guard.requirements_probe`.
2. On cache miss: call `HibpApiClient::fetchRange('00000')` with a short 5-second timeout.
3. Map result to requirement severity:
   - HTTP 200 → `REQUIREMENT_OK`, title "HIBP API reachable".
   - HTTP non-200 / timeout → `REQUIREMENT_WARNING`, title "HIBP API returned unexpected status".
   - `ConnectException` / DNS failure → `REQUIREMENT_ERROR`, title "HIBP API unreachable".
4. Cache the severity result in `cache.default` for 300 seconds (5 minutes) to avoid API hammering on repeated Status Report loads.
5. Return the `$requirements['hibp_password_guard']` array.

Returned array structure:

```php
[
  'hibp_password_guard' => [
    'title'       => 'HIBP Pwned Passwords API',
    'value'       => 'Reachable' | 'Warning: ...' | 'Error: ...',
    'description' => TranslatableMarkup,
    'severity'    => REQUIREMENT_OK | REQUIREMENT_WARNING | REQUIREMENT_ERROR,
  ],
]
```

Phase `install`: returns an empty array (no install-time checks required beyond Drupal's standard dependency resolution).

### `hook_help` — `HibpPasswordGuardHooks::help()`

File: `src/Hook/HibpPasswordGuardHooks.php`

```php
#[Hook('help')]
public function help(string $route_name, RouteMatchInterface $route_match): string|array
```

Triggered by: `hibp_password_guard.module` stub on `hook_help` invocations.

Behaviour: When `$route_name === 'help.page.hibp_password_guard'`, returns a render array containing:
- A brief description of what the module does.
- A link to the admin settings form.
- A link to the HIBP Pwned Passwords documentation.

Returns an empty string for all other route names.

---

## Event Subscribers

HIBP Password Guard does not implement any Symfony event subscribers in v1.0.

The password validation integration is handled entirely through the Password Policy module's plugin system (synchronous constraint evaluation during form submission). No asynchronous event-driven processing is required.

Potential future event subscribers (not in v1.0 scope):

| Event | Potential Use |
|---|---|
| `KernelEvents::REQUEST` | Could detect password reset routes and inject constraint checks outside of Password Policy. |
| `\Drupal\user\Event\UserFloodEvent` | Could integrate flood control if high-volume abuse is detected. |

---

## Entity Definitions

HIBP Password Guard defines **no custom entity types** in v1.0.

The module interacts with two existing entity types:

| Entity | Interaction |
|---|---|
| `user` | Read-only: the Drush command `hibp:check-user` loads `UserInterface` entities by name via `entity_type.manager` to access the stored password hash field for hash-based checks (with the caveat that PHPass hashes cannot be directly SHA-1-compared). |
| `password_policy` | Passive: the `HibpCompromised` constraint plugin is added to `PasswordPolicyEntity` instances via the Password Policy module's admin UI. The module reads but never writes `PasswordPolicyEntity`. |

---

## External API Integrations

### HIBP Pwned Passwords Range API

| Property | Value |
|---|---|
| Provider | Have I Been Pwned Foundation (operated by Troy Hunt) |
| Endpoint | `GET https://api.pwnedpasswords.com/range/{PREFIX}` |
| Authentication | None required. The endpoint is freely available without an API key. |
| TLS | Required. Guzzle enforces certificate verification by default; this must not be disabled. |
| Request headers | `Add-Padding: true` (mitigates traffic-analysis attacks by padding all responses to a uniform size) |
| Path parameter | `{PREFIX}` — 5 uppercase hexadecimal characters (first 5 chars of the SHA-1 hash of the candidate password) |
| Response format | HTTP 200, `Content-Type: text/plain; charset=utf-8`. Body: CRLF-delimited lines, each `SUFFIX:COUNT`. SUFFIX is 35 uppercase hex characters. COUNT is an integer breach occurrence count. Padding lines have `COUNT` of `0`. |
| Error responses | 400 (malformed prefix), 429 (rate limited), 5xx (server error). All non-200 responses trigger the configured `fail_mode` behaviour. |
| Rate limits | No hard rate limit published for the Range API; HIBP recommends respectful use. The module's 24-hour cache TTL per prefix keeps request volume proportional to the number of distinct password prefixes tested, not the number of users. |
| CDN | Served via Cloudflare. Typical global latency under 100 ms. |
| Privacy guarantee | K-anonymity: the 5-character prefix is shared by an average of ~10,000 distinct hashes across the ~10 billion entries in the HIBP dataset, making it computationally infeasible to reverse the query to a specific password. |

#### Request Construction (pseudo-code)

```php
$hash   = strtoupper(hash('sha1', $password));   // 40-char hex string, entirely in-process
$prefix = substr($hash, 0, 5);                   // First 5 chars placed on the wire
$suffix = substr($hash, 5);                      // Remaining 35 chars — never leaves the server

$response = $httpClient->get(
    $config->get('api_base_url') . '/range/' . $prefix,
    [
        'headers' => ['Add-Padding' => 'true'],
        'timeout' => $config->get('http_timeout'),
        'connect_timeout' => $config->get('http_timeout'),
    ]
);
```

#### Response Parsing (pseudo-code)

```php
$lines = explode("\r\n", $response->getBody()->getContents());
foreach ($lines as $line) {
    [$responseSuffix, $count] = explode(':', $line, 2);
    if ((int) $count === 0) continue;             // Discard padding entries
    if (strcasecmp($responseSuffix, $suffix) === 0) {
        // Password found in breach database with $count occurrences
        return new HibpCheckResult(isPwned: true, breachCount: (int) $count);
    }
}
return new HibpCheckResult(isPwned: false, breachCount: 0);
```

#### Cache Integration

```
Cache key:   hibp_range:{PREFIX}           (e.g., hibp_range:A94A8)
Cache value: Raw response body string      (CRLF-delimited SUFFIX:COUNT lines)
Cache TTL:   hibp_password_guard.settings:cache_ttl  (default 86400 seconds)
Cache bin:   cache.hibp_password_guard
```

On cache hit, the stored response body is parsed in-process. No outbound HTTP request is made.
On cache miss after a successful API call, the response body is written to the cache before returning.
On API failure, nothing is written to the cache (no negative caching of errors in v1.0).

---

## Security Design

### Access Control

| Resource | Protection Mechanism |
|---|---|
| Admin settings form at `admin/config/security/hibp-password-guard` | Drupal route requirement `_permission: administer hibp password guard`; permission declared with `restrict access: true` |
| `PasswordConstraint` plugin execution | Runs within Password Policy module's constraint evaluation, which is invoked only during Drupal's user account edit/register form submission. Protected by existing Drupal user account access control (`user.edit` access check on the user entity). |
| Drush `hibp:check-user` command | Drush commands are CLI-only and require shell access to the server. No additional permission check is needed beyond OS-level access control. The command is non-destructive (read-only). |
| Cache bin `cache.hibp_password_guard` | Accessible only to server-side PHP code. Cache keys contain only a 5-character hex prefix; no user identifiers are embedded in cache keys. |

### Input Validation

| Input | Validation |
|---|---|
| `admin/config/security/hibp-password-guard` form fields | `cache_ttl` and `http_timeout` validated as positive integers via `#[Element: integerfield]` and custom `validateForm()` checks. `fail_mode` validated against allowed enum values `fail_open` / `fail_closed`. `api_base_url` validated as a well-formed URL via `UrlHelper::isValid($url, TRUE)`. |
| `{PREFIX}` path parameter to HIBP API | Constructed entirely from `strtoupper(substr(hash('sha1', $password), 0, 5))` — guaranteed to be exactly 5 uppercase hex characters. No user-supplied data reaches the API URL without this transformation. |
| Drush `--plaintext` option | Treated as a raw string and passed directly to the SHA-1 computation. Not logged. |
| Drush `username` argument | Looked up via `entity_type.manager->getStorage('user')->loadByProperties(['name' => $username])`. No SQL string concatenation. |

### Output Encoding

| Output location | Encoding approach |
|---|---|
| Constraint violation message in password form | `$this->t('This password has appeared in a data breach...')` — `TranslatableMarkup` which is auto-escaped by the Twig render pipeline. |
| Admin settings form labels and descriptions | All use `$this->t()` or `#title`/`#description` form API keys, which Twig escapes automatically. |
| `hook_help` output | Returned as a `render array` with `#markup` using `Markup::create($this->t(...))` — explicit safe markup wrapper. |
| Status report `hook_requirements` value/description | All values constructed via `$this->t()` and returned as `TranslatableMarkup`; no raw user input is reflected. |
| Watchdog/log entries | Composed only of module-internal strings, HTTP status codes (integers), and exception class names. Never include passwords, full hashes, or prefixes associated with user identifiers. |
| Drush command output | Uses `$this->io()->success()` / `$this->io()->warning()` / `$this->io()->error()` with controlled string arguments. |

### Sensitive Data Handling

| Data item | Handling |
|---|---|
| Plaintext password | Exists only in PHP call-stack memory during validation. Never passed to any logging facility, never stored anywhere, never included in exception messages. The `HibpPasswordCheckerService::check()` method signature accepts a `string $password` parameter that is used only to compute the SHA-1 hash before being released to GC. |
| Full 40-character SHA-1 hash | Computed in-process. Only the 5-character prefix leaves the PHP process (via HTTP to HIBP). The suffix is compared in-memory against API response data. Never logged, never cached with a user identifier. |
| 5-character prefix | Placed on the wire to HIBP over HTTPS. Stored as part of the cache key `hibp_range:{PREFIX}`. Acceptable: the prefix reveals membership in a set of ~10,000 distinct hashes and cannot be associated with a specific user without additional context. |
| Cache keys | `hibp_range:{PREFIX}` — no user identifier, no timestamp, purely the prefix. Safe to store in any Drupal cache backend. |

### TLS and Transport Security

- All requests to the HIBP API use HTTPS. Guzzle's `verify` option defaults to `true` (system CA bundle). This setting is **not** exposed in the admin UI to prevent operators from accidentally disabling certificate verification.
- Operators who override `api_base_url` to a custom endpoint are responsible for TLS on that endpoint. The module does not disable verification for custom URLs.
- Proxy support is inherited from Drupal's `$settings['http_client_config']` in `settings.php` (Guzzle's handler stack picks this up automatically).

### No Authentication Credentials

The HIBP Pwned Passwords Range API requires no API key or authentication token. The module stores no credentials. There is no credential management surface.

### Dependency Risk

`guzzlehttp/guzzle` is a Drupal core dependency (shipped in `composer.lock` for every Drupal 11 site). No additional PHP packages are introduced by this module, minimising supply-chain attack surface. SHA-1 hashing uses PHP's built-in `hash()` — no third-party cryptography library.

---

## Test Strategy

### Unit Tests

Location: `tests/src/Unit/`
Namespace: `Drupal\Tests\hibp_password_guard\Unit\`
Base class: `Drupal\Tests\UnitTestCase`
Framework: PHPUnit 10+

| Test class | File | What it tests |
|---|---|---|
| `HibpApiClientTest` | `tests/src/Unit/Service/HibpApiClientTest.php` | Constructs `HibpApiClient` with a mock Guzzle client. Asserts correct URL construction (`{api_base_url}/range/{PREFIX}`). Asserts `Add-Padding: true` header is present. Asserts timeout option is read from config. Asserts that `GuzzleException` is caught and does not propagate (returns error result). Asserts that log entries on failure do not contain password or hash data. |
| `HibpPasswordCheckerServiceTest` | `tests/src/Unit/Service/HibpPasswordCheckerServiceTest.php` | Mocks `HibpApiClient` and cache backend. Asserts correct SHA-1 prefix/suffix split for known test vectors. Asserts that cache hit skips API call. Asserts that successful API response with matching suffix returns `isPwned: true`. Asserts that API response without matching suffix returns `isPwned: false`. Asserts that padding entries (COUNT=0) are discarded. Asserts `fail_open` returns non-pwned result on API error. Asserts `fail_closed` returns pwned result on API error. Asserts `bypassCache: true` skips cache read and forces API call. |
| `HibpCompromisedPluginTest` | `tests/src/Unit/Plugin/PasswordConstraint/HibpCompromisedTest.php` | Mocks `HibpPasswordCheckerService`. Asserts that `validate()` returns a passing `PasswordPolicyResult` for a non-pwned password. Asserts that `validate()` returns a failing `PasswordPolicyResult` with a non-empty error message for a pwned password. Asserts that `validate()` returns passing when module `enabled` config is `false`. Asserts `getSummary()` returns a non-empty string. |
| `HibpPasswordGuardHooksTest` | `tests/src/Unit/Hook/HibpPasswordGuardHooksTest.php` | Mocks `HibpApiClient`. Asserts `requirements()` returns `REQUIREMENT_OK` when API responds HTTP 200. Asserts `requirements()` returns `REQUIREMENT_WARNING` on non-200. Asserts `requirements()` returns `REQUIREMENT_ERROR` on `ConnectException`. Asserts probe uses prefix `00000`. |

Test vectors for SHA-1 / HIBP:

- Password `"password"` → SHA-1 `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8` → prefix `5BAA6`, suffix `1E4C9B93F3F0682250B6CF8331B7EE68FD8`. This is a well-known pwned password with millions of occurrences and is safe to use as a test vector.
- A UUID-like random string unlikely to appear in any breach corpus, used to test the non-pwned path.

### Functional Tests (BrowserTestBase)

Location: `tests/src/Functional/`
Namespace: `Drupal\Tests\hibp_password_guard\Functional\`
Base class: `Drupal\Tests\BrowserTestBase`

| Test class | File | What it tests |
|---|---|---|
| `HibpSettingsFormTest` | `tests/src/Functional/Form/HibpSettingsFormTest.php` | Creates a user with `administer hibp password guard` permission. Visits `admin/config/security/hibp-password-guard`. Asserts all five form fields are present. Submits valid values and asserts config is saved. Submits invalid values (negative TTL, bad URL) and asserts validation errors appear. Verifies that a user without the permission receives a 403 response. |
| `HibpConstraintIntegrationTest` | `tests/src/Functional/Plugin/PasswordConstraint/HibpConstraintIntegrationTest.php` | Installs `password_policy` and `hibp_password_guard`. Creates a policy with the `hibp_compromised` constraint and assigns it to authenticated users. Uses a mock HTTP client (via `http_client_middleware` test service override) to return a controlled HIBP-style response containing the SHA-1 suffix of `"password"`. Attempts to set password `"password"` via the user edit form and asserts the form validation error is displayed. Attempts to set a non-pwned password and asserts the save succeeds. Verifies fail-open behaviour by configuring the mock client to throw a `ConnectException` and asserting the password save succeeds. Verifies fail-closed behaviour under the same error condition. |
| `HibpStatusReportTest` | `tests/src/Functional/Hook/HibpStatusReportTest.php` | Visits `admin/reports/status` as an administrator. Asserts the "HIBP Pwned Passwords API" row is present. With a mock HTTP client returning 200, asserts the row shows OK status. With a mock client throwing `ConnectException`, asserts the row shows ERROR status. |

### Drush Command Tests

Location: `tests/src/Functional/Drush/`

| Test class | What it tests |
|---|---|
| `HibpCommandsTest` | Uses `Drush\TestTraits\DrushTestTrait`. Asserts `hibp:check-user` with `--plaintext=password` outputs a WARNING-level result (pwned). Asserts command with a non-pwned plaintext outputs OK. Asserts `--bypass-cache` forces an API call (mock verifies HTTP call count). Asserts that a non-existent username produces an appropriate error message. |

### Playwright / End-to-End Tests

Location: `playwright/` (project-level, not inside the module)

| Test file | What it tests |
|---|---|
| `hibp-settings-form.spec.ts` | Navigates to `/admin/config/security/hibp-password-guard`. Fills and submits the settings form. Asserts success message. Tests field-level validation for out-of-range values. |
| `hibp-password-constraint.spec.ts` | Creates a password policy with the HIBP constraint via admin UI. Navigates to the user edit form. Enters a known-pwned password (`"password"`) and asserts the constraint error appears. Enters a complex uncompromised password and asserts the save succeeds. |
| `hibp-status-report.spec.ts` | Navigates to `admin/reports/status`. Asserts the HIBP row is visible and displays a status value. |

### Test Coverage Goals

| Coverage area | Target |
|---|---|
| `HibpApiClient` (service) | 100% line coverage via unit tests with mock Guzzle |
| `HibpPasswordCheckerService` (service) | 100% branch coverage (cache hit/miss, pwned/not-pwned, fail_open/fail_closed) |
| `HibpCompromised` plugin | 100% branch coverage |
| `HibpPasswordGuardHooks` | All three severity outcomes covered |
| Settings form | All validation rules covered (functional) |
| End-to-end constraint enforcement | Full user flow (Playwright) |

---

## Appendix: Value Objects

To maintain type safety and avoid passing primitive booleans across service boundaries, the following internal value objects (not Drupal entities) are used:

### `HibpCheckResult`

```php
// src/Value/HibpCheckResult.php
final readonly class HibpCheckResult {
    public function __construct(
        public readonly bool $isPwned,
        public readonly int $breachCount,
        public readonly bool $apiError = false,
        public readonly string $errorType = '',
    ) {}
}
```

### `HibpRangeResponse`

```php
// src/Value/HibpRangeResponse.php
final readonly class HibpRangeResponse {
    public function __construct(
        public readonly bool $success,
        public readonly string $body = '',
        public readonly int $statusCode = 0,
        public readonly string $errorMessage = '',
    ) {}
}
```

These classes require no Drupal service registration. They are plain PHP objects used as typed return values by `HibpApiClient` and `HibpPasswordCheckerService`.

---

## Appendix: Full File Manifest

```
hibp_password_guard/
├── composer.json
├── hibp_password_guard.info.yml
├── hibp_password_guard.install
├── hibp_password_guard.links.menu.yml
├── hibp_password_guard.module
├── hibp_password_guard.permissions.yml
├── hibp_password_guard.routing.yml
├── hibp_password_guard.services.yml
├── config/
│   ├── install/
│   │   └── hibp_password_guard.settings.yml
│   └── schema/
│       └── hibp_password_guard.schema.yml
├── src/
│   ├── Hook/
│   │   └── HibpPasswordGuardHooks.php
│   ├── Form/
│   │   └── HibpPasswordGuardSettingsForm.php
│   ├── Plugin/
│   │   └── PasswordConstraint/
│   │       └── HibpCompromised.php
│   ├── Service/
│   │   ├── HibpApiClient.php
│   │   └── HibpPasswordCheckerService.php
│   ├── Value/
│   │   ├── HibpCheckResult.php
│   │   └── HibpRangeResponse.php
│   └── Drush/
│       └── Commands/
│           └── HibpCommands.php
└── tests/
    └── src/
        ├── Unit/
        │   ├── Hook/
        │   │   └── HibpPasswordGuardHooksTest.php
        │   ├── Plugin/
        │   │   └── PasswordConstraint/
        │   │       └── HibpCompromisedTest.php
        │   └── Service/
        │       ├── HibpApiClientTest.php
        │       └── HibpPasswordCheckerServiceTest.php
        └── Functional/
            ├── Drush/
            │   └── HibpCommandsTest.php
            ├── Form/
            │   └── HibpSettingsFormTest.php
            ├── Hook/
            │   └── HibpStatusReportTest.php
            └── Plugin/
                └── PasswordConstraint/
                    └── HibpConstraintIntegrationTest.php
```
