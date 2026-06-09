# API Flood Guard

## Description

API Flood Guard protects Drupal API authentication endpoints against
brute-force and credential-stuffing attacks. It intercepts incoming requests
on a configurable list of paths — including JSON:API, REST, GraphQL, and OAuth
token endpoints — and enforces independent per-IP and per-username flood
counters before routing, authentication, or page-cache processing occurs.

Key features:

- Per-IP flood control with configurable threshold and time window.
- Per-username flood control using SHA-256-hashed identifiers (username,
  client_id, or HTTP Basic credentials) so raw usernames are never stored.
- CIDR-based IP allowlist supporting IPv4, IPv6, and subnet notation.
- Optional IP reputation integration via a plugin system; ships with an
  AbuseIPDB v2 provider.
- Fail-open design: reputation provider errors never block legitimate traffic.
- Per-username flood counters are automatically cleared on a successful (HTTP
  200) authentication response, so valid users are never locked out after a
  single successful login.
- JSON:API-compatible error responses (`application/vnd.api+json`) returned
  when the client sends a matching `Accept` header.
- `Retry-After` header included in every block response.
- Admin dashboard showing live flood-state entries and recent block events.
- Drush command set for status, clear, allowlist management, and IP testing.
- No third-party PHP library dependencies beyond Drupal core.

## Requirements

- Drupal 10.4 or Drupal 11 (any patch release).
- PHP 8.1 or higher.
- Drupal core `flood` service (provided by core; no additional modules needed).

Optional:

- **Key** module (`drupal/key`): store the AbuseIPDB API key in a Key entity
  rather than plain configuration. Recommended for production.
- **Drush 12+**: required only to use the included Drush commands.

## Installation

1. Place the module in your project:

   ```
   composer require drupal/api_flood_guard
   ```

   Or copy the `api_flood_guard` directory to
   `web/modules/custom/api_flood_guard`.

2. Enable the module:

   ```
   drush en api_flood_guard
   ```

   Or navigate to **Extend** (`/admin/modules`) and enable *API Flood Guard*
   under the *Security* package.

3. Navigate to **Administration > Configuration > Security > API Flood Guard**
   (`/admin/config/security/api-flood-guard`) to configure protected paths,
   thresholds, and IP reputation settings.

## Configuration

All settings are stored in `api_flood_guard.settings` and can be managed
through the admin UI or exported to `config/sync`.

### Admin UI

Navigate to `/admin/config/security/api-flood-guard`.

The settings form is divided into the following sections.

#### Protected API Paths

A list of paths subject to flood control. Each entry uses one of two formats:

```
prefix:/jsonapi
exact:/oauth/token
exact:/user/login
exact:/rest/user/login
```

- `prefix:` matches any path that begins with the given string.
- `exact:` matches only the exact path.

Default protected paths:

| Format | Path |
|--------|------|
| prefix | `/jsonapi` |
| exact  | `/user/login` |
| exact  | `/oauth/token` |
| exact  | `/rest/user/login` |

Note: HTML form submissions to `/user/login` (i.e., `Content-Type:
application/x-www-form-urlencoded` without `?_format=json`) are automatically
excluded so that Drupal core's built-in login flood protection handles them.

#### Flood Thresholds

| Setting | Default | Description |
|---------|---------|-------------|
| Per-IP request threshold | 100 | Maximum requests from one IP within the IP window before blocking. |
| Per-IP time window | 3600 s (1 hr) | Window duration for the per-IP counter. |
| Per-username request threshold | 20 | Maximum requests for one username within the username window before blocking. |
| Per-username time window | 900 s (15 min) | Window duration for the per-username counter. |

#### Block Response

| Setting | Default | Description |
|---------|---------|-------------|
| HTTP response code | 429 | `429 Too Many Requests` (RFC 6585) or `503 Service Unavailable`. |
| Block response message | *"Too many authentication requests..."* | Human-readable message included in the response body. |

#### IP Allowlist

One CIDR entry per line. Allowlisted IPs bypass all flood and reputation
checks. Accepts individual addresses and subnet ranges:

```
127.0.0.1
10.0.0.0/8
192.168.1.0/24
::1
2001:db8::/32
```

#### IP Reputation (optional)

Select **AbuseIPDB** from the provider dropdown and supply credentials.

| Setting | Default | Description |
|---------|---------|-------------|
| Provider | None | Select `AbuseIPDB` to enable reputation checking. |
| API key (plain text) | — | Your AbuseIPDB v2 API key. Get a free key at https://www.abuseipdb.com. |
| API key (Key entity) | — | Select a Key module entity. Takes precedence over the plain-text field. |
| Confidence score threshold | 85 | IPs with a score at or above this value are blocked (0–100). |
| Maximum report age | 30 days | Only consider reports this many days old or newer. |
| Cache TTL | 3600 s | Cache AbuseIPDB responses per IP for this duration. Set to 0 to disable caching (not recommended in production). |

#### Debugging

Enable **debug-level logging** to write a log entry for every request that
passes through a protected path. This generates high log volume and should be
used only when troubleshooting. Disabled by default.

### Configuration via `config/sync`

Export and deploy settings with standard Drupal configuration management:

```
drush cex   # export
drush cim   # import
```

The configuration object name is `api_flood_guard.settings`.

## Usage

Once enabled and configured, the module operates transparently. No code
changes are required in your application.

### Admin Dashboard

Three admin pages are available under
**Administration > Configuration > Security > API Flood Guard**:

| Path | Description |
|------|-------------|
| `/admin/config/security/api-flood-guard` | Main settings form. |
| `/admin/config/security/api-flood-guard/flood-state` | Live flood-state table showing active IP and username counters; supports manual entry clearing. |
| `/admin/config/security/api-flood-guard/log` | Recent block events pulled from the Drupal watchdog log. |

The flood-state page auto-refreshes every 30 seconds via a small JavaScript
polling routine.

### Drush Commands

All commands require the `administer api flood guard` permission or Drush
access.

#### `api-flood-guard:status` (alias: `afg:status`)

Show active flood entry counts grouped by namespace.

```
drush api-flood-guard:status
```

#### `api-flood-guard:clear` (alias: `afg:clear`)

Clear flood entries by IP, username, or all at once.

```
drush api-flood-guard:clear --ip=203.0.113.42
drush api-flood-guard:clear --user=admin
drush api-flood-guard:clear --all
```

#### `api-flood-guard:allowlist-add` (alias: `afg:allowlist-add`)

Add a CIDR range or single IP to the allowlist.

```
drush api-flood-guard:allowlist-add 10.0.0.0/8
drush api-flood-guard:allowlist-add 203.0.113.42
```

#### `api-flood-guard:test-ip` (alias: `afg:test-ip`)

Test a specific IP against the configured reputation provider and display the
result (score, blocked/allowed, cache status).

```
drush api-flood-guard:test-ip 203.0.113.42
```

### Block Response Format

When a request is blocked, the module returns:

- **HTTP status**: 429 (or 503 if configured).
- **`Retry-After`** header: seconds until the flood window expires.
- **`Cache-Control: no-store, no-cache`** to prevent caching of block responses.
- **`X-Content-Type-Options: nosniff`**.
- **Body**: JSON:API-formatted error object if the request `Accept` header
  includes `application/json` or `application/vnd.api+json`; plain text
  otherwise.

JSON:API error body example:

```json
{
  "errors": [
    {
      "status": "429",
      "title": "Too Many Requests",
      "detail": "Too many authentication requests. Please wait before trying again."
    }
  ]
}
```

## API (for developers)

### Services

#### `api_flood_guard.manager` — `ApiFloodManager`

The central pipeline service. Inject it when you need to invoke flood
evaluation from custom code.

```php
/** @var \Drupal\api_flood_guard\Service\ApiFloodManager $floodManager */
$decision = $floodManager->evaluate($request, $clientIp, $usernameHash);

if (!$decision->allowed) {
  // $decision->reason: 'ip' | 'user' | 'reputation'
  // $decision->retryAfter: seconds
}

// Clear per-IP counter manually (e.g., after a confirmed false positive):
$floodManager->clearIpFlood('203.0.113.42');

// Clear per-username counter on successful authentication:
$floodManager->clearUserFlood($usernameHash); // hash('sha256', strtolower(trim($username)))
```

#### `api_flood_guard.endpoint_detector` — `ApiEndpointDetector`

Detects whether a request targets a protected path and extracts a
SHA-256-hashed username/client_id identifier from the request.

```php
/** @var \Drupal\api_flood_guard\Service\ApiEndpointDetector $detector */
$isProtected  = $detector->isProtectedPath($request);       // bool
$usernameHash = $detector->extractUsernameIdentifier($request); // SHA-256 string or ''
```

### Value Objects

#### `FloodDecision`

Immutable result returned by `ApiFloodManager::evaluate()`.

| Property | Type | Description |
|----------|------|-------------|
| `$allowed` | bool | `true` if the request may proceed. |
| `$reason` | string | `'passed'`, `'allowlist'`, `'ip'`, `'user'`, or `'reputation'`. |
| `$identifier` | string | The IP address or hashed username that triggered the decision. |
| `$retryAfter` | int | Seconds until the flood window resets (0 when allowed). |

#### `IpReputationResult`

Immutable result returned by reputation provider plugins.

| Property | Type | Description |
|----------|------|-------------|
| `$isBlocked` | bool | Whether the IP should be blocked. |
| `$confidenceScore` | int | Provider confidence score (0–100). |
| `$providerName` | string | Plugin ID of the provider that ran. |
| `$fromCache` | bool | `true` when the result was served from the Drupal cache. |
| `$providerError` | bool | `true` when the provider failed (fail-open). |

### IP Reputation Plugin System

You can add a custom IP reputation provider by implementing the
`IpReputationProviderInterface` and applying the `#[IpReputationProvider]`
attribute.

```php
use Drupal\api_flood_guard\Annotation\IpReputationProvider;
use Drupal\api_flood_guard\Contract\IpReputationProviderInterface;
use Drupal\api_flood_guard\Value\IpReputationResult;
use Drupal\Core\Plugin\PluginBase;
use Drupal\Core\StringTranslation\TranslatableMarkup;

#[IpReputationProvider(
  id: 'my_provider',
  label: new TranslatableMarkup('My Provider'),
  description: new TranslatableMarkup('Custom IP reputation check.'),
  api_endpoint: 'https://api.example.com/check',
)]
class MyProvider extends PluginBase implements IpReputationProviderInterface {

  public function isConfigured(): bool {
    return TRUE; // Check for API key, etc.
  }

  public function checkIp(string $ip): IpReputationResult {
    // Must be fail-open: never throw; return IpReputationResult::failOpen() on error.
    try {
      // ... call external service ...
      return IpReputationResult::allowed(score: 0, providerName: 'my_provider');
    }
    catch (\Throwable) {
      return IpReputationResult::failOpen('my_provider');
    }
  }
}
```

Place the class in `src/Plugin/IpReputation/` inside your module. Drupal's
plugin manager discovers it automatically. The plugin ID then becomes
selectable in the admin settings form's provider dropdown.

**Contract requirement**: every `checkIp()` implementation must be fail-open.
On any error (network failure, invalid credentials, rate-limit exceeded), set
`providerError = true` and `isBlocked = false` so that legitimate traffic is
never blocked due to provider unavailability.

### Event Subscriber Priority

| Event | Priority | Purpose |
|-------|----------|---------|
| `KernelEvents::REQUEST` | 300 | Evaluates and potentially blocks requests before routing, authentication, and page cache. |
| `KernelEvents::RESPONSE` | -100 | Clears per-username flood counters after a successful (HTTP 200) authentication response. |

### Flood Namespaces

The module writes to Drupal core's `flood` table using these event names:

| Namespace | Keyed by |
|-----------|----------|
| `api_flood_guard.ip` | Client IP address |
| `api_flood_guard.user` | SHA-256 hash of the normalized username or client_id |

## Security Notes

- **Identifier privacy**: usernames and client IDs are never stored in plain
  text. The module hashes all identifiers with SHA-256 before writing them to
  the flood table. Only the first 8 characters of a hash appear in warning
  log messages.

- **Fail-open reputation checks**: if the AbuseIPDB API (or any custom
  provider) is unreachable or returns an error, the module logs a warning and
  proceeds to standard flood checks. It never fails closed and blocks
  legitimate traffic due to a third-party service outage.

- **CIDR allowlist**: trust internal networks (load balancers, health checkers,
  internal services) by adding their IP ranges to the allowlist. Allowlisted
  IPs skip both reputation and flood checks entirely.

- **HTML form bypass**: standard Drupal login form submissions
  (`Content-Type: application/x-www-form-urlencoded` to `/user/login` without
  `?_format=json`) are passed through to Drupal core's own login flood
  protection and are not double-counted by this module.

- **Reverse-proxy compatibility**: the module reads the client IP via Symfony's
  `Request::getClientIp()`. If your site runs behind a reverse proxy or load
  balancer, configure Drupal's `reverse_proxy` settings in `settings.php` so
  the real client IP is resolved correctly:

  ```php
  $settings['reverse_proxy'] = TRUE;
  $settings['reverse_proxy_addresses'] = ['10.0.0.1'];
  ```

- **API key storage**: store AbuseIPDB API keys using the Key module rather
  than the plain-text configuration field. This keeps sensitive credentials
  out of the configuration export and version control.

- **Response code**: `429 Too Many Requests` is the RFC 6585-compliant code
  for rate limiting. Use `503 Service Unavailable` only if required by an
  upstream reverse proxy for throttling purposes.

- **Debug logging**: the debug-logging option writes a log entry for every
  allowed request on protected paths. Enable this only in development or for
  short troubleshooting sessions; it can produce very high log volume on
  production sites.

## Maintainers

- Harshvardhan Soni (harshvardhan.soni@xecurify.com)

## License

This project is licensed under the GNU General Public License, version 2 or
later. See the [LICENSE](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
file for details.
