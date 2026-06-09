# HIBP Password Guard

## Description

HIBP Password Guard integrates with the [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
Pwned Passwords Range API to prevent users from choosing passwords that have
appeared in known data breaches.

The module extends the [Password Policy](https://www.drupal.org/project/password_policy)
module by providing a **Not Pwned Password** constraint plugin. When a user
sets or changes a password, the constraint hashes it with SHA-1, sends only the
first five hexadecimal characters of that hash to the HIBP API (k-anonymity
model), and checks whether the remaining suffix appears in the returned list of
breach records. The plaintext password and the full SHA-1 hash **never leave
the server** and are never stored or logged.

Key features:

- K-anonymity model: only a 5-character SHA-1 prefix is transmitted over the
  network.
- Configurable response caching per prefix (default: 24 hours) to avoid
  repeated outbound requests for the same hash range.
- Configurable degradation mode: **fail open** (accept the password when the
  API is unreachable) or **fail closed** (block the password when the API is
  unreachable).
- Connectivity probe on the Drupal Status Report page
  (`/admin/reports/status`), cached for five minutes.
- Drush command (`hibp:check-user`) for manual breach checks from the CLI.
- Support for a custom API base URL (self-hosted mirror, corporate proxy).

---

## Requirements

- **Drupal** 10.4 or 11.x
- **PHP** 8.2 or later (uses readonly properties and named arguments)
- **Password Policy** module 4.x (`drupal/password_policy ^4.0`)
- **Guzzle HTTP** 7.x (`guzzlehttp/guzzle ^7.0`) -- included with Drupal core
- Outbound HTTPS access to `https://api.pwnedpasswords.com` (unless a
  custom API base URL is configured)
- **Drush** 12.x (optional, required only for the `hibp:check-user` command)

---

## Installation

### With Composer (recommended)

Place the module in your project's `modules/custom/` directory or add it via
Composer if it is published on Packagist:

```bash
composer require drupal/hibp_password_guard
```

Enable the module:

```bash
drush en hibp_password_guard
```

Or navigate to **Extend** (`/admin/modules`), locate **HIBP Password Guard**
under the **Security** package, and enable it.

> The Password Policy module must be enabled before or at the same time as
> HIBP Password Guard. Drupal's module installer handles this automatically
> because `password_policy:password_policy` is declared as a dependency in
> `hibp_password_guard.info.yml`.

### Manual installation

1. Copy the `hibp_password_guard` directory to `modules/custom/`.
2. Enable via Drush or the UI as described above.

---

## Configuration

Navigate to **Administration > Configuration > Security > HIBP Password Guard**
(`/admin/config/security/hibp-password-guard`).

The permission `administer hibp password guard` is required to access this
page. It is restricted to privileged roles by default.

### Global settings

| Setting | Default | Description |
|---|---|---|
| **Enable HIBP breach checking** | Enabled | Global on/off switch. When disabled, the constraint always passes without making any HTTP call. |

### API settings

| Setting | Default | Description |
|---|---|---|
| **HIBP API base URL** | `https://api.pwnedpasswords.com` | Override to point at a self-hosted mirror, corporate proxy, or alternative endpoint. TLS verification is always enforced. |
| **HTTP request timeout** | `5` seconds | Combined connect and read timeout for a single API request. Minimum 1, maximum 30 seconds. |

### Caching

| Setting | Default | Description |
|---|---|---|
| **Cache TTL** | `86400` seconds (24 hours) | How long a successful HIBP range response is cached per 5-character SHA-1 prefix. Set to `0` to disable caching (not recommended for production). |

### Degradation mode

| Mode | Behaviour |
|---|---|
| **Fail open** (default) | When the HIBP API cannot be reached, the password check is skipped and the password is accepted. A watchdog notice is logged. Recommended for most sites to avoid locking users out during transient API outages. |
| **Fail closed** | When the HIBP API is unreachable, the password change is blocked. Recommended for high-security environments where enforcement takes priority over availability. |

---

## Usage

### Adding the constraint to a password policy

1. Navigate to **Administration > Configuration > Security > Password policies**
   (`/admin/config/security/password-policy`).
2. Edit an existing policy or create a new one.
3. On the **Constraints** tab, click **Add constraint**.
4. Select **Not Pwned Password** from the list and save.
5. The constraint appears in the policy summary as:
   > Password must not appear in the Have I Been Pwned breach database.

No per-constraint configuration is needed. All behaviour is controlled by the
module-level settings described in the Configuration section above.

### User experience

When a user submits a password that has appeared in a data breach, they see:

> This password has appeared in a data breach N time(s). Please choose a
> different password.

When the API is unavailable and the module is in **fail closed** mode:

> Password breach check is temporarily unavailable. Please try again later.

### Status Report

HIBP Password Guard adds a row to the Drupal Status Report page
(`/admin/reports/status`) labelled **HIBP Pwned Passwords API**. The probe
sends an innocuous range request to the configured API endpoint and reports
one of three states:

| Severity | Meaning |
|---|---|
| OK | API is reachable and returned HTTP 200. |
| Warning | API returned an unexpected HTTP status code. |
| Error | Connection-level failure; check outbound HTTPS access. |

Probe results are cached for five minutes to prevent excessive outbound
requests on repeated page loads.

### Drush command

Check whether a given plaintext password would be flagged as pwned:

```bash
drush hibp:check-user <username> --plaintext="MyPassword123!"
```

Force a fresh API call, bypassing the local cache:

```bash
drush hibp:check-user <username> --plaintext="MyPassword123!" --bypass-cache
```

Look up a user by name without supplying a password (confirms the user exists
and explains why stored-hash comparison is not possible with PHPass):

```bash
drush hibp:check-user <username>
```

Alias: `hibp-cu`

> Drupal stores passwords with PHPass (a bcrypt derivative), not SHA-1.
> Direct comparison with the HIBP database requires the plaintext password.
> The Drush command never stores or logs the value passed via `--plaintext`.

---

## API (for developers)

### Services

Two services are registered and available via the Drupal service container.

#### `hibp_password_guard.checker`

Class: `Drupal\hibp_password_guard\Service\HibpPasswordCheckerService`

Orchestrates the full check pipeline: SHA-1 hashing, cache lookup, API call,
response parsing, and fail-mode resolution.

```php
/** @var \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService $checker */
$checker = \Drupal::service('hibp_password_guard.checker');

$result = $checker->check('plaintextPassword');
// $result->isPwned   -- bool: TRUE if found in a breach
// $result->breachCount -- int: number of breach records
// $result->apiError  -- bool: TRUE if the API call failed
// $result->errorType -- string: sanitised error description

// Force a fresh API call (skips cache read; still writes on success):
$result = $checker->check('plaintextPassword', bypassCache: true);
```

#### `hibp_password_guard.api_client`

Class: `Drupal\hibp_password_guard\Service\HibpApiClient`

Low-level HTTP wrapper for the HIBP Pwned Passwords Range API. Accepts exactly
a 5-character uppercase hexadecimal prefix and returns an `HibpRangeResponse`
value object. Prefer `hibp_password_guard.checker` for most use cases.

```php
/** @var \Drupal\hibp_password_guard\Service\HibpApiClient $client */
$client = \Drupal::service('hibp_password_guard.api_client');

$response = $client->fetchRange('AABB1');
// $response->success    -- bool
// $response->body       -- string: raw CRLF-delimited SUFFIX:COUNT lines
// $response->statusCode -- int: HTTP status, or 0 on connection failure
// $response->errorMessage -- string: sanitised error description
```

### Value objects

Both value objects are immutable (`final readonly class`).

#### `HibpCheckResult`

`Drupal\hibp_password_guard\Value\HibpCheckResult`

Returned by `HibpPasswordCheckerService::check()`. Properties: `isPwned`
(bool), `breachCount` (int), `apiError` (bool), `errorType` (string).

#### `HibpRangeResponse`

`Drupal\hibp_password_guard\Value\HibpRangeResponse`

Returned by `HibpApiClient::fetchRange()`. Properties: `success` (bool),
`body` (string), `statusCode` (int), `errorMessage` (string).

### Password constraint plugin

Plugin ID: `hibp_compromised`

The constraint plugin is discovered automatically by the Password Policy module.
It can be referenced programmatically by its plugin ID if you need to add it to
a policy via the API or in test fixtures.

### Cache bin

The module declares a dedicated cache bin `cache.hibp_password_guard`
(key: `hibp_password_guard`). Range response bodies are cached under the key
`hibp_range:<PREFIX>`. You can clear all HIBP range caches with:

```bash
drush cache:clear hibp_password_guard
```

Or in PHP:

```php
\Drupal::cache('hibp_password_guard')->deleteAll();
```

---

## Security Notes

- **K-anonymity**: only the first 5 hexadecimal characters of the SHA-1 hash
  are sent to the HIBP API. Troy Hunt's k-anonymity model guarantees that the
  API cannot determine which specific password was queried.
- **No plaintext transmission**: the plaintext password is SHA-1 hashed
  in-process and immediately released to garbage collection. It is never stored,
  logged, or passed to any external service.
- **No user linkage in logs**: log entries contain only exception class names
  and HTTP status codes. The prefix, suffix, hash, username, and password are
  never included in log messages.
- **TLS enforced**: Guzzle's default TLS certificate verification is always
  active. It is not disabled for any configured API base URL.
- **`Add-Padding` header**: all range requests include the `Add-Padding: true`
  header, which instructs the HIBP API to pad responses to a fixed size,
  preventing traffic-analysis attacks that could otherwise infer which prefix
  was queried.
- **Restricted admin permission**: the `administer hibp password guard`
  permission is marked `restrict access: true`, so it is not granted to any
  role by default and must be explicitly assigned.

---

## Maintainers

- Harshvardhan Soni (harshvardhan.soni@xecurify.com)

---

## License

This module is licensed under the **GNU General Public License, version 2 or
later** (GPL-2.0-or-later).

See [LICENSE.txt](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) or
the `LICENSE.txt` file at the root of your Drupal installation for the full
license text.
