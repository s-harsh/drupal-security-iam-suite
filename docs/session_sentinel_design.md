# Session Sentinel — Design Document

## 1. Purpose

Session Sentinel replaces three unmaintained Drupal modules — `session_limit`, `session_expire`, and `user_protect` — with a single, well-architected Drupal 11 module. It implements idle session timeout, concurrent session limiting, and device fingerprint binding in a unified codebase that follows current Drupal 11 coding standards.

## 2. Problem Statement

### 2.1 Unmaintained Predecessors

| Module | Last Release | Issue |
|---|---|---|
| session_limit | 2022 | No Drupal 11 port; uses procedural hooks |
| session_expire | 2021 | No D11 support; only client-side timeout |
| user_protect | 2020 | Archived; scope overlap with other modules |

### 2.2 Security Gaps Addressed

- **Session hijacking**: No built-in mechanism prevents an attacker from using a stolen session token indefinitely.
- **Account sharing**: Nothing limits simultaneous logins from multiple devices.
- **Stale sessions**: Sessions can persist long after a user stops interacting.
- **Device anomalies**: Drupal has no native mechanism to detect mid-session device changes.

## 3. Feature Specification

### 3.1 Idle Session Timeout

**Requirement**: Sessions that have been idle for longer than a configured threshold must be invalidated server-side and the user must be redirected to the login page.

**Design decisions**:
- The timeout is enforced server-side (in `SessionTimeoutSubscriber`) on every authenticated request. Client-side JavaScript is only a user-experience aid.
- Per-role overrides allow tighter restrictions for privileged roles (e.g. administrators get 15 minutes, editors get 60 minutes).
- The tightest applicable role timeout wins when a user has multiple roles.
- Timeout of `0` disables idle expiry globally (opt-in to the feature).

**JavaScript warning**:
- `session-timeout-warning.js` runs as a Drupal behaviour attached to the page body.
- It reads `drupalSettings.sessionSentinel.idleTimeout` and `warningLeadTime`.
- When the client-side idle counter exceeds `(idleTimeout - warningLeadTime)` seconds, a fixed-position countdown banner is injected into the DOM.
- User activity events (mousemove, keydown, click, scroll, touchstart) reset the client-side counter.
- A throttled keep-alive POST is sent at most once per 30 seconds to update the server-side `last_active` timestamp.
- The "Stay logged in" button sends an immediate keep-alive and dismisses the banner.

### 3.2 Concurrent Session Limit

**Requirement**: When a user logs in and they already have N active sessions (where N is configured), the oldest session must be killed automatically.

**Design decisions**:
- "Active" sessions are those represented by rows in `session_sentinel_sessions` with a `last_active` timestamp within the configured `prune_age`.
- On `hook_user_login`, after creating the new sentinel record, `enforceConcurrentLimit()` queries all sessions for that UID ordered by `last_active ASC` and deletes from the oldest until the count is at or below the limit.
- The newly-created session is never killed during enforcement.
- Administrators (uid=1 or users with `administer users`) are exempt by default (configurable).
- A limit of `0` means unlimited sessions.

### 3.3 Device Fingerprint Binding

**Requirement**: Detect when a session's device context changes mid-session (potential session hijacking) and take configurable action.

**Design decisions**:
- The fingerprint is `SHA-256(User-Agent + '|' + subnet)` where subnet is the /24 for IPv4 or /48 for IPv6.
- Using a subnet rather than the exact IP tolerates normal DHCP lease churn within the same network.
- The fingerprint is stored at session creation (`hook_user_login`).
- On every authenticated request, `SessionTimeoutSubscriber` computes the current fingerprint and compares it with the stored value using `hash_equals()` (timing-safe).
- **Flag mode** (default, `kill_on_device_change = false`): The `flagged_device_change` column is set to 1, a WARNING is logged, and the session continues. The admin dashboard highlights flagged sessions.
- **Kill mode** (`kill_on_device_change = true`): The session is immediately destroyed and the user is redirected to the login page.
- IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are normalised to IPv4 before subnet extraction.

### 3.4 Admin Session Dashboard

**Requirement**: Administrators must be able to view all active sessions and kill individual sessions.

**Design decisions**:
- The dashboard at `/admin/config/security/session-sentinel/dashboard` renders an HTML table with per-session kill buttons.
- Kill actions use CSRF tokens (`_csrf_token: true` in routing and manual `\Drupal::csrfToken()->validate()` in the controller).
- A JSON endpoint at `/admin/config/security/session-sentinel/dashboard/data` returns session data for JavaScript-driven auto-refresh without a full page reload.
- The dashboard loads at most 300 sessions to bound memory usage on large sites.

### 3.5 Drush Commands

| Command | Alias | Description |
|---|---|---|
| `session-sentinel:prune` | `ss:prune` | Delete stale sentinel records |
| `session-sentinel:list {uid}` | `ss:list` | List all sessions for a UID |
| `session-sentinel:kill {hash}` | `ss:kill` | Kill session by ID hash |
| `session-sentinel:status` | `ss:status` | Summary of active/flagged counts |

## 4. Data Model

### 4.1 `session_sentinel_sessions` Table

| Column | Type | Notes |
|---|---|---|
| `id` | serial UINT | Primary key |
| `uid` | INT UINT | FK to users.uid (not enforced at DB level) |
| `session_id_hash` | VARCHAR(64) | SHA-256 of PHP session ID; UNIQUE |
| `device_fingerprint` | VARCHAR(64) | SHA-256 of UA + subnet |
| `ip_address` | VARCHAR(45) | Raw client IP at login |
| `user_agent` | VARCHAR(512) | User-Agent (truncated) |
| `created` | INT UINT | Unix timestamp |
| `last_active` | INT UINT | Unix timestamp; updated on every request |
| `flagged_device_change` | TINYINT | 0/1 boolean flag |

**Indexes**: `uid`, `last_active`, `(uid, last_active)`, UNIQUE on `session_id_hash`.

### 4.2 Relationship to Drupal Core Sessions

Drupal stores active session data in the `sessions` table with `sid` = SHA-256 hash of the session ID (since Drupal 9.3). Session Sentinel's `session_id_hash` column is designed to match this value, enabling `killSession()` to delete from both tables atomically.

## 5. Configuration

All configuration lives in `session_sentinel.settings` (a simple config object). There are no entities.

## 6. Security Considerations

- Session ID hashes are never stored in plain text. Raw session IDs never leave PHP memory in this module.
- CSRF protection is applied to the kill action via Drupal's built-in token system.
- Fingerprint comparison uses `hash_equals()` to prevent timing side-channels.
- Device binding failure is fail-open by default to avoid locking out mobile users whose IPs change mid-session.
- The JSON dashboard endpoint requires the `administer session sentinel` permission and is not publicly accessible.

## 7. Testing Strategy

| Layer | Tools | What is tested |
|---|---|---|
| Unit | PHPUnit + MockObject | SessionRecord immutability, idleSeconds, DeviceFingerprintService subnet logic, SessionSentinelManager business logic with mocked DB |
| Functional | BrowserTestBase | Settings form saves/validates, dashboard access control, JSON endpoint structure, CSRF enforcement on kill |
| E2E | Playwright | Full user flows: login, JS warning banner, "Stay logged in", forced logout redirect |
