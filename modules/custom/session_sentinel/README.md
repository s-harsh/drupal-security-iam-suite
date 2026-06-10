# Session Sentinel

**Session Sentinel** is a Drupal 11 security module that unifies the functionality of three unmaintained modules — `session_limit`, `session_expire`, and `user_protect` — into a single, well-maintained package.

## Features

### Idle Session Timeout
- Per-role configurable idle timeout (default 30 minutes).
- Warns the user via a JavaScript countdown banner 5 minutes before the session expires.
- On timeout, the session is destroyed and the user is redirected to the login page with a message.

### Concurrent Session Limiting
- Configurable maximum number of simultaneous sessions per user (default 3).
- When a new login causes the limit to be exceeded, the oldest session is automatically killed.
- Administrators are exempt from concurrent session limits by default (configurable).

### Device Fingerprint Binding
- Generates a SHA-256 fingerprint from the User-Agent string and the /24 IP subnet.
- Flags sessions where the fingerprint changes mid-session (anomalous device change).
- Flagged sessions are visible in the admin dashboard and can be killed immediately.
- Logging is emitted for all flagged changes.

### Admin Session Dashboard
- Live table at `/admin/config/security/session-sentinel/dashboard` showing all active sessions.
- Columns: User, UID, IP Address, User Agent (truncated), Last Active, Device Flagged, Kill.
- Per-session "Kill" button destroys the session immediately (CSRF-protected).
- JSON data endpoint for JavaScript-driven auto-refresh.

## Drush Commands

```bash
# Prune expired/stale sessions from the sentinel metadata table
drush session-sentinel:prune

# List all active sessions for a specific user
drush session-sentinel:list {uid}

# Kill a specific session by its session ID hash
drush session-sentinel:kill {session_id_hash}

# Show a summary of active session counts
drush session-sentinel:status
```

## Installation

```bash
composer require drupal/session_sentinel
drush en session_sentinel
drush cr
```

Navigate to **Administration > Configuration > Security > Session Sentinel** to configure the module.

## Configuration

All settings are at `/admin/config/security/session-sentinel`:

| Setting | Default | Description |
|---|---|---|
| Idle timeout (seconds) | 1800 | Global idle timeout. 0 = disabled. |
| Warning lead-time (seconds) | 300 | Seconds before expiry to show the JS countdown warning. |
| Per-role overrides | (empty) | Per-role idle timeout in seconds. 0 = use global. |
| Max concurrent sessions | 3 | Maximum simultaneous sessions per user. 0 = unlimited. |
| Exempt admins from limit | true | Exempt uid=1 and users with administer users permission. |
| Enable device binding | true | Enable device fingerprint anomaly detection. |
| Kill on device change | false | If true, kill sessions on fingerprint mismatch instead of just flagging. |

## Requirements

- Drupal 11 (or 10.4+)
- PHP 8.1+
- Drush 12+ (for Drush commands)

## License

GPL-2.0-or-later
