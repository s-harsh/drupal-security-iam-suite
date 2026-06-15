# Paranoia Reborn

**Modern replacement for the abandoned Paranoia module.**
Security hardening for Drupal 11 sites — configurable lockdown profiles, admin-path access controls, PHP filter disablement, and a full audit trail.

---

## Features

| Feature | Description |
|---|---|
| **Lockdown Profiles** | Three profiles — *Strict*, *Balanced* (default), *Custom* — each controlling which protections are active |
| **Admin Path Restriction** | Blocks `/admin/*` for roles not on the trusted list; per-path exceptions supported (with `/**` wildcard suffix) |
| **PHP Filter Hardening** | Automatically uninstalls the `php` module (a critical RCE vector) when the profile requires it; re-disables it if re-installed |
| **Field UI Protection** | Hides `/admin/structure/types/manage/*/fields` (and taxonomy/paragraph equivalents) from non-developer roles |
| **Views UI Protection** | Restricts `/admin/structure/views` to trusted roles only |
| **Audit Log** | Every blocked attempt is written to Drupal's watchdog (dblog) with path, UID, roles, and IP |
| **Status Report** | Each protection's state is surfaced on `/admin/reports/status` |
| **Menu Link Filtering** | Field UI and Views UI menu links are removed from the admin toolbar for untrusted users |

---

## Installation

```bash
composer require drupal/paranoia_reborn
drush en paranoia_reborn -y
drush cr
```

Or enable via **Admin > Extend**.

---

## Configuration

Navigate to **Admin > Configuration > Security > Paranoia Reborn** (`/admin/config/security/paranoia-reborn`).

### Lockdown Profiles

| Profile | Behaviour |
|---|---|
| **Strict** | All protections enabled. No admin paths allowed for non-trusted roles (except explicit exceptions). |
| **Balanced** | All protections enabled. Pre-configured exceptions for `/admin/content` and `/admin/content/files` so editors can manage content. *Recommended for most sites.* |
| **Custom** | Each feature toggled individually. |

### Trusted Roles

Add roles whose members bypass all Paranoia Reborn restrictions. Always include `administrator`. UID 1 and any user with the `bypass paranoia reborn restrictions` permission are implicitly trusted regardless of this list.

### Admin Path Exceptions

Paths listed here (one per line) are accessible to all authenticated users even when admin-path restriction is active. Supports `/**` wildcard suffixes:

```
/admin/content
/admin/content/files
/admin/user/login/**
```

### Custom Profile Toggles

When the **Custom** profile is selected, each protection can be individually enabled or disabled:

- **Restrict `/admin/*` paths** — block non-trusted roles from all admin pages.
- **Disable PHP filter module** — uninstall `php` module on save.
- **Restrict Field UI routes** — hide field management pages from non-developers.
- **Restrict Views UI routes** — hide view creation/editing from non-developers.
- **Enable audit logging** — write blocked attempts to dblog.

---

## Permissions

| Permission | Description |
|---|---|
| `administer paranoia reborn` | Access the settings form and audit log page. Grant to site administrators only. |
| `bypass paranoia reborn restrictions` | Exempts the user from all restrictions. Grant only to senior developers. |

---

## Audit Log

View the audit log at **Admin > Reports > Paranoia Reborn Audit Log** (`/admin/reports/paranoia-reborn-audit`).

Each entry includes:

- Timestamp
- Blocked path
- UID and roles of the blocked user
- IP address
- Block reason (profile and trigger type)

---

## Drush Commands

```bash
# Show current hardening status
drush paranoia-reborn:status

# Apply hardening (disable PHP filter, etc.) manually
drush paranoia-reborn:harden

# Clear the audit log
drush paranoia-reborn:clear-log
```

---

## Requirements

- Drupal 11 (core ≥ 11.0)
- PHP 8.3+
- `dblog` module (for audit logging)

---

## Development

```bash
# Run PHPUnit unit tests
vendor/bin/phpunit modules/custom/paranoia_reborn/tests/src/Unit/

# Run PHPUnit functional tests (requires a running Drupal install)
vendor/bin/phpunit modules/custom/paranoia_reborn/tests/src/Functional/

# Run Playwright E2E tests
npx playwright test playwright/paranoia_reborn.spec.js
```

---

## Maintainers

- Harshvardhan Soni <harshvardhan.soni@xecurify.com> — Miniorange Software Security

---

## License

GPL-2.0-or-later — see [LICENSE](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
