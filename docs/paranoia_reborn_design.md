# Paranoia Reborn — Design Document

## 1. Problem Statement

The original [Paranoia](https://www.drupal.org/project/paranoia) module for Drupal 7/8 was abandoned and has no Drupal 10/11-compatible release. It provided critical security hardening that many enterprise sites depended on. Paranoia Reborn fills this gap for Drupal 11 with a modern architecture, Drupal 11 coding standards, and an expanded feature set.

The module addresses a real attack surface pattern: Drupal sites often give editors overly broad role permissions, leaving `/admin/*` paths, the PHP filter module, Field UI, and Views UI accessible to accounts that should never touch them.

---

## 2. Goals

1. **Replace Paranoia module functionality** for Drupal 11: admin path blocking, PHP filter hardening.
2. **Extend** with Field UI and Views UI route protection.
3. **Profiles** — preconfigured lockdown levels so administrators can choose a sensible default without manually tuning every toggle.
4. **Audit trail** — every blocked attempt logged to dblog with full context.
5. **Status report integration** — surfaced on `/admin/reports/status` so security posture is visible at a glance.
6. **Zero procedural code** — all logic in OOP services and hook classes per Drupal 11 standards.
7. **Testable** — unit-testable services with no dependency on the full Drupal kernel.

---

## 3. Non-Goals

- This module does not attempt to replicate Drupal's role/permission system.
- It does not perform authentication (login/logout).
- It does not integrate with external IAM providers.
- It does not manage two-factor authentication or password policies (those are covered by other modules in this suite).

---

## 4. Threat Model

### 4.1 PHP Filter (CVE vector)
The `php` module allows site administrators to embed and execute raw PHP code inside text fields. If a privileged account (or an account that can be hijacked via XSS, credential stuffing, or session fixation) has access to this feature, an attacker can achieve Remote Code Execution (RCE) on the server.

**Mitigation**: Paranoia Reborn automatically uninstalls the `php` module at configuration-save time and via `hook_modules_installed` to prevent re-activation.

### 4.2 Admin Path Exposure
Drupal's permission system protects individual actions but relies on administrators correctly assigning permissions. Misconfigurations are common — e.g., giving "editor" roles `use text format full_html` + `administer nodes` by mistake. An attacker who can access `/admin/config/system/performance` or `/admin/structure` may be able to:

- Enable dangerous text formats
- Modify site configuration to inject code
- Create or modify content types in unexpected ways

**Mitigation**: PathRestrictor blocks the entire `/admin/*` namespace for non-trusted roles, with an explicit exception list for paths that editors legitimately need (e.g., `/admin/content`).

### 4.3 Field UI / Views UI Abuse
Field UI and Views UI allow structural changes to the database schema and data presentation layer. Access to these routes by non-developer roles can lead to:

- Accidental data loss (deleting fields)
- Exposing sensitive fields through misconfigured views
- Creating views that bypass normal access checks

**Mitigation**: Separate restriction flags for Field UI and Views UI, applied via PathRestrictor.

---

## 5. Lockdown Profiles

Three profiles are provided to balance security with operational usability:

### Strict
- All protections active.
- No admin-path exceptions (except those explicitly listed).
- Intended for high-security environments: PCI-DSS, healthcare, government portals.

### Balanced (default)
- All protections active.
- Pre-configured exceptions: `/admin/content`, `/admin/content/files`.
- Intended for standard content-managed sites where editors need content management access.

### Custom
- Administrator toggles each protection individually.
- Admin-path allowlist roles available (roles that can access `/admin/*` even with restriction on).
- Intended for teams with non-standard workflows that cannot fit into Strict/Balanced.

---

## 6. Access Decision Flow

```
Incoming request (KernelEvents::REQUEST, priority 33)
    │
    ├─ Sub-request? ──Yes──▶ Skip (no block)
    │
    ├─ Is path /admin/* or Field UI or Views UI? ──No──▶ Skip
    │
    ├─ Account is anonymous? ──Yes──▶ BLOCK + audit log
    │
    ├─ UID 1? ──Yes──▶ Allow
    │
    ├─ Has 'bypass paranoia reborn restrictions'? ──Yes──▶ Allow
    │
    ├─ Any role in trusted_roles? ──Yes──▶ Allow
    │
    ├─ Path in admin_path_exceptions? ──Yes──▶ Allow
    │
    ├─ Profile=custom AND role in admin_path_allowlist_roles? ──Yes──▶ Allow
    │
    └─ BLOCK ──▶ Return HTTP 403 + audit log entry
```

---

## 7. Configuration Schema

All settings stored in `paranoia_reborn.settings`:

| Key | Type | Default (Balanced) | Description |
|---|---|---|---|
| `lockdown_profile` | string | `balanced` | Active profile ID |
| `trusted_roles` | list\<string\> | `[administrator]` | Role IDs that bypass all restrictions |
| `admin_path_allowlist_roles` | list\<string\> | `[]` | Roles allowed `/admin/*` in custom profile |
| `admin_path_restriction` | bool | `true` | Block `/admin/*` for untrusted roles |
| `disable_php_filter` | bool | `true` | Uninstall PHP filter module |
| `field_ui_restriction` | bool | `true` | Block Field UI routes |
| `views_ui_restriction` | bool | `true` | Block Views UI routes |
| `admin_path_exceptions` | list\<string\> | `[/admin/content, /admin/content/files]` | Paths allowed for all auth'd users |
| `audit_log_enabled` | bool | `true` | Write blocked attempts to watchdog |

---

## 8. Audit Log Format

Each audit log entry is a `WARNING`-severity watchdog message of type `paranoia_reborn` with the following template:

```
Paranoia Reborn blocked access to @path for uid @uid (roles: @roles) from IP @ip. Reason: @reason.
```

Variable substitution uses Drupal's standard `@variable` pattern so watchdog handles sanitization. Log entries are viewable at `/admin/reports/paranoia-reborn-audit`.

---

## 9. Status Report Items

| Item key | Pass condition | Fail severity |
|---|---|---|
| `paranoia_reborn_profile` | Always INFO | — |
| `paranoia_reborn_php_filter` | PHP filter not installed | ERROR |
| `paranoia_reborn_admin_paths` | Restriction active | WARNING |
| `paranoia_reborn_field_ui` | Restriction active | WARNING |
| `paranoia_reborn_views_ui` | Restriction active | WARNING |
| `paranoia_reborn_audit` | Always INFO | — |

---

## 10. Open Issues / Future Work

- **Drush commands**: `paranoia-reborn:status`, `paranoia-reborn:harden`, `paranoia-reborn:clear-log` (scaffolded in roadmap; requires `drush/drush` ^12 dev dependency).
- **Role-based path allowlist in Balanced profile**: Currently only available in Custom. May be promoted to Balanced in a future minor version.
- **Integration with Drupal's Permission overview**: Could annotate the `/admin/people/permissions` page to highlight roles that bypass restrictions.
- **Event dispatching**: Dispatch a `ParanoiaRebornBlockEvent` so other modules can react to blocked access (e.g., trigger a security alert, increment a flood counter).
