## Description

<!-- Summarize the changes and the motivation. Link to relevant issues. -->

Closes #<!-- issue number -->

---

## Type of Change

- [ ] `feat` — New module or feature
- [ ] `fix` — Bug fix
- [ ] `security` — Security fix
- [ ] `docs` — Documentation only
- [ ] `test` — Tests only
- [ ] `refactor` — Refactor with no feature/fix
- [ ] `chore` — Build, tooling, dependencies

---

## Module(s) Affected

<!-- List the modules this PR touches -->

- [ ] hibp_password_guard
- [ ] api_flood_guard
- [ ] csp_wizard
- [ ] session_sentinel
- [ ] paranoia_reborn
- [ ] sbom_sentinel
- [ ] passkey_forge
- [ ] zero_standing_privilege
- [ ] scim_bridge
- [ ] api_key_vault
- [ ] behavior_beacon
- [ ] compliance_command_center

---

## Checklist

### Code Quality
- [ ] Code follows [Drupal Coding Standards](https://www.drupal.org/docs/develop/standards)
- [ ] PHP 8.2+ features used where appropriate
- [ ] All new classes use constructor dependency injection
- [ ] `strict_types=1` on every PHP file
- [ ] No deprecated Drupal APIs used
- [ ] No `eval()`, `exec()`, or `shell_exec()` calls

### Tests
- [ ] Unit tests written for all new service methods
- [ ] Functional tests written for admin form changes
- [ ] Playwright spec updated for UI changes
- [ ] All existing tests still pass (CI green)
- [ ] New tests have meaningful assertions (not just `assertTrue(true)`)

### Documentation
- [ ] README.md updated if behavior changed
- [ ] CHANGELOG.md entry added under `[Unreleased]`
- [ ] Config schema updated if new config keys added
- [ ] hook_requirements() updated if new status checks needed

### Security
- [ ] All user input is validated/sanitized
- [ ] All output is properly encoded (`Html::escape()`)
- [ ] No SQL string concatenation (parameterized queries only)
- [ ] Permissions checked before sensitive operations
- [ ] CSRF protection maintained on all forms

---

## Testing Instructions

<!-- Steps for reviewers to test this PR manually -->

1. Enable module: `drush en [module_name]`
2. Navigate to: `Admin > Configuration > Security > [Module]`
3. ...

---

## Screenshots (if UI changes)

<!-- Add before/after screenshots for any admin UI changes -->

---

## Notes for Reviewers

<!-- Anything else the reviewer should know -->
