# CSP Wizard — Design Document

## Problem Statement

Modern Drupal sites routinely embed third-party scripts from Google Tag Manager, Stripe, YouTube, reCAPTCHA, and CKEditor5. Without a Content Security Policy (CSP), any Cross-Site Scripting (XSS) vulnerability allows an attacker to inject and execute arbitrary JavaScript, exfiltrating payment card data, hijacking sessions, or performing drive-by cryptomining.

Adding a strict CSP to an existing Drupal site is notoriously difficult for three reasons:

1. **Policy complexity** — Each third-party service requires a specific set of `script-src`, `connect-src`, `frame-src`, and `img-src` directives. Getting these wrong either breaks functionality or leaves the policy too permissive to offer meaningful protection.
2. **Inline script collisions** — Drupal core, contributed modules, and themes routinely emit inline `<script>` blocks. A strict CSP that bans `unsafe-inline` breaks these immediately. The correct fix — attaching a cryptographic nonce to every inline block — requires changes across the entire render pipeline.
3. **Compliance pressure** — PCI DSS v4.0 Requirement 6.4.3 (effective April 1, 2025) mandates that all scripts on payment pages be explicitly authorized, their integrity verified, and a complete inventory maintained. Organisations that process card-not-present transactions must satisfy this requirement or face assessment failure.

No single Drupal contributed module addresses all three problems in a guided, wizard-driven workflow. The existing `seckit` module exposes a flat configuration form; the `csp` module requires deep policy knowledge; neither provides a PCI DSS compliance mode or an audit sub-module that scans installed modules for `unsafe-inline` usage.

CSP Wizard fills this gap by providing:
- A guided, step-by-step UI that asks about active third-party services and generates a tailored policy.
- A `NonceGeneratorService` that produces a cryptographically random nonce per request and injects it into every inline script in the render pipeline.
- An on-site Report-URI endpoint that logs CSP violations to Drupal's watchdog.
- A `Report-Only` mode for safe policy rollout without blocking anything.
- A `csp_audit` sub-module that inspects installed module source code for `unsafe-inline` patterns and surfaces actionable findings.
- A PCI DSS 6.4.3 compliance mode that enforces nonce coverage on all checkout and payment pages.

---

## Solution Overview

CSP Wizard is a Drupal 11 module suite (machine name `csp_wizard`) composed of three packages:

| Package | Machine name | Purpose |
|---|---|---|
| Core wizard | `csp_wizard` | Policy wizard UI, nonce service, response subscriber, violation endpoint |
| Audit sub-module | `csp_audit` | Static scan of installed module files for `unsafe-inline` |
| (optional) SecKit bridge | `csp_wizard_seckit` | Thin integration layer that copies the generated policy into SecKit's config |

### High-level data flow

```
Admin completes wizard
        |
        v
Config saved: csp_wizard.settings
        |
        v
Per-request flow:
  1. NonceGeneratorService::getNonce()  [called once per request, cached in RequestStack]
  2. CspResponseSubscriber::onResponse()  [KernelEvents::RESPONSE]
     - Builds Content-Security-Policy header from saved config + current nonce
     - Writes header to Symfony Response object
  3. hook_page_attachments_alter()
     - Injects nonce value into drupalSettings and #attached html_tag elements
  4. #pre_render callbacks on html_tag elements of type "script"
     - Stamps nonce="<value>" attribute on every inline script tag
```

Violation reports submitted by browsers hit `/csp-wizard/report` (a JSON endpoint), are decoded, sanitised, and written to `watchdog` under the `csp_wizard` channel.

---

## User Stories

1. As a site administrator, I want a step-by-step wizard that asks which third-party services my site uses so that the resulting CSP policy is correct without requiring me to understand CSP directive syntax.
2. As a site administrator, I want to enable Report-Only mode so that I can observe what would be blocked before switching to enforcement mode.
3. As a security engineer, I want every inline script on the page to carry a server-generated nonce so that an attacker who injects a `<script>` block cannot execute it.
4. As a site administrator, I want CSP violation reports logged to Drupal's database log (dblog) so that I can monitor blocked resources from the standard Reports UI.
5. As a compliance officer, I want a PCI DSS 6.4.3 mode that restricts the generated policy to payment-related page patterns and enforces nonce coverage on every script so that audit evidence can be exported.
6. As a developer, I want a `csp_audit` report page that lists all enabled modules that emit `unsafe-inline` so that I can prioritise remediation work.
7. As a site administrator, I want the wizard to generate a ready-to-use policy for CKEditor5 so that the editor continues to function after enabling enforcement mode.
8. As a DevOps engineer, I want the generated CSP stored as exportable configuration (CMI) so that it can be deployed through a standard config-split/config-export pipeline.
9. As a site administrator, I want to add custom `script-src`, `style-src`, and other directives beyond the wizard's presets so that bespoke integrations are not broken.
10. As a security engineer, I want the SecKit integration bridge to automatically copy the wizard's policy into SecKit's configuration so that I do not need to maintain two sources of truth.

---

## Feature List

### F-01: Multi-step Wizard UI
- Six wizard steps rendered via `FormBase` with `$form_state->set('step', ...)` state management.
- Step 1 — Introduction and mode selection (Enforce / Report-Only).
- Step 2 — Select active third-party services (checkboxes: CKEditor5, Google Tag Manager, Stripe, YouTube, reCAPTCHA v2/v3, custom domain freetext).
- Step 3 — Nonce settings (enable nonce injection, fallback to `unsafe-inline` if nonce cannot be added, nonce entropy: 128/192/256 bits).
- Step 4 — Violation reporting (Report-URI endpoint on/off, external SIEM webhook URL, flood-control threshold).
- Step 5 — PCI DSS 6.4.3 mode (on/off, page path patterns for payment pages, script inventory export format).
- Step 6 — Review and save (shows the full computed header value, confirm save).
- Each step validates independently; "Back" preserves entered values via `$form_state`.

### F-02: Policy Builder Service (`CspPolicyBuilderService`)
- Takes the saved wizard config and assembles directive arrays.
- Built-in profiles for each supported service (see Configuration Options below).
- `strict-dynamic` added to `script-src` when nonce mode is active and GTM is selected.
- Returns a fully serialised CSP header string ready for output.

### F-03: NonceGeneratorService
- Generates a nonce using `random_bytes(32)` (PHP 7+), Base64url-encoded without padding.
- Nonce is stored on the current `RequestStack` as a request attribute (`_csp_wizard_nonce`), ensuring it is generated exactly once per request.
- Provides `getNonce(): string` and `resetNonce(): void` (for test environments only).
- The nonce value is NOT stored in the session or cache.

### F-04: CSP Response Subscriber
- Implements `EventSubscriberInterface`, subscribes to `KernelEvents::RESPONSE` at priority `-10` (after page is assembled, before it is sent).
- Skips non-HTML responses (`application/json`, file downloads, etc.) by checking `Content-Type`.
- Reads policy from `CspPolicyBuilderService::buildHeader()` and writes it to `$response->headers->set('Content-Security-Policy', ...)` (or `Content-Security-Policy-Report-Only` when in Report-Only mode).
- Also writes the `Reporting-Endpoints` header when Report-To is configured (Reporting API Level 1, supported by Chrome/Edge 96+).

### F-05: Nonce Injection via `hook_page_attachments_alter`
- Retrieves the per-request nonce from `NonceGeneratorService`.
- Injects it into `$attachments['#attached']['drupalSettings']['cspWizard']['nonce']` so JavaScript can use it when creating dynamic script elements.
- Iterates `$attachments['#attached']['html_head']` and, for every element whose `#tag` is `script` and which lacks a `src` attribute (i.e., inline), adds `nonce` to `#attributes`.

### F-06: `#pre_render` Callback on `html_tag` Elements
- Provides a static pre-render callback `CspWizardInlineScript::preRenderAddNonce(array $element): array`.
- Registered on Drupal core's `html_tag` render element via `hook_element_info_alter()`.
- The callback checks: `$element['#tag'] === 'script'` and no `src` attribute present.
- Stamps `$element['#attributes']['nonce'] = NonceGeneratorService::getNonce()`.
- Fully cache-safe: the nonce is applied during render, after the page cache check.

### F-07: Report-URI Violation Endpoint
- Route: `GET /csp-wizard/report` (HTML info page) and `POST /csp-wizard/report` (violation receiver).
- Controller parses the JSON body (`application/csp-report` MIME type, W3C CSP Level 2 format, and `application/reports+json` for Reporting API Level 1).
- Applies flood control: max N reports per IP per minute (configurable, default 60).
- Logs to `\Drupal::logger('csp_wizard')->warning(...)` with structured fields: `blocked-uri`, `violated-directive`, `document-uri`, `source-file`, `line-number`, `script-sample`.
- Optionally forwards the raw payload to an external SIEM webhook URL via Guzzle with a 2-second timeout.
- Report-URI endpoint URL is auto-configured in the generated CSP header (`report-uri /csp-wizard/report; report-to csp-wizard-endpoint`).

### F-08: Report-Only Mode
- Controlled by `csp_wizard.settings:report_only` (boolean).
- When true, the response subscriber writes `Content-Security-Policy-Report-Only` instead of `Content-Security-Policy`.
- Admin UI shows a visible amber banner ("Report-Only mode active — policy is not being enforced").
- Switching from Report-Only to Enforce is a one-click toggle with a confirmation dialog (`data-drupal-confirm`).

### F-09: PCI DSS 6.4.3 Compliance Mode
- When enabled, the module:
  - Applies a separate, stricter policy only on paths matching the configured payment page patterns (e.g., `/checkout/**`, `/cart/**`, `/user/*/payment`).
  - Enforces `require-trusted-types-for 'script'` where browser support exists.
  - Exports an on-demand script inventory report (CSV or JSON) that lists every `script-src` origin in the policy with its authorisation rationale, satisfying PCI DSS 6.4.3 inventory requirement.
  - Adds `subresource-integrity` validation guidance as a configuration recommendation.
- The stricter payment-page policy is maintained as a separate config object (`csp_wizard.payment_policy`) to keep it distinct from the site-wide policy.

### F-10: `csp_audit` Sub-module
- Provides an admin report page at `/admin/reports/csp-audit`.
- On first load (or after manual re-scan), iterates all enabled modules via `\Drupal::moduleHandler()->getModuleList()`.
- For each module, scans `.js` files under `<module>/js/` for the string `unsafe-inline` and `.php` files for `#attached['html_head']` arrays containing inline script patterns (`#tag' => 'script'` without `src`).
- Groups findings by module, severity (error / warning), and file path.
- Caches scan results in a dedicated cache bin (`cache.csp_audit`) with a 1-hour TTL.
- Provides a "Re-scan" action that clears the cache and reruns the scan.
- Findings are exportable as CSV for inclusion in security review artefacts.
- Known-safe list: a config form at `/admin/config/security/csp-wizard/audit-allowlist` lets maintainers mark modules as reviewed and exempt.

### F-11: SecKit Integration Bridge (`csp_wizard_seckit` optional sub-module)
- When both `seckit` and `csp_wizard_seckit` are enabled, a `ConfigEvents::SAVE` subscriber detects saves to `csp_wizard.settings`.
- Reads the generated CSP header string and writes it into `seckit.settings:csp.policy-uri` (or the appropriate SecKit config key).
- Prevents double-header: when the bridge is active, the CSP Wizard response subscriber skips writing the `Content-Security-Policy` header, deferring to SecKit.

### F-12: Configuration Management (CMI) Integration
- All settings stored in `csp_wizard.settings` simple config.
- Payment policy stored in `csp_wizard.payment_policy` simple config.
- Third-party service profiles stored in `csp_wizard.service_profiles` config (importable/exportable per environment).
- Module ships with `config/install/` defaults for a safe starter policy.

---

## Security Considerations

### SC-01: Nonce entropy and uniqueness
The nonce is 32 bytes from `random_bytes()` (PHP CSPRNG, backed by OS entropy: `/dev/urandom` on Linux, `CryptGenRandom` on Windows). Base64url-encoded, this yields 43 characters. The probability of collision across concurrent requests is negligible (birthday bound: ~2^128 after 2^64 requests). The nonce is never logged, never stored in a cookie, and never written to a cache backend.

### SC-02: Preventing nonce downgrade
If another module or theme forces `unsafe-inline` into `script-src`, a nonce loses its protective value (browsers ignore nonces when `unsafe-inline` is also present). The Policy Builder Service detects this and emits a `\Drupal::messenger()->addWarning()` alert in the admin UI. It also logs a watchdog entry at the `warning` level.

### SC-03: Report endpoint abuse / DoS
The violation report endpoint is a publicly-accessible POST route. Without flood control, an attacker can spam it to fill the dblog table. The module applies `\Drupal::flood()->register('csp_wizard_report', $config->get('flood.window'))` and returns HTTP 429 when the threshold is exceeded. Maximum request body size is capped at 4 KB (the endpoint rejects larger payloads with HTTP 413).

### SC-04: XSS in violation reports
Logged fields (`blocked-uri`, `source-file`, `script-sample`) are passed through `Html::escape()` before reaching `\Drupal::logger()` to prevent log-injection attacks when reports are rendered in the dblog UI.

### SC-05: CSP header injection
The policy string is built from structured config values (arrays of allowed origins) rather than free-form text fields, minimising header-injection risk. Custom domain inputs are validated against a strict allowlist regex (`^[a-zA-Z0-9\-\.\:\_\*\/]+$`). A `Content-Security-Policy` value that contains newline characters (`\r\n`) will cause the response subscriber to throw an `\InvalidArgumentException` and fall back to an empty policy rather than output a malformed header.

### SC-06: `strict-dynamic` and hash-based fallback
When GTM is active with nonce mode, `strict-dynamic` is appended to `script-src`. Older browsers that do not support `strict-dynamic` will still see the explicit `https://www.googletagmanager.com` host source as a fallback, because CSP Level 2 browsers ignore `strict-dynamic` and evaluate host sources.

### SC-07: Trusted Types (forward compatibility)
The PCI DSS compliance mode adds `require-trusted-types-for 'script'` to the payment-page policy. This is a CSP Level 3 directive and is currently supported in Chromium-based browsers only. The wizard notes this limitation in the UI and does not enable it in the site-wide policy by default.

### SC-08: Sub-resource Integrity guidance
The wizard's review step displays a recommendation to add `integrity` attributes to external script tags when third-party CDN sources are included. The module does not enforce SRI automatically (that is out of scope), but it links to Drupal.org documentation on the Libraries API SRI support.

---

## Drupal Implementation Notes

### Module structure

```
csp_wizard/
  csp_wizard.info.yml
  csp_wizard.services.yml
  csp_wizard.routing.yml
  csp_wizard.permissions.yml
  csp_wizard.links.menu.yml
  csp_wizard.module              # hook implementations
  config/
    install/
      csp_wizard.settings.yml
      csp_wizard.payment_policy.yml
      csp_wizard.service_profiles.yml
    schema/
      csp_wizard.schema.yml
  src/
    Form/
      CspWizardForm.php          # multi-step wizard (FormBase)
      CspWizardSettingsForm.php  # quick-edit outside the wizard
      CspAuditAllowlistForm.php
    Service/
      NonceGeneratorService.php
      CspPolicyBuilderService.php
    EventSubscriber/
      CspResponseSubscriber.php
      CspSecKitBridgeSubscriber.php  # (in csp_wizard_seckit)
    Controller/
      CspReportController.php
      CspAuditController.php
    Render/
      CspWizardInlineScript.php  # pre_render callback
  modules/
    csp_audit/
      csp_audit.info.yml
      csp_audit.routing.yml
      csp_audit.links.menu.yml
      src/
        Scanner/
          ModuleScanner.php
        Controller/
          CspAuditReportController.php
    csp_wizard_seckit/
      csp_wizard_seckit.info.yml
      csp_wizard_seckit.services.yml
      src/
        EventSubscriber/
          CspSecKitBridgeSubscriber.php
```

### Key hooks

| Hook | Location | Purpose |
|---|---|---|
| `hook_page_attachments_alter` | `csp_wizard.module` | Inject nonce into `drupalSettings` and `html_head` inline scripts |
| `hook_element_info_alter` | `csp_wizard.module` | Append `CspWizardInlineScript::preRenderAddNonce` to `#pre_render` on `html_tag` |
| `hook_requirements` | `csp_wizard.module` | Status report: current mode, last violation timestamp, audit findings summary |
| `hook_help` | `csp_wizard.module` | Contextual help text per route |

### Services

```yaml
# csp_wizard.services.yml
services:
  csp_wizard.nonce_generator:
    class: Drupal\csp_wizard\Service\NonceGeneratorService
    arguments: ['@request_stack']

  csp_wizard.policy_builder:
    class: Drupal\csp_wizard\Service\CspPolicyBuilderService
    arguments: ['@config.factory', '@csp_wizard.nonce_generator', '@module_handler']

  csp_wizard.response_subscriber:
    class: Drupal\csp_wizard\EventSubscriber\CspResponseSubscriber
    arguments: ['@config.factory', '@csp_wizard.policy_builder']
    tags:
      - { name: event_subscriber }

  csp_wizard.report_controller:
    class: Drupal\csp_wizard\Controller\CspReportController
    arguments: ['@config.factory', '@logger.factory', '@flood', '@http_client']
    tags:
      - { name: controller.service_arguments }
```

### NonceGeneratorService implementation pattern

```php
class NonceGeneratorService {
  public function __construct(private RequestStack $requestStack) {}

  public function getNonce(): string {
    $request = $this->requestStack->getCurrentRequest();
    if (!$request->attributes->has('_csp_wizard_nonce')) {
      $nonce = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
      $request->attributes->set('_csp_wizard_nonce', $nonce);
    }
    return $request->attributes->get('_csp_wizard_nonce');
  }
}
```

### CspResponseSubscriber pattern

```php
public function onResponse(ResponseEvent $event): void {
  $response = $event->getResponse();
  // Skip non-HTML responses.
  $contentType = $response->headers->get('Content-Type', '');
  if (!str_contains($contentType, 'text/html')) {
    return;
  }
  $header = $this->policyBuilder->buildHeader();
  $headerName = $this->config->get('report_only')
    ? 'Content-Security-Policy-Report-Only'
    : 'Content-Security-Policy';
  $response->headers->set($headerName, $header);
}

public static function getSubscribedEvents(): array {
  return [KernelEvents::RESPONSE => ['onResponse', -10]];
}
```

### hook_page_attachments_alter pattern

```php
function csp_wizard_page_attachments_alter(array &$attachments): void {
  $nonce = \Drupal::service('csp_wizard.nonce_generator')->getNonce();
  // Expose nonce to JavaScript for dynamic script creation.
  $attachments['#attached']['drupalSettings']['cspWizard']['nonce'] = $nonce;
  // Stamp nonce on inline html_head script elements.
  if (!empty($attachments['#attached']['html_head'])) {
    foreach ($attachments['#attached']['html_head'] as &$element) {
      if (isset($element[0]['#tag']) && $element[0]['#tag'] === 'script'
          && empty($element[0]['#attributes']['src'])) {
        $element[0]['#attributes']['nonce'] = $nonce;
      }
    }
  }
}
```

### hook_element_info_alter pattern

```php
function csp_wizard_element_info_alter(array &$types): void {
  if (isset($types['html_tag'])) {
    $types['html_tag']['#pre_render'][] = [
      CspWizardInlineScript::class, 'preRenderAddNonce'
    ];
  }
}
```

### Report endpoint route

```yaml
# csp_wizard.routing.yml
csp_wizard.report:
  path: '/csp-wizard/report'
  defaults:
    _controller: '\Drupal\csp_wizard\Controller\CspReportController::receive'
    _title: 'CSP Violation Report'
  methods: [POST]
  requirements:
    _access: 'TRUE'
  options:
    _auth: []
    no_cache: TRUE
```

### Dynamic Page Cache compatibility
The nonce placeholder approach follows the same pattern used by Drupal core's BigPipe: the initial render uses a placeholder (`'#NONCE_PLACEHOLDER#'`), which is substituted with the real nonce in a post-render step outside the cache boundary. This allows full compatibility with the Dynamic Page Cache.

---

## Configuration Options

All options live in `csp_wizard.settings` unless noted.

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `report_only` | `enforce` or `report_only` |
| `nonce_enabled` | boolean | `true` | Enable per-request nonce injection |
| `nonce_bits` | integer | `256` | Nonce entropy in bits (128, 192, or 256) |
| `nonce_fallback` | string | `unsafe-inline` | Fallback `script-src` value when nonce cannot be applied |
| `report_uri_enabled` | boolean | `true` | Enable on-site violation report endpoint |
| `report_uri_path` | string | `/csp-wizard/report` | Path of the report endpoint |
| `report_siem_url` | string | `''` | External SIEM webhook URL (empty = disabled) |
| `flood_limit` | integer | `60` | Maximum violation reports per IP per minute |
| `flood_window` | integer | `60` | Flood control window in seconds |
| `services.ckeditor5` | boolean | `false` | Include CKEditor5 CSP directives |
| `services.gtm` | boolean | `false` | Include Google Tag Manager directives |
| `services.stripe` | boolean | `false` | Include Stripe.js directives |
| `services.youtube` | boolean | `false` | Include YouTube embed directives |
| `services.recaptcha_v2` | boolean | `false` | Include reCAPTCHA v2 directives |
| `services.recaptcha_v3` | boolean | `false` | Include reCAPTCHA v3 directives |
| `services.custom_domains` | sequence | `[]` | Free-form additional allowed origins |
| `directives.default_src` | sequence | `['self']` | Extra `default-src` origins |
| `directives.script_src` | sequence | `[]` | Extra `script-src` origins |
| `directives.style_src` | sequence | `[]` | Extra `style-src` origins |
| `directives.img_src` | sequence | `['self', 'data:']` | Extra `img-src` origins |
| `directives.connect_src` | sequence | `['self']` | Extra `connect-src` origins |
| `directives.frame_src` | sequence | `[]` | Extra `frame-src` origins |
| `directives.font_src` | sequence | `['self']` | Extra `font-src` origins |
| `directives.object_src` | sequence | `['none']` | `object-src` value |
| `directives.base_uri` | sequence | `['self']` | `base-uri` value |
| `directives.form_action` | sequence | `['self']` | `form-action` value |
| `directives.frame_ancestors` | sequence | `['none']` | `frame-ancestors` value |
| `directives.upgrade_insecure` | boolean | `true` | Include `upgrade-insecure-requests` |
| `pci_mode.enabled` | boolean | `false` | Enable PCI DSS 6.4.3 compliance mode |
| `pci_mode.page_patterns` | sequence | `['/checkout/**', '/cart/**']` | Path patterns treated as payment pages |
| `pci_mode.export_format` | string | `csv` | Script inventory export format (`csv` or `json`) |
| `pci_mode.trusted_types` | boolean | `false` | Add `require-trusted-types-for 'script'` |
| `seckit_bridge` | boolean | `false` | Sync policy to SecKit (requires `csp_wizard_seckit`) |

Payment-page-specific overrides live in `csp_wizard.payment_policy` with the same `directives.*` structure as above, applied only to paths matching `pci_mode.page_patterns`.

`csp_wizard.service_profiles` stores the canonical CSP directives for each supported service and can be overridden via config split per environment.

---

## Composer Dependencies

| Package | Version constraint | Purpose |
|---|---|---|
| _(none required beyond Drupal core)_ | — | PHP `random_bytes()` is part of core PHP 7+; no polyfill needed |

Optional, pulled in only when specific features are enabled:

| Package | Version constraint | Purpose |
|---|---|---|
| `guzzlehttp/guzzle` | `^7.0` | SIEM webhook forwarding (already a Drupal core dependency via `drupal/core`) |

The module deliberately has no required Composer dependencies beyond Drupal core to minimise installation friction. All crypto operations use PHP standard library functions.

---

## Integration Points

### SecKit (`drupal/seckit`)
When the `csp_wizard_seckit` sub-module is enabled, the generated CSP is written into SecKit's configuration on every wizard save. The CSP Wizard response subscriber detects SecKit's presence and yields header control to it, preventing duplicate or conflicting `Content-Security-Policy` headers.

### Drupal core CSP module (`drupal/csp`)
If the community `csp` module is installed alongside CSP Wizard, the wizard detects this via `\Drupal::moduleHandler()->moduleExists('csp')` and emits a status warning recommending administrators disable one of the two modules to avoid conflicting headers. Integration mode (where CSP Wizard populates the `csp` module's policy via the `PolicyAlterEvent` rather than writing its own header) is a planned Phase 2 feature.

### CKEditor5 (`drupal/ckeditor5`, Drupal core)
CKEditor5 requires `script-src 'self' https://cdn.ckeditor.com` and `style-src 'self' 'unsafe-inline'` for the classic build. The wizard's CKEditor5 profile adds these directives and also adds a `nonce` to the CKEditor5 initialisation inline script via `hook_page_attachments_alter`.

### Google Tag Manager
GTM requires `script-src https://www.googletagmanager.com 'nonce-<value>' 'strict-dynamic'` and `connect-src https://www.google-analytics.com https://analytics.google.com`. When nonce mode is active, `strict-dynamic` is included so GTM-loaded child scripts are automatically trusted.

### Stripe
Stripe.js requires `script-src https://js.stripe.com`, `frame-src https://js.stripe.com https://hooks.stripe.com`, and `connect-src https://api.stripe.com`. The PCI DSS mode automatically selects the most restrictive Stripe domain set.

### YouTube Embeds
YouTube requires `frame-src https://www.youtube.com https://www.youtube-nocookie.com` and `img-src https://i.ytimg.com`. The privacy-enhanced `youtube-nocookie.com` domain is preferred.

### reCAPTCHA v2 / v3
reCAPTCHA requires `script-src https://www.google.com https://www.gstatic.com`, `frame-src https://www.google.com`, and `style-src https://www.gstatic.com`.

### Drupal Flood API
The violation report endpoint uses `\Drupal::flood()` (the `flood` service) for rate limiting, consistent with Drupal core's approach in `user.module` and other security-sensitive routes.

### Drupal Watchdog / DBLog
Violation records are written via the standard `LoggerChannelFactoryInterface` with channel `csp_wizard`. Site administrators can filter the dblog report by channel to view only CSP violations. Log entries include severity `RfcLogLevel::WARNING`.

### Drupal Permissions / RBAC
- `administer csp wizard` — Full wizard and settings access (grant to Site Administrator role).
- `view csp violations` — View the violation log report without configuration access.
- `administer csp audit` — Access the `csp_audit` report and allowlist configuration.

### Reporting API (W3C)
The violation endpoint accepts both `application/csp-report` (CSP Level 2, legacy) and `application/reports+json` (Reporting API Level 1, Chrome 96+). The `Reporting-Endpoints` HTTP header is written alongside the CSP header when `report_uri_enabled` is true, directing the newer format to the same endpoint URL.
