# CSP Wizard — Architecture

## Module Structure

```
csp_wizard/
├── composer.json                                   # Module-level composer metadata; no required deps beyond drupal/core
├── csp_wizard.info.yml                             # Module metadata, package: Security, core_version_requirement: ^11 || ^10.4
├── csp_wizard.module                               # Minimal stub; delegates hook_page_attachments_alter, hook_element_info_alter, hook_requirements, hook_help to OOP hooks class
├── csp_wizard.services.yml                         # All service, event_subscriber, logger, and hooks service definitions
├── csp_wizard.routing.yml                          # All admin, wizard, report, and API routes
├── csp_wizard.permissions.yml                      # Three permissions: administer csp wizard, view csp violations, administer csp audit
├── csp_wizard.links.menu.yml                       # Admin menu links under admin/config/security
├── config/
│   ├── install/
│   │   ├── csp_wizard.settings.yml                 # Default values: report_only mode, nonce enabled, flood limits, empty service selections
│   │   ├── csp_wizard.payment_policy.yml           # Stricter payment-page directive defaults (PCI DSS mode)
│   │   └── csp_wizard.service_profiles.yml         # Built-in CSP directive profiles for CKEditor5, GTM, Stripe, YouTube, reCAPTCHA v2/v3
│   └── schema/
│       └── csp_wizard.schema.yml                   # Config schema for all three config objects
└── src/
    ├── Hook/
    │   └── CspWizardHooks.php                      # OOP hook class tagged drupal.hook; implements hook_page_attachments_alter, hook_element_info_alter, hook_requirements, hook_help
    ├── Form/
    │   ├── CspWizardForm.php                       # Six-step wizard using FormBase + $form_state step management
    │   ├── CspSettingsForm.php                     # ConfigFormBase quick-edit form outside the wizard
    │   └── CspAuditAllowlistForm.php               # ConfigFormBase for marking modules as known-safe in csp_audit
    ├── Service/
    │   ├── NonceGeneratorService.php               # Generates and caches per-request nonce on RequestStack attribute
    │   ├── CspPolicyBuilderService.php             # Assembles directive arrays from config + service profiles; returns header string
    │   └── CspViolationLogger.php                  # Sanitises and writes violation report fields to watchdog; optional SIEM forwarding
    ├── EventSubscriber/
    │   └── CspHeaderSubscriber.php                 # KernelEvents::RESPONSE at priority -10; writes CSP header to HTML responses
    ├── Controller/
    │   └── CspReportController.php                 # POST /csp-wizard/report; flood control; parses csp-report and reports+json
    ├── Render/
    │   └── CspWizardInlineScript.php               # Static pre_render callback that stamps nonce attribute on inline html_tag script elements
    └── Value/
        └── CspViolationReport.php                  # Readonly value object carrying parsed violation report fields

modules/
├── csp_audit/
│   ├── csp_audit.info.yml                          # Sub-module metadata; depends on csp_wizard
│   ├── csp_audit.routing.yml                       # Routes for audit report page and re-scan action
│   ├── csp_audit.services.yml                      # ModuleScanner and CspAuditHooks service definitions
│   ├── csp_audit.links.menu.yml                    # Menu link under admin/reports
│   ├── config/
│   │   ├── install/
│   │   │   └── csp_audit.settings.yml              # Default scan settings: cache TTL 3600, empty allowlist
│   │   └── schema/
│   │       └── csp_audit.schema.yml                # Config schema for csp_audit.settings
│   └── src/
│       ├── Hook/
│       │   └── CspAuditHooks.php                   # hook_requirements for audit summary in status report
│       ├── Scanner/
│       │   └── ModuleScanner.php                   # Scans enabled-module .js and .php files for unsafe-inline patterns; caches 1 hour
│       └── Controller/
│           └── CspAuditReportController.php        # Renders grouped findings table; CSV export; triggers re-scan
└── csp_wizard_seckit/
    ├── csp_wizard_seckit.info.yml                  # Optional bridge sub-module; depends on csp_wizard and seckit
    ├── csp_wizard_seckit.services.yml              # CspSecKitBridgeSubscriber service definition
    └── src/
        └── EventSubscriber/
            └── CspSecKitBridgeSubscriber.php       # ConfigEvents::SAVE subscriber; copies generated policy into seckit.settings
```

### File-by-File Responsibilities

| File | Responsibility |
|---|---|
| `csp_wizard.info.yml` | Declares `name: 'CSP Wizard'`, `type: module`, `package: Security`, `core_version_requirement: ^11 \|\| ^10.4`, `configure: csp_wizard.settings`. No module dependencies beyond Drupal core. |
| `csp_wizard.module` | Thin stub file. Contains exactly four procedural functions, each a single-line delegation to `\Drupal::service('csp_wizard.hooks')`. Required because `hook_page_attachments_alter` and `hook_element_info_alter` are invoked by Drupal's hook discovery system, not the `#[Hook]` attribute path for legacy hooks. |
| `csp_wizard.services.yml` | Defines services: `csp_wizard.nonce_generator`, `csp_wizard.policy_builder`, `csp_wizard.violation_logger`, `csp_wizard.header_subscriber`, `csp_wizard.hooks`, `logger.channel.csp_wizard`. Tags the subscriber and hooks appropriately. |
| `csp_wizard.routing.yml` | Declares routes: `csp_wizard.settings`, `csp_wizard.wizard`, `csp_wizard.report` (POST), `csp_wizard.report_info` (GET), `csp_wizard.pci_export`, `csp_wizard.toggle_mode`. |
| `csp_wizard.permissions.yml` | Declares `administer csp wizard` (`restrict access: true`), `view csp violations`, and `administer csp audit`. |
| `csp_wizard.links.menu.yml` | Places `csp_wizard.settings` under `system.admin_config_security` at weight 10. Also adds a menu item for the wizard launch and, when `csp_audit` is enabled, the audit report under `system.admin_reports`. |
| `composer.json` | `name: drupal/csp_wizard`, `type: drupal-module`, `license: GPL-2.0-or-later`. Requires only `drupal/core: ^11 \|\| ^10.4`. Notes `guzzlehttp/guzzle: ^7.0` as a soft suggestion (already a Drupal core transitive dependency). PSR-4 autoload maps `Drupal\csp_wizard\` to `src/`. |
| `config/install/csp_wizard.settings.yml` | Ships defaults: `mode: report_only`, `nonce_enabled: true`, `nonce_bits: 256`, `report_uri_enabled: true`, `flood_limit: 60`, `flood_window: 60`, all service flags `false`, all custom directive sequences empty, PCI mode `false`. |
| `config/install/csp_wizard.payment_policy.yml` | Ships stricter default directives for payment pages: narrower `script-src`, `trusted_types: false`, empty `pci_page_patterns` (must be filled during wizard). |
| `config/install/csp_wizard.service_profiles.yml` | Canonical directive sets per service. Each profile entry is a mapping of directive names to sequences of allowed sources. These are the authoritative source consumed by `CspPolicyBuilderService`. |
| `config/schema/csp_wizard.schema.yml` | Full config schema for all three config objects. Types: `config_object`, `mapping`, `sequence`, `string`, `boolean`, `integer`. |
| `src/Hook/CspWizardHooks.php` | Implements `#[Hook('requirements')]`, `#[Hook('help')]`, `#[Hook('page_attachments_alter')]`, `#[Hook('element_info_alter')]`. Receives `NonceGeneratorService`, `ConfigFactoryInterface`, and `ModuleHandlerInterface` via constructor DI. |
| `src/Form/CspWizardForm.php` | `FormBase` six-step wizard. Each step is a separate `buildStepN()` private method. `$form_state->set('step', $n)` drives progression. "Back" re-populates form from `$form_state->get('wizard_values')`. Final step calls `CspPolicyBuilderService::buildHeader()` to preview the policy before save. |
| `src/Form/CspSettingsForm.php` | `ConfigFormBase` providing a flat settings form for administrators who have already run the wizard. Exposes mode toggle, flood settings, and SIEM URL fields without re-running all six steps. |
| `src/Form/CspAuditAllowlistForm.php` | `ConfigFormBase` at `admin/config/security/csp-wizard/audit-allowlist`. Presents a table of scanned modules with a per-module "mark as reviewed" checkbox. Saves the allowlist into `csp_audit.settings:allowlist`. |
| `src/Service/NonceGeneratorService.php` | `getNonce(): string` — reads `_csp_wizard_nonce` from the current request attribute; on miss, calls `random_bytes(32)` and stores it. `resetNonce(): void` — clears the attribute (test use only). Never touches session, cache, or config. |
| `src/Service/CspPolicyBuilderService.php` | Reads `csp_wizard.settings` and `csp_wizard.service_profiles`. Iterates enabled service flags, merges their profile directives into a directive array. Appends the nonce value from `NonceGeneratorService`. Applies `strict-dynamic` for GTM when nonce is enabled. Detects conflicting `unsafe-inline` presence and emits a messenger warning. Serialises directive array into a header string. Separate `buildPaymentHeader(): string` method for PCI paths. |
| `src/Service/CspViolationLogger.php` | Accepts a `CspViolationReport` value object. Passes fields through `Html::escape()`. Calls `$this->logger->warning()` with structured placeholders. Optionally POSTs the raw JSON payload to the configured SIEM webhook via the `http_client` service with a 2-second timeout and independent try/catch. |
| `src/EventSubscriber/CspHeaderSubscriber.php` | Subscribes to `KernelEvents::RESPONSE` at priority `-10`. Checks response `Content-Type` header; skips non-HTML. Reads `mode` from config to choose header name. Calls `CspPolicyBuilderService` to get the header string. Validates the string does not contain `\r` or `\n` before writing; falls back to an empty policy if it does. Also checks if the SecKit bridge is active and yields if so. |
| `src/Controller/CspReportController.php` | `receive(Request $request): Response`. Checks flood via `$this->flood->isAllowed('csp_wizard_report', ...)`. Rejects payloads larger than 4 KB with 413. Reads `Content-Type` to select parser: `application/csp-report` (CSP Level 2 JSON wrapper) or `application/reports+json` (Reporting API array). Passes parsed fields to `CspViolationLogger`. Returns HTTP 204 on success, 429 on flood, 400 on malformed body. |
| `src/Render/CspWizardInlineScript.php` | Provides a single `public static function preRenderAddNonce(array $element): array`. Checks `$element['#tag'] === 'script'` and no `src` attribute. Obtains nonce from `\Drupal::service('csp_wizard.nonce_generator')->getNonce()`. Stamps `$element['#attributes']['nonce']`. Returns modified element. |
| `src/Value/CspViolationReport.php` | `final readonly class` with typed properties: `documentUri`, `violatedDirective`, `blockedUri`, `sourceFile`, `lineNumber`, `columnNumber`, `scriptSample`, `statusCode`, `disposition`. Constructor accepts named arguments; all strings. |
| `modules/csp_audit/src/Scanner/ModuleScanner.php` | Iterates `$moduleHandler->getModuleList()`. For each module: scans `js/` directory for `*.js` files containing the literal string `unsafe-inline`. Scans `src/` and `*.module` PHP files for array patterns indicating inline script attachment without `src`. Groups findings by module and severity. Stores result in `cache.csp_audit` with a 1-hour TTL. |
| `modules/csp_audit/src/Controller/CspAuditReportController.php` | Loads scan results from `ModuleScanner`. Filters out modules in the allowlist. Renders a `#type => table` with sortable columns: Module, File, Pattern, Severity. Provides a "Re-scan" link that clears `cache.csp_audit`. Provides a CSV export download link that triggers `CsvExportResponse`. |
| `modules/csp_wizard_seckit/src/EventSubscriber/CspSecKitBridgeSubscriber.php` | Subscribes to `ConfigEvents::SAVE`. On save of `csp_wizard.settings`, calls `CspPolicyBuilderService::buildHeader()` and writes the result into `seckit.settings` via `config.factory`. Sets `csp_wizard.settings:seckit_bridge_active = true` so `CspHeaderSubscriber` knows to yield. |

---

## Service Definitions

### `csp_wizard.nonce_generator`

| Property | Value |
|---|---|
| Class | `Drupal\csp_wizard\Service\NonceGeneratorService` |
| Constructor args | `@request_stack` |
| Responsibility | Produces a cryptographically secure, Base64url-encoded nonce of 32 bytes (256 bits) per HTTP request. Uses the Symfony `RequestStack` `getCurrentRequest()->attributes` bag as a per-request cache. The nonce is generated at most once per request regardless of how many services call `getNonce()`. Never touches Drupal's cache API, session, or persistent storage. Exposes `resetNonce()` for test isolation only. |

```yaml
csp_wizard.nonce_generator:
  class: Drupal\csp_wizard\Service\NonceGeneratorService
  arguments:
    - '@request_stack'
```

### `csp_wizard.policy_builder`

| Property | Value |
|---|---|
| Class | `Drupal\csp_wizard\Service\CspPolicyBuilderService` |
| Constructor args | `@config.factory`, `@csp_wizard.nonce_generator`, `@module_handler`, `@messenger` |
| Responsibility | Reads `csp_wizard.settings` and `csp_wizard.service_profiles`. Iterates enabled service flags and merges per-service directive arrays from profiles. Appends `'nonce-{value}'` to `script-src` when nonce is enabled. Appends `'strict-dynamic'` when GTM is active and nonce mode is on. Validates no `unsafe-inline` coexists with a nonce (emits a messenger warning if detected). Serialises directive map into a valid CSP header string. Provides a separate `buildPaymentHeader(): string` method that reads `csp_wizard.payment_policy` and applies PCI-specific rules. |

```yaml
csp_wizard.policy_builder:
  class: Drupal\csp_wizard\Service\CspPolicyBuilderService
  arguments:
    - '@config.factory'
    - '@csp_wizard.nonce_generator'
    - '@module_handler'
    - '@messenger'
```

### `csp_wizard.violation_logger`

| Property | Value |
|---|---|
| Class | `Drupal\csp_wizard\Service\CspViolationLogger` |
| Constructor args | `@logger.channel.csp_wizard`, `@config.factory`, `@http_client` |
| Responsibility | Accepts a `CspViolationReport` value object. Passes all string fields through `Html::escape()` before logging. Writes a `RfcLogLevel::WARNING` watchdog entry to the `csp_wizard` channel with structured context placeholders. If `report_siem_url` is non-empty, POSTs the raw violation JSON to the SIEM URL via `http_client` with a 2-second connect and read timeout, catching all `GuzzleException` subclasses silently (SIEM forwarding is best-effort and must not break the report endpoint). |

```yaml
csp_wizard.violation_logger:
  class: Drupal\csp_wizard\Service\CspViolationLogger
  arguments:
    - '@logger.channel.csp_wizard'
    - '@config.factory'
    - '@http_client'
```

### `csp_wizard.header_subscriber`

| Property | Value |
|---|---|
| Class | `Drupal\csp_wizard\EventSubscriber\CspHeaderSubscriber` |
| Constructor args | `@config.factory`, `@csp_wizard.policy_builder`, `@module_handler` |
| Tags | `{name: event_subscriber}` |
| Responsibility | Listens to `KernelEvents::RESPONSE` at priority `-10`. Checks `Content-Type` header for `text/html`; skips all other responses. Reads `mode` from config and selects `Content-Security-Policy` or `Content-Security-Policy-Report-Only`. Calls `CspPolicyBuilderService::buildHeader()`. Guards against header injection by verifying the policy string contains no CR or LF characters. Writes `Reporting-Endpoints` header when Report-To is configured. Yields control to SecKit when `seckit_bridge_active` is true. |

```yaml
csp_wizard.header_subscriber:
  class: Drupal\csp_wizard\EventSubscriber\CspHeaderSubscriber
  arguments:
    - '@config.factory'
    - '@csp_wizard.policy_builder'
    - '@module_handler'
  tags:
    - { name: event_subscriber }
```

### `csp_wizard.hooks`

| Property | Value |
|---|---|
| Class | `Drupal\csp_wizard\Hook\CspWizardHooks` |
| Constructor args | `@csp_wizard.nonce_generator`, `@config.factory`, `@module_handler` |
| Tags | `{name: drupal.hook}` |
| Responsibility | Tagged OOP hook class. Implements `#[Hook('requirements')]` to surface current mode, last violation timestamp, and audit summary in the Drupal status report. Implements `#[Hook('help')]` for route-contextual module help. Implements `#[Hook('page_attachments_alter')]` to inject the nonce into `drupalSettings` and stamp inline `html_head` script elements. Implements `#[Hook('element_info_alter')]` to register `CspWizardInlineScript::preRenderAddNonce` on the `html_tag` render element. |

```yaml
csp_wizard.hooks:
  class: Drupal\csp_wizard\Hook\CspWizardHooks
  arguments:
    - '@csp_wizard.nonce_generator'
    - '@config.factory'
    - '@module_handler'
  tags:
    - { name: drupal.hook }
```

### `logger.channel.csp_wizard`

| Property | Value |
|---|---|
| Parent | `logger.channel_base` |
| Constructor args | `csp_wizard` (channel name string) |
| Responsibility | Named log channel for all watchdog entries emitted by the module (violation reports, policy warnings, SIEM forwarding errors). Visible under the `csp_wizard` channel filter in `admin/reports/dblog`. |

```yaml
logger.channel.csp_wizard:
  parent: logger.channel_base
  arguments: ['csp_wizard']
```

### `cache.csp_audit` (csp_audit sub-module)

| Property | Value |
|---|---|
| Interface | `Drupal\Core\Cache\CacheBackendInterface` |
| Factory | `cache_factory:get` with argument `csp_audit` |
| Tags | `{name: cache.bin}` |
| Responsibility | Dedicated cache bin for `ModuleScanner` scan results. Default TTL is 3600 seconds (1 hour). Cache is invalidated by the "Re-scan" button action. Backed by the site's default cache backend. |

```yaml
cache.csp_audit:
  class: Drupal\Core\Cache\CacheBackendInterface
  tags:
    - { name: cache.bin }
  factory: cache_factory:get
  arguments: [csp_audit]
```

### `csp_audit.module_scanner` (csp_audit sub-module)

| Property | Value |
|---|---|
| Class | `Drupal\csp_audit\Scanner\ModuleScanner` |
| Constructor args | `@module_handler`, `@config.factory`, `@cache.csp_audit`, `@logger.channel.csp_wizard` |
| Responsibility | On cache miss, iterates all enabled modules via `ModuleHandlerInterface::getModuleList()`. Opens each module's `js/` and `src/` directories via `\RecursiveDirectoryIterator`. Scans `.js` files for the literal string `unsafe-inline`. Scans `.php` and `.module` files for inline script attachment patterns (`#tag.*script` without `src`). Groups findings into `CspAuditFinding` value objects. Writes results to `cache.csp_audit` with a 3600-second TTL. |

```yaml
csp_audit.module_scanner:
  class: Drupal\csp_audit\Scanner\ModuleScanner
  arguments:
    - '@module_handler'
    - '@config.factory'
    - '@cache.csp_audit'
    - '@logger.channel.csp_wizard'
```

### `csp_wizard_seckit.bridge_subscriber` (csp_wizard_seckit sub-module)

| Property | Value |
|---|---|
| Class | `Drupal\csp_wizard_seckit\EventSubscriber\CspSecKitBridgeSubscriber` |
| Constructor args | `@config.factory`, `@csp_wizard.policy_builder`, `@module_handler` |
| Tags | `{name: event_subscriber}` |
| Responsibility | Subscribes to `ConfigEvents::SAVE`. Checks if the saved config name is `csp_wizard.settings`. When triggered, builds the full policy header string via `CspPolicyBuilderService::buildHeader()` and writes it into the appropriate `seckit.settings` CSP key. Sets `csp_wizard.settings:seckit_bridge_active = true` to signal `CspHeaderSubscriber` to skip writing its own `Content-Security-Policy` header. |

```yaml
csp_wizard_seckit.bridge_subscriber:
  class: Drupal\csp_wizard_seckit\EventSubscriber\CspSecKitBridgeSubscriber
  arguments:
    - '@config.factory'
    - '@csp_wizard.policy_builder'
    - '@module_handler'
  tags:
    - { name: event_subscriber }
```

---

## Plugin System

CSP Wizard does not define its own plugin types. It integrates with Drupal core's existing render element plugin system via `hook_element_info_alter` and provides the `CspWizardInlineScript` pre-render callback that attaches to the `html_tag` element type.

### Pre-render Callback — `CspWizardInlineScript::preRenderAddNonce`

| Property | Value |
|---|---|
| Class | `Drupal\csp_wizard\Render\CspWizardInlineScript` |
| Registered on | Drupal core `html_tag` render element type via `hook_element_info_alter` |
| Callback signature | `public static function preRenderAddNonce(array $element): array` |
| Trigger condition | `$element['#tag'] === 'script'` and `$element['#attributes']['src']` is not set |
| Operation | Calls `\Drupal::service('csp_wizard.nonce_generator')->getNonce()` and stamps the returned value as `$element['#attributes']['nonce']`. Returns the modified element array. |
| Cache safety | Because `hook_element_info_alter` is a compile-time hook (cached in the render element cache), the `#pre_render` callbacks list is stable. The nonce value itself is applied at render time, after the Dynamic Page Cache has been consulted, so it is never stored inside a cache entry. |

### Dynamic Page Cache Compatibility

For pages served from Dynamic Page Cache, the nonce placeholder strategy is used:

1. During the initial uncached render pass, `CspWizardInlineScript::preRenderAddNonce` stamps nonces normally. The nonce is unique per request, so cached pages that contain nonce values would be invalid.
2. To resolve this, the `CspPolicyBuilderService` detects when Dynamic Page Cache is active and uses a fixed placeholder string `'#NONCE_PLACEHOLDER#'` in the script tag attributes during the cache-stored render.
3. On a subsequent cached response delivery, a post-process step (a Symfony Response filter outside the cache boundary) replaces `#NONCE_PLACEHOLDER#` with the real per-request nonce value before the response is sent.
4. The `CspHeaderSubscriber` always calls `NonceGeneratorService::getNonce()` at response time (never from cache), ensuring the nonce in the HTTP header always matches the nonce substituted into the page body.

---

## Database Schema

CSP Wizard creates **no custom database tables**. All persistent state is managed through Drupal's standard subsystems:

- **Config API** — three `config_object` items (`csp_wizard.settings`, `csp_wizard.payment_policy`, `csp_wizard.service_profiles`) stored in the standard `config` table.
- **Cache API** — `cache.csp_audit` bin backed by `cache_csp_audit` table (when using DatabaseBackend) for scan results; managed automatically by the cache factory.
- **Watchdog (DBLog)** — violation reports written to the standard `watchdog` table via the `LoggerChannelFactoryInterface`. No custom schema; DBLog creates and manages this table.
- **Flood API** — flood entries written to the standard `flood` table via `\Drupal\Core\Flood\FloodInterface`. No custom schema required.

There is no `hook_schema()` implementation. No `csp_wizard.install` file is required.

---

## Config Schema

### `csp_wizard.settings`

File: `config/schema/csp_wizard.schema.yml`

```yaml
csp_wizard.settings:
  type: config_object
  label: 'CSP Wizard settings'
  mapping:
    mode:
      type: string
      label: 'CSP mode (enforce or report_only)'
    nonce_enabled:
      type: boolean
      label: 'Enable per-request nonce injection'
    nonce_bits:
      type: integer
      label: 'Nonce entropy in bits (128, 192, or 256)'
    nonce_fallback:
      type: string
      label: 'Fallback script-src value when nonce unavailable'
    report_uri_enabled:
      type: boolean
      label: 'Enable on-site violation report endpoint'
    report_uri_path:
      type: string
      label: 'Path of the report endpoint'
    report_siem_url:
      type: string
      label: 'External SIEM webhook URL for violation forwarding'
    flood_limit:
      type: integer
      label: 'Maximum violation reports per IP per flood window'
    flood_window:
      type: integer
      label: 'Flood control window in seconds'
    seckit_bridge_active:
      type: boolean
      label: 'Whether SecKit bridge has taken over header control'
    services:
      type: mapping
      label: 'Third-party service toggles'
      mapping:
        ckeditor5:
          type: boolean
          label: 'Include CKEditor5 CSP directives'
        gtm:
          type: boolean
          label: 'Include Google Tag Manager directives'
        stripe:
          type: boolean
          label: 'Include Stripe.js directives'
        youtube:
          type: boolean
          label: 'Include YouTube embed directives'
        recaptcha_v2:
          type: boolean
          label: 'Include reCAPTCHA v2 directives'
        recaptcha_v3:
          type: boolean
          label: 'Include reCAPTCHA v3 directives'
        custom_domains:
          type: sequence
          label: 'Additional custom allowed origins'
          sequence:
            type: string
            label: 'Domain or origin'
    directives:
      type: mapping
      label: 'Extra CSP directive origins beyond service profiles'
      mapping:
        default_src:
          type: sequence
          label: 'Extra default-src origins'
          sequence:
            type: string
        script_src:
          type: sequence
          label: 'Extra script-src origins'
          sequence:
            type: string
        style_src:
          type: sequence
          label: 'Extra style-src origins'
          sequence:
            type: string
        img_src:
          type: sequence
          label: 'Extra img-src origins'
          sequence:
            type: string
        connect_src:
          type: sequence
          label: 'Extra connect-src origins'
          sequence:
            type: string
        frame_src:
          type: sequence
          label: 'Extra frame-src origins'
          sequence:
            type: string
        font_src:
          type: sequence
          label: 'Extra font-src origins'
          sequence:
            type: string
        object_src:
          type: sequence
          label: 'object-src values'
          sequence:
            type: string
        base_uri:
          type: sequence
          label: 'base-uri values'
          sequence:
            type: string
        form_action:
          type: sequence
          label: 'form-action values'
          sequence:
            type: string
        frame_ancestors:
          type: sequence
          label: 'frame-ancestors values'
          sequence:
            type: string
        upgrade_insecure:
          type: boolean
          label: 'Include upgrade-insecure-requests directive'
    pci_mode:
      type: mapping
      label: 'PCI DSS 6.4.3 compliance mode settings'
      mapping:
        enabled:
          type: boolean
          label: 'Enable PCI DSS compliance mode'
        page_patterns:
          type: sequence
          label: 'URL path patterns for payment pages'
          sequence:
            type: string
        export_format:
          type: string
          label: 'Script inventory export format (csv or json)'
        trusted_types:
          type: boolean
          label: 'Add require-trusted-types-for directive'
```

### `csp_wizard.payment_policy`

```yaml
csp_wizard.payment_policy:
  type: config_object
  label: 'CSP Wizard payment page policy'
  mapping:
    directives:
      type: mapping
      label: 'Stricter directive overrides for payment pages'
      mapping:
        default_src:
          type: sequence
          label: 'default-src origins'
          sequence:
            type: string
        script_src:
          type: sequence
          label: 'script-src origins'
          sequence:
            type: string
        style_src:
          type: sequence
          label: 'style-src origins'
          sequence:
            type: string
        img_src:
          type: sequence
          label: 'img-src origins'
          sequence:
            type: string
        connect_src:
          type: sequence
          label: 'connect-src origins'
          sequence:
            type: string
        frame_src:
          type: sequence
          label: 'frame-src origins'
          sequence:
            type: string
        object_src:
          type: sequence
          label: 'object-src values'
          sequence:
            type: string
        trusted_types_policy_names:
          type: sequence
          label: 'Trusted Types policy name allowlist'
          sequence:
            type: string
```

### `csp_wizard.service_profiles`

```yaml
csp_wizard.service_profiles:
  type: config_object
  label: 'CSP Wizard built-in service directive profiles'
  mapping:
    ckeditor5:
      type: mapping
      label: 'CKEditor5 profile'
      mapping:
        script_src:
          type: sequence
          sequence:
            type: string
        style_src:
          type: sequence
          sequence:
            type: string
    gtm:
      type: mapping
      label: 'Google Tag Manager profile'
      mapping:
        script_src:
          type: sequence
          sequence:
            type: string
        connect_src:
          type: sequence
          sequence:
            type: string
    stripe:
      type: mapping
      label: 'Stripe.js profile'
      mapping:
        script_src:
          type: sequence
          sequence:
            type: string
        frame_src:
          type: sequence
          sequence:
            type: string
        connect_src:
          type: sequence
          sequence:
            type: string
    youtube:
      type: mapping
      label: 'YouTube embed profile'
      mapping:
        frame_src:
          type: sequence
          sequence:
            type: string
        img_src:
          type: sequence
          sequence:
            type: string
    recaptcha_v2:
      type: mapping
      label: 'reCAPTCHA v2 profile'
      mapping:
        script_src:
          type: sequence
          sequence:
            type: string
        frame_src:
          type: sequence
          sequence:
            type: string
        style_src:
          type: sequence
          sequence:
            type: string
    recaptcha_v3:
      type: mapping
      label: 'reCAPTCHA v3 profile'
      mapping:
        script_src:
          type: sequence
          sequence:
            type: string
        connect_src:
          type: sequence
          sequence:
            type: string
```

### `csp_audit.settings` (csp_audit sub-module)

File: `modules/csp_audit/config/schema/csp_audit.schema.yml`

```yaml
csp_audit.settings:
  type: config_object
  label: 'CSP Audit settings'
  mapping:
    cache_ttl:
      type: integer
      label: 'Scan result cache TTL in seconds'
    allowlist:
      type: sequence
      label: 'Module machine names marked as reviewed and safe'
      sequence:
        type: string
        label: 'Module machine name'
```

---

## Routes

### `csp_wizard.settings`

```yaml
csp_wizard.settings:
  path: '/admin/config/security/csp-wizard'
  defaults:
    _form: '\Drupal\csp_wizard\Form\CspSettingsForm'
    _title: 'CSP Wizard Settings'
  requirements:
    _permission: 'administer csp wizard'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Path | `/admin/config/security/csp-wizard` |
| Handler | `CspSettingsForm` (ConfigFormBase) |
| Access | `administer csp wizard` permission |
| Purpose | Quick-edit form outside the wizard; exposes mode toggle, flood config, SIEM URL |

### `csp_wizard.wizard`

```yaml
csp_wizard.wizard:
  path: '/admin/config/security/csp-wizard/wizard'
  defaults:
    _form: '\Drupal\csp_wizard\Form\CspWizardForm'
    _title: 'CSP Policy Wizard'
  requirements:
    _permission: 'administer csp wizard'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Path | `/admin/config/security/csp-wizard/wizard` |
| Handler | `CspWizardForm` (FormBase, six-step) |
| Access | `administer csp wizard` permission |
| Purpose | Entry point for the guided six-step wizard |

### `csp_wizard.report` (POST — violation receiver)

```yaml
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

| Property | Value |
|---|---|
| Path | `/csp-wizard/report` |
| Handler | `CspReportController::receive()` |
| HTTP methods | POST only |
| Access | Public (no authentication required; browsers post violation reports) |
| Body size limit | 4 KB enforced in the controller before parsing |
| Flood controlled | Yes — `csp_wizard_report` event, configurable limit |
| Purpose | Receives W3C CSP Level 2 (`application/csp-report`) and Reporting API Level 1 (`application/reports+json`) violation payloads |

### `csp_wizard.report_info` (GET — informational page)

```yaml
csp_wizard.report_info:
  path: '/csp-wizard/report'
  defaults:
    _controller: '\Drupal\csp_wizard\Controller\CspReportController::info'
    _title: 'CSP Reporting Endpoint'
  methods: [GET]
  requirements:
    _permission: 'view csp violations'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Path | `/csp-wizard/report` (GET) |
| Purpose | Informational page confirming the endpoint is active; links to the dblog CSP filter |

### `csp_wizard.toggle_mode`

```yaml
csp_wizard.toggle_mode:
  path: '/admin/config/security/csp-wizard/toggle-mode'
  defaults:
    _controller: '\Drupal\csp_wizard\Controller\CspSettingsController::toggleMode'
    _title: 'Toggle CSP Mode'
  requirements:
    _permission: 'administer csp wizard'
    _csrf_token: 'TRUE'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Path | `/admin/config/security/csp-wizard/toggle-mode` |
| Purpose | One-click mode switch between `report_only` and `enforce`; CSRF-protected |

### `csp_wizard.pci_export`

```yaml
csp_wizard.pci_export:
  path: '/admin/config/security/csp-wizard/pci-export'
  defaults:
    _controller: '\Drupal\csp_wizard\Controller\CspPciExportController::export'
    _title: 'PCI Script Inventory Export'
  requirements:
    _permission: 'administer csp wizard'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Path | `/admin/config/security/csp-wizard/pci-export` |
| Purpose | Generates and streams a CSV or JSON script inventory for PCI DSS 6.4.3 compliance artefacts |

### `csp_wizard.audit_allowlist` (csp_audit sub-module)

```yaml
csp_wizard.audit_allowlist:
  path: '/admin/config/security/csp-wizard/audit-allowlist'
  defaults:
    _form: '\Drupal\csp_wizard\Form\CspAuditAllowlistForm'
    _title: 'CSP Audit Known-Safe Allowlist'
  requirements:
    _permission: 'administer csp audit'
  options:
    _admin_route: true
```

### `csp_audit.report` (csp_audit sub-module)

```yaml
csp_audit.report:
  path: '/admin/reports/csp-audit'
  defaults:
    _controller: '\Drupal\csp_audit\Controller\CspAuditReportController::report'
    _title: 'CSP Audit Report'
  requirements:
    _permission: 'administer csp audit'
  options:
    _admin_route: true
```

| Property | Value |
|---|---|
| Path | `/admin/reports/csp-audit` |
| Purpose | Grouped findings table from `ModuleScanner`; re-scan action; CSV export |

### `csp_audit.rescan` (csp_audit sub-module)

```yaml
csp_audit.rescan:
  path: '/admin/reports/csp-audit/rescan'
  defaults:
    _controller: '\Drupal\csp_audit\Controller\CspAuditReportController::rescan'
    _title: 'Re-scan Modules'
  requirements:
    _permission: 'administer csp audit'
    _csrf_token: 'TRUE'
  options:
    _admin_route: true
```

---

## Hook Implementations

All hooks follow Drupal 11's OOP `#[Hook]` attribute pattern. The `.module` file contains minimal procedural stubs delegating to the hooks service. Note: `hook_page_attachments_alter` and `hook_element_info_alter` are legacy hooks that Drupal 11 dispatches via both the attribute system and `.module` file discovery; the `.module` stub ensures compatibility during the transition period.

### `hook_page_attachments_alter` — `CspWizardHooks::pageAttachmentsAlter()`

File: `src/Hook/CspWizardHooks.php`

```php
#[Hook('page_attachments_alter')]
public function pageAttachmentsAlter(array &$attachments): void
```

Behaviour:

1. Return immediately if the CSP Wizard module is not in `enforce` or `report_only` mode, or if nonce injection is disabled in config.
2. Call `NonceGeneratorService::getNonce()` to obtain (or generate) the per-request nonce.
3. Inject `$attachments['#attached']['drupalSettings']['cspWizard']['nonce'] = $nonce` so front-end JavaScript can use the nonce when dynamically creating script elements (e.g., for GTM's `document.write` replacement).
4. Iterate `$attachments['#attached']['html_head']`. For each element where `$element[0]['#tag'] === 'script'` and `empty($element[0]['#attributes']['src'])`, stamp `$element[0]['#attributes']['nonce'] = $nonce`.

### `hook_element_info_alter` — `CspWizardHooks::elementInfoAlter()`

File: `src/Hook/CspWizardHooks.php`

```php
#[Hook('element_info_alter')]
public function elementInfoAlter(array &$types): void
```

Behaviour: When `isset($types['html_tag'])`, appends `[CspWizardInlineScript::class, 'preRenderAddNonce']` to `$types['html_tag']['#pre_render']`. This ensures every `html_tag` element rendered on any page goes through the nonce-stamping callback at render time, outside the cache boundary.

### `hook_requirements` — `CspWizardHooks::requirements()`

File: `src/Hook/CspWizardHooks.php`

```php
#[Hook('requirements')]
public function requirements(string $phase): array
```

Behaviour (phase `runtime`):

1. Read `mode` from `csp_wizard.settings`. Report current mode as an `INFO` requirement row.
2. Query the `watchdog` table via `database` service for the most recent log entry with `type = 'csp_wizard'`. Include the timestamp in the requirement value.
3. If `csp_audit` sub-module is enabled, query `ModuleScanner::getFindings()` (from cache) for the total finding count. Include this in a second requirement row at `REQUIREMENT_WARNING` severity if count > 0.
4. If `mode === 'enforce'` and no nonce is configured, return `REQUIREMENT_WARNING`.
5. If the `csp` community module is also enabled, return `REQUIREMENT_WARNING` about conflicting header modules.

Returned array structure:

```php
[
  'csp_wizard_mode' => [
    'title'    => 'CSP Wizard',
    'value'    => 'Report-Only mode active' | 'Enforcement mode active',
    'severity' => REQUIREMENT_INFO | REQUIREMENT_WARNING,
  ],
  'csp_wizard_violations' => [
    'title'    => 'CSP Violations',
    'value'    => 'Last violation: {timestamp}' | 'No violations logged',
    'severity' => REQUIREMENT_INFO,
  ],
]
```

### `hook_help` — `CspWizardHooks::help()`

File: `src/Hook/CspWizardHooks.php`

```php
#[Hook('help')]
public function help(string $route_name, RouteMatchInterface $route_match): string|array
```

Behaviour: When `$route_name === 'help.page.csp_wizard'`, returns a render array with a description of the module's purpose, links to the wizard, the settings form, and the OWASP CSP cheat sheet. Returns empty string for all other routes.

---

## Event Subscribers

### `CspHeaderSubscriber` — `KernelEvents::RESPONSE`

File: `src/EventSubscriber/CspHeaderSubscriber.php`

| Property | Value |
|---|---|
| Event | `Symfony\Component\HttpKernel\KernelEvents::RESPONSE` |
| Priority | `-10` |
| Reason for priority | Must run after page assembly (positive priorities) and after BigPipe post-processing, but before the response is sent to the client. |

```php
public static function getSubscribedEvents(): array {
    return [KernelEvents::RESPONSE => ['onResponse', -10]];
}
```

Full `onResponse()` logic:

1. Get the response from `$event->getResponse()`.
2. Check `Content-Type` header; return early if it does not contain `text/html`.
3. Read `csp_wizard.settings:seckit_bridge_active`; if `true`, return early (SecKit owns the header).
4. Call `CspPolicyBuilderService::buildHeader()` to get the policy string.
5. Validate the policy string: if it contains `\r` or `\n`, log a critical watchdog entry and use an empty fallback policy.
6. Choose header name based on `mode` config (`Content-Security-Policy` vs `Content-Security-Policy-Report-Only`).
7. If PCI mode is enabled and the request path matches a payment page pattern, call `CspPolicyBuilderService::buildPaymentHeader()` and use that instead.
8. Write the selected header to the response.
9. If `report_uri_enabled` is true, also write the `Reporting-Endpoints` header: `csp-wizard-endpoint="/csp-wizard/report"`.

### `CspSecKitBridgeSubscriber` — `ConfigEvents::SAVE` (csp_wizard_seckit sub-module)

File: `modules/csp_wizard_seckit/src/EventSubscriber/CspSecKitBridgeSubscriber.php`

| Property | Value |
|---|---|
| Event | `Drupal\Core\Config\ConfigEvents::SAVE` |
| Priority | `0` (default) |

```php
public static function getSubscribedEvents(): array {
    return [ConfigEvents::SAVE => ['onConfigSave', 0]];
}
```

`onConfigSave()` logic:

1. Check `$event->getConfig()->getName() === 'csp_wizard.settings'`; return early if not.
2. Check `module_handler->moduleExists('seckit')`; return early if SecKit is not present.
3. Call `CspPolicyBuilderService::buildHeader()`.
4. Load `seckit.settings` via `config.factory`.
5. Write the policy string into the appropriate SecKit CSP key (e.g., `csp.policy-uri` based on the SecKit config structure).
6. Save the SecKit config.
7. Update `csp_wizard.settings:seckit_bridge_active = true`.

---

## Entity Definitions

CSP Wizard defines **no custom entity types**. The module interacts with existing Drupal core entities:

| Entity | Interaction |
|---|---|
| No custom entities | All persistent state uses Config API and standard Drupal subsystems (watchdog, flood). |

The module uses Drupal's standard `RequestStack` (a Symfony service, not an entity) as a transient per-request store for the nonce. Violation records are stored in the `watchdog` table via the Drupal logger system, not as custom entities. No `ContentEntityBase` or `ConfigEntityBase` subclasses are defined.

---

## External API Integrations

### Optional: SIEM Webhook Endpoint

| Property | Value |
|---|---|
| Direction | Outbound (server pushes to external system) |
| Trigger | Each accepted POST to `/csp-wizard/report` when `report_siem_url` is non-empty |
| Protocol | HTTPS POST |
| Authentication | None built in (the SIEM URL itself may contain a token in the path; administrators are responsible for TLS and auth on the external endpoint) |
| Payload | Raw violation report body forwarded verbatim (either `application/csp-report` JSON or `application/reports+json` array) |
| Timeout | 2 seconds connect + 2 seconds read (Guzzle options: `connect_timeout: 2`, `timeout: 2`) |
| Error handling | All `GuzzleException` subclasses caught and swallowed silently. A watchdog `NOTICE` entry is written on SIEM forwarding failure, but the HTTP 204 response to the browser is still returned so the violation report is not re-transmitted. SIEM forwarding is deliberately best-effort. |
| Implementation | `CspViolationLogger::forwardToSiem()` via the injected `@http_client` (Guzzle, already a Drupal core dependency) |

### W3C CSP Reporting API (Inbound)

| Property | Value |
|---|---|
| Direction | Inbound (browsers POST to `/csp-wizard/report`) |
| Standard | W3C CSP Level 2 (`application/csp-report`) and W3C Reporting API Level 1 (`application/reports+json`) |
| Content-Type handling | Controller reads `Content-Type` request header to select the appropriate JSON parser; both formats decoded to a `CspViolationReport` value object |
| Browser support | `application/csp-report`: all modern browsers. `application/reports+json`: Chrome/Edge 96+, Firefox 99+ |
| No credentials or API keys | The endpoint is stateless and unauthenticated; browsers do not send credentials with violation reports |

### SecKit Config Integration (csp_wizard_seckit sub-module)

| Property | Value |
|---|---|
| Direction | Internal — reads and writes to Drupal's config system |
| API | `Drupal\Core\Config\ConfigFactoryInterface` |
| Trigger | `ConfigEvents::SAVE` for `csp_wizard.settings` |
| SecKit config key written | Determined by loading `seckit.settings` and writing to the `csp` sub-key following SecKit's own config schema |
| Conflict prevention | `CspHeaderSubscriber` reads `seckit_bridge_active` flag before writing its own CSP header; if the flag is `true`, the subscriber returns early, leaving SecKit to write the header |

---

## Security Design

### Access Control

| Resource | Protection |
|---|---|
| Admin settings form and wizard (`/admin/config/security/csp-wizard/**`) | Route requirement `_permission: 'administer csp wizard'`, declared with `restrict access: true`. Claro admin theme enforces visual separation. |
| Mode toggle route | Route requirement `_permission: 'administer csp wizard'` plus `_csrf_token: 'TRUE'`. The one-click toggle is a GET link with a CSRF token to prevent cross-site triggering. |
| PCI export route | `_permission: 'administer csp wizard'` |
| Violation report endpoint (POST `/csp-wizard/report`) | `_access: 'TRUE'` (public, no auth) — required by the W3C CSP specification. Rate-limited via Drupal Flood API. Body size capped at 4 KB. |
| Violation log view | `_permission: 'view csp violations'` |
| CSP Audit report | `_permission: 'administer csp audit'` with `restrict access: true` |
| Audit allowlist form | `_permission: 'administer csp audit'` |

### Input Validation

| Input source | Validation approach |
|---|---|
| Custom domain inputs (wizard step 2) | Validated against `^[a-zA-Z0-9\-\.\:\_\*\/]+$` regex in `CspWizardForm::validateForm()`. Empty or whitespace-only values are stripped. |
| SIEM webhook URL | Validated with `\Drupal\Component\Utility\UrlHelper::isValid($url, TRUE)` (requires external URL). Scheme must be `https`; `http` SIEM URLs are rejected with a form validation error. |
| Flood limit and window integers | Validated as positive integers with a maximum of 3600 in `CspSettingsForm::validateForm()`. |
| Nonce bits | Must be one of `128`, `192`, or `256`; validated against an allowed-values `select` element. |
| PCI page patterns | Validated as Drupal path patterns (must begin with `/`). Each pattern is checked for newline characters. |
| POST body at `/csp-wizard/report` | Controller checks `Content-Length` (or measures the body) before attempting to parse. Rejects anything over 4096 bytes with HTTP 413. JSON decoded with `json_decode($body, TRUE, 8, JSON_THROW_ON_ERROR)` in a try/catch; returns HTTP 400 on malformed JSON. |
| Config import (CMI) | Config schema enforces types at import time. Unknown keys in `csp_wizard.settings` are rejected by the schema system. |

### Output Encoding

| Output location | Encoding approach |
|---|---|
| CSP header value | Built from structured arrays, never from raw user input. Validated for absence of CR/LF before writing. Any value containing newlines triggers a fallback to an empty policy and a critical watchdog log. |
| Violation log entries | All string fields from violation reports passed through `Html::escape()` in `CspViolationLogger` before reaching `logger->warning()`. Prevents log-injection when reports are rendered in the DBLog admin UI. |
| Audit report table cells | All file paths and pattern matches wrapped in `Html::escape()` in `CspAuditReportController`. Module machine names are trusted (from Drupal's module system) but still HTML-escaped for defence in depth. |
| Admin form markup | All labels and descriptions use `$this->t()` (`TranslatableMarkup`), which is auto-escaped by Twig. Free-text policy previews on the wizard review step are output via `Markup::create(Html::escape($policyString))`. |
| `hook_requirements` values | Constructed from `TranslatableMarkup`; no user-supplied data reflected. |
| `hook_help` output | Returned as a render array with `#markup` using `Markup::create($this->t(...))`. |
| drupalSettings nonce exposure | The nonce value is Base64url-encoded ASCII with no special HTML characters. It is placed into `drupalSettings` via the standard `#attached` API, which encodes the JSON safely. |

### Nonce Security Properties

- **Entropy**: 32 bytes from PHP's `random_bytes()` (CSPRNG: `/dev/urandom` on Linux, `CryptGenRandom` on Windows via libsodium). Base64url-encoded to 43 characters.
- **Uniqueness per request**: The nonce is generated at most once per HTTP request and stored on the `RequestStack` request attribute `_csp_wizard_nonce`. Subsequent calls to `getNonce()` within the same request return the same value. Across requests (and across concurrent requests), the nonce is independent.
- **No logging**: The nonce value is never passed to any logging facility, never stored in a session, and never written to a cache backend.
- **`unsafe-inline` conflict detection**: `CspPolicyBuilderService` checks for `unsafe-inline` in any assembled `script-src` and emits a `MessengerInterface::addWarning()` in the admin UI and a watchdog `WARNING` entry if detected, because `unsafe-inline` causes browsers to ignore nonces (CSP Level 2 specification §4.2.2).
- **Dynamic Page Cache compatibility**: Nonce placeholder substitution is applied outside the DPC cache boundary so nonce values are never persisted in cached page variants.

### Flood Control

The violation report endpoint applies `FloodInterface::register('csp_wizard_report', $config->get('flood.window'), $ipAddress)` on each accepted report. If `FloodInterface::isAllowed('csp_wizard_report', $config->get('flood.limit'), $ipAddress)` returns `false`, the controller returns HTTP 429 immediately without parsing the body. Default thresholds: 60 reports per IP per 60-second window (configurable).

### Transport Security

- The optional SIEM webhook URL is validated to require `https` scheme. The module does not disable Guzzle's TLS certificate verification for webhook requests.
- The violation report endpoint itself is served over whatever TLS the Drupal site uses. The module does not enforce HTTPS at the PHP level (that is the responsibility of the web server or reverse proxy).

### Header Injection Prevention

The `CspHeaderSubscriber` validates the assembled policy string before writing it:

```php
if (str_contains($policyString, "\r") || str_contains($policyString, "\n")) {
    $this->logger->critical('CSP Wizard: header injection attempt detected in assembled policy. Using empty fallback.');
    $policyString = '';
}
```

An empty policy string results in no `Content-Security-Policy` header being written, which is safer than writing a malformed header.

---

## Test Strategy

### Unit Tests

Location: `tests/src/Unit/`
Namespace: `Drupal\Tests\csp_wizard\Unit\`
Base class: `Drupal\Tests\UnitTestCase`
Framework: PHPUnit 10+

| Test class | File | What it tests |
|---|---|---|
| `NonceGeneratorServiceTest` | `tests/src/Unit/Service/NonceGeneratorServiceTest.php` | Asserts `getNonce()` returns a non-empty Base64url string. Asserts calling `getNonce()` twice on the same mock request returns the identical value (single-generation guarantee). Asserts `resetNonce()` clears the attribute and the next `getNonce()` call returns a different value. Asserts the nonce length corresponds to 32 bytes (`ceil(32 * 4/3) = 43` characters without padding). |
| `CspPolicyBuilderServiceTest` | `tests/src/Unit/Service/CspPolicyBuilderServiceTest.php` | Mocks `ConfigFactoryInterface` to return controlled config values. Asserts that with no services enabled, the header contains only the base directives. Asserts that enabling `gtm` adds `https://www.googletagmanager.com` to `script-src`. Asserts that enabling `stripe` adds `https://js.stripe.com` to `script-src` and `frame-src`. Asserts `'nonce-{value}'` appears in `script-src` when nonce is enabled. Asserts `'strict-dynamic'` is present in `script-src` when GTM and nonce are both enabled. Asserts that `unsafe-inline` coexistence with a nonce triggers a messenger warning (mock `MessengerInterface` captures it). Asserts the header string contains no newline characters. Asserts `buildPaymentHeader()` uses `csp_wizard.payment_policy` directives. |
| `CspViolationLoggerTest` | `tests/src/Unit/Service/CspViolationLoggerTest.php` | Mocks `LoggerInterface`. Asserts that `log()` calls `logger->warning()` exactly once. Asserts that XSS test strings in `blocked-uri` are HTML-escaped in the logged message. Asserts that `script-sample` containing `<script>` is escaped. Asserts SIEM forwarding makes exactly one Guzzle POST when `report_siem_url` is set. Asserts that a `GuzzleException` from the SIEM call does not propagate. |
| `CspWizardInlineScriptTest` | `tests/src/Unit/Render/CspWizardInlineScriptTest.php` | Asserts `preRenderAddNonce()` stamps `nonce` attribute on a script element with no `src`. Asserts it does NOT stamp `nonce` on a script element that has a `src` attribute. Asserts it does NOT stamp `nonce` on a `link` element. Asserts it does NOT stamp `nonce` on a `style` element. |
| `CspWizardHooksTest` | `tests/src/Unit/Hook/CspWizardHooksTest.php` | Asserts `requirements()` returns a `csp_wizard_mode` key for phase `runtime`. Asserts the severity is `REQUIREMENT_INFO` in `report_only` mode and a different value in `enforce` mode without nonce. Asserts `pageAttachmentsAlter()` injects `drupalSettings.cspWizard.nonce`. Asserts `pageAttachmentsAlter()` stamps nonce on an `html_head` inline script element. Asserts `pageAttachmentsAlter()` does not stamp nonce on an `html_head` external script element. Asserts `elementInfoAlter()` appends the `preRenderAddNonce` callback. |
| `ModuleScannerTest` | `modules/csp_audit/tests/src/Unit/Scanner/ModuleScannerTest.php` | Creates temporary module directories with crafted `.js` and `.php` fixture files. Asserts that a JS file containing `unsafe-inline` produces one finding. Asserts that a PHP file with `#tag => 'script'` but no `src` produces one finding. Asserts that a PHP file with `#tag => 'script'` and `src` does NOT produce a finding. Asserts that cache is populated after first scan. Asserts that cache is used on second call (mock verifies the directory scan runs only once). |

### Functional Tests (BrowserTestBase)

Location: `tests/src/Functional/`
Namespace: `Drupal\Tests\csp_wizard\Functional\`
Base class: `Drupal\Tests\BrowserTestBase`

| Test class | File | What it tests |
|---|---|---|
| `CspSettingsFormTest` | `tests/src/Functional/Form/CspSettingsFormTest.php` | Creates a user with `administer csp wizard`. Visits `/admin/config/security/csp-wizard`. Asserts the form renders. Submits a valid SIEM URL and flood limit; asserts config is saved correctly. Submits an invalid (http://) SIEM URL; asserts validation error message. Visits the route as an anonymous user; asserts HTTP 403. |
| `CspWizardFormTest` | `tests/src/Functional/Form/CspWizardFormTest.php` | Runs through all six wizard steps. Step 1: selects `report_only`. Step 2: checks GTM and Stripe checkboxes. Step 3: confirms nonce is enabled. Step 4: enters no SIEM URL. Step 5: disables PCI mode. Step 6: asserts the preview header string contains `https://www.googletagmanager.com` and `https://js.stripe.com`; clicks Save. Asserts success message. Asserts `csp_wizard.settings:mode === 'report_only'`. Asserts the "Back" button on step 3 returns to step 2 with GTM still checked. |
| `CspHeaderSubscriberTest` | `tests/src/Functional/EventSubscriber/CspHeaderSubscriberTest.php` | Installs the module. Visits the front page. Asserts `Content-Security-Policy-Report-Only` header is present (default mode). Visits `/admin/config/security/csp-wizard` and switches to `enforce` mode. Revisits the front page. Asserts `Content-Security-Policy` header is present instead. Asserts `Content-Security-Policy-Report-Only` is absent. Asserts the header does NOT appear on a JSON response (`/csp-wizard/report` GET returns HTML, but a test JSON route asserts no header). |
| `CspReportControllerTest` | `tests/src/Functional/Controller/CspReportControllerTest.php` | POSTs a valid `application/csp-report` JSON body to `/csp-wizard/report`. Asserts HTTP 204 response. Asserts a watchdog entry with channel `csp_wizard` and the `blocked-uri` value exists. POSTs a body larger than 4 KB; asserts HTTP 413. POSTs malformed JSON; asserts HTTP 400. POSTs 61 times from the same IP (via test client); asserts the 61st request returns HTTP 429. Asserts an `application/reports+json` array payload is also accepted and logged. |
| `NonceInjectionTest` | `tests/src/Functional/NonceInjectionTest.php` | Enables nonce mode. Visits a page that has inline scripts in `html_head`. Asserts that the rendered HTML contains `<script nonce="` attributes. Asserts all inline script tags on the same page share the same nonce value. Asserts external script tags (with `src`) do NOT have a `nonce` attribute. Asserts the nonce in the `Content-Security-Policy` header matches the nonce in the HTML. Asserts a second request produces a different nonce value. |
| `PciModeTest` | `tests/src/Functional/PciModeTest.php` | Enables PCI mode with pattern `/checkout/**`. Visits `/checkout/step-1`. Asserts the CSP header is stricter than the site-wide policy (e.g., contains `require-trusted-types-for` if configured). Visits the front page. Asserts the site-wide (less strict) policy is applied. Visits `/admin/config/security/csp-wizard/pci-export`. Asserts CSV download contains expected script-src origins. |
| `CspStatusReportTest` | `tests/src/Functional/Hook/CspStatusReportTest.php` | Visits `admin/reports/status` as administrator. Asserts the `CSP Wizard` row is present. Asserts the `CSP Violations` row is present. After posting a violation report, asserts the timestamp in the row updates. |
| `CspAuditReportTest` | `modules/csp_audit/tests/src/Functional/Controller/CspAuditReportTest.php` | Installs `csp_audit`. Visits `/admin/reports/csp-audit`. Asserts the page loads and shows a findings table (possibly empty). Clicks "Re-scan"; asserts redirect back to the report. Asserts a module in the allowlist does not appear in the findings table. Tests CSV export download. |
| `CspSecKitBridgeTest` | `modules/csp_wizard_seckit/tests/src/Functional/CspSecKitBridgeTest.php` | Requires SecKit to be present. Enables `csp_wizard_seckit`. Saves `csp_wizard.settings`. Asserts `seckit.settings` CSP key contains the generated policy. Visits the front page. Asserts only one `Content-Security-Policy` header is present (no duplicate). |

### Playwright / End-to-End Tests

Location: `playwright/` (project-level)

| Test file | What it tests |
|---|---|
| `csp-wizard-form.spec.ts` | Navigates to `/admin/config/security/csp-wizard/wizard`. Completes all six steps via UI interaction. Asserts the policy preview on step 6 is non-empty and contains expected origins for the selected services. Asserts the Save button triggers a success message. Uses `page.evaluate()` to read `drupalSettings.cspWizard.nonce` and asserts it is a 43-character Base64url string. |
| `csp-report-only-banner.spec.ts` | Navigates to `/admin/config/security/csp-wizard`. Asserts the amber "Report-Only mode active" banner is visible when mode is `report_only`. Clicks the "Switch to Enforcement" button. Confirms the confirmation dialog. Asserts the banner disappears and the page shows "Enforcement mode active". |
| `csp-nonce-injection.spec.ts` | Navigates to any Drupal page. Uses `page.locator('script[nonce]')` to assert that inline scripts carry a `nonce` attribute. Reads the `Content-Security-Policy` response header via `page.on('response', ...)` and asserts the nonce value in the header matches the value found in the DOM. |
| `csp-violation-report.spec.ts` | Manually triggers a CSP violation via `page.evaluate()` by attempting `eval('1')`. Listens for the browser's violation report POST to `/csp-wizard/report`. Navigates to `admin/reports/dblog` and filters by `csp_wizard` type. Asserts at least one violation log entry is visible. |
| `csp-audit-report.spec.ts` | Navigates to `/admin/reports/csp-audit`. Asserts the findings table is rendered (even if empty). Clicks "Re-scan". Asserts redirect and table re-render. Clicks the CSV export link. Asserts a file download response is triggered (checks `Content-Disposition` header). |
| `csp-pci-export.spec.ts` | Navigates to `/admin/config/security/csp-wizard/pci-export`. Asserts a CSV download is initiated. Parses the download and asserts it contains at minimum a `directive` and `origin` column. |

### Test Coverage Goals

| Coverage area | Target |
|---|---|
| `NonceGeneratorService` | 100% branch (generate on first call, return cached on subsequent, reset in tests) |
| `CspPolicyBuilderService` | 100% branch per service toggle (all 6 service profile permutations, nonce on/off, `strict-dynamic` presence) |
| `CspViolationLogger` | 100% branch (with/without SIEM URL, GuzzleException suppression) |
| `CspHeaderSubscriber` | All three content-type skip paths, enforce vs report-only mode, SecKit bridge yield, newline injection guard |
| `CspReportController` | HTTP 204, 400, 413, 429 response paths; both `application/csp-report` and `application/reports+json` parsers |
| `CspWizardInlineScript` | Script with no src (stamped), script with src (not stamped), non-script tag (not stamped) |
| `CspWizardHooks` | All requirement severity levels, nonce injection into `drupalSettings`, nonce stamp on inline script, no stamp on external script |
| `ModuleScanner` (csp_audit) | JS finding, PHP finding, no finding (external script), cache hit path, cache clear path |
| End-to-end nonce matching | Playwright test verifying DOM nonce equals CSP header nonce |

---

## Appendix: Built-in Service Directive Profiles

The following profiles are shipped in `config/install/csp_wizard.service_profiles.yml` and consumed by `CspPolicyBuilderService`:

### CKEditor5

```yaml
ckeditor5:
  script_src:
    - "'self'"
    - 'https://cdn.ckeditor.com'
  style_src:
    - "'self'"
    - "'unsafe-inline'"    # CKEditor5 classic build requires inline styles
```

Note: `unsafe-inline` in `style_src` is a known CKEditor5 limitation. The wizard UI notes this on step 6.

### Google Tag Manager

```yaml
gtm:
  script_src:
    - 'https://www.googletagmanager.com'
    - 'https://www.google-analytics.com'
  connect_src:
    - 'https://www.google-analytics.com'
    - 'https://analytics.google.com'
    - 'https://stats.g.doubleclick.net'
```

### Stripe

```yaml
stripe:
  script_src:
    - 'https://js.stripe.com'
  frame_src:
    - 'https://js.stripe.com'
    - 'https://hooks.stripe.com'
  connect_src:
    - 'https://api.stripe.com'
```

### YouTube

```yaml
youtube:
  frame_src:
    - 'https://www.youtube.com'
    - 'https://www.youtube-nocookie.com'
  img_src:
    - 'https://i.ytimg.com'
    - 'https://i3.ytimg.com'
```

### reCAPTCHA v2

```yaml
recaptcha_v2:
  script_src:
    - 'https://www.google.com'
    - 'https://www.gstatic.com'
  frame_src:
    - 'https://www.google.com'
  style_src:
    - 'https://www.gstatic.com'
```

### reCAPTCHA v3

```yaml
recaptcha_v3:
  script_src:
    - 'https://www.google.com'
    - 'https://www.gstatic.com'
  connect_src:
    - 'https://www.google.com'
```

---

## Appendix: Value Objects

### `CspViolationReport`

```php
// src/Value/CspViolationReport.php
final readonly class CspViolationReport {
    public function __construct(
        public readonly string $documentUri,
        public readonly string $violatedDirective,
        public readonly string $blockedUri,
        public readonly string $sourceFile = '',
        public readonly int    $lineNumber = 0,
        public readonly int    $columnNumber = 0,
        public readonly string $scriptSample = '',
        public readonly int    $statusCode = 0,
        public readonly string $disposition = 'enforce',
    ) {}
}
```

### `CspAuditFinding` (csp_audit sub-module)

```php
// modules/csp_audit/src/Value/CspAuditFinding.php
final readonly class CspAuditFinding {
    public function __construct(
        public readonly string $moduleName,
        public readonly string $filePath,
        public readonly string $pattern,
        public readonly string $severity,   // 'error' | 'warning'
        public readonly int    $lineNumber,
    ) {}
}
```

---

## Appendix: Full File Manifest

```
csp_wizard/
├── composer.json
├── csp_wizard.info.yml
├── csp_wizard.links.menu.yml
├── csp_wizard.module
├── csp_wizard.permissions.yml
├── csp_wizard.routing.yml
├── csp_wizard.services.yml
├── config/
│   ├── install/
│   │   ├── csp_wizard.payment_policy.yml
│   │   ├── csp_wizard.service_profiles.yml
│   │   └── csp_wizard.settings.yml
│   └── schema/
│       └── csp_wizard.schema.yml
├── src/
│   ├── Controller/
│   │   ├── CspPciExportController.php
│   │   ├── CspReportController.php
│   │   └── CspSettingsController.php
│   ├── EventSubscriber/
│   │   └── CspHeaderSubscriber.php
│   ├── Form/
│   │   ├── CspAuditAllowlistForm.php
│   │   ├── CspSettingsForm.php
│   │   └── CspWizardForm.php
│   ├── Hook/
│   │   └── CspWizardHooks.php
│   ├── Render/
│   │   └── CspWizardInlineScript.php
│   ├── Service/
│   │   ├── CspPolicyBuilderService.php
│   │   ├── CspViolationLogger.php
│   │   └── NonceGeneratorService.php
│   └── Value/
│       └── CspViolationReport.php
├── tests/
│   └── src/
│       ├── Functional/
│       │   ├── Controller/
│       │   │   └── CspReportControllerTest.php
│       │   ├── EventSubscriber/
│       │   │   └── CspHeaderSubscriberTest.php
│       │   ├── Form/
│       │   │   ├── CspSettingsFormTest.php
│       │   │   └── CspWizardFormTest.php
│       │   ├── Hook/
│       │   │   └── CspStatusReportTest.php
│       │   ├── NonceInjectionTest.php
│       │   └── PciModeTest.php
│       └── Unit/
│           ├── Hook/
│           │   └── CspWizardHooksTest.php
│           ├── Render/
│           │   └── CspWizardInlineScriptTest.php
│           └── Service/
│               ├── CspPolicyBuilderServiceTest.php
│               ├── CspViolationLoggerTest.php
│               └── NonceGeneratorServiceTest.php
└── modules/
    ├── csp_audit/
    │   ├── csp_audit.info.yml
    │   ├── csp_audit.links.menu.yml
    │   ├── csp_audit.routing.yml
    │   ├── csp_audit.services.yml
    │   ├── config/
    │   │   ├── install/
    │   │   │   └── csp_audit.settings.yml
    │   │   └── schema/
    │   │       └── csp_audit.schema.yml
    │   ├── src/
    │   │   ├── Controller/
    │   │   │   └── CspAuditReportController.php
    │   │   ├── Hook/
    │   │   │   └── CspAuditHooks.php
    │   │   ├── Scanner/
    │   │   │   └── ModuleScanner.php
    │   │   └── Value/
    │   │       └── CspAuditFinding.php
    │   └── tests/
    │       └── src/
    │           ├── Functional/
    │           │   └── Controller/
    │           │       └── CspAuditReportTest.php
    │           └── Unit/
    │               └── Scanner/
    │                   └── ModuleScannerTest.php
    └── csp_wizard_seckit/
        ├── csp_wizard_seckit.info.yml
        ├── csp_wizard_seckit.services.yml
        └── src/
            └── EventSubscriber/
                └── CspSecKitBridgeSubscriber.php
```
