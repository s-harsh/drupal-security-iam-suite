<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Form;

use Drupal\Component\Utility\Html;
use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Render\Markup;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\csp_wizard\Service\CspPolicyBuilderService;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Six-step guided CSP Policy Wizard.
 *
 * Step 1 — Introduction and mode selection.
 * Step 2 — Third-party service selection.
 * Step 3 — Nonce settings.
 * Step 4 — Violation reporting.
 * Step 5 — PCI DSS 6.4.3 mode.
 * Step 6 — Review and save.
 *
 * Uses $form_state->set('step', N) for navigation and
 * $form_state->set('wizard_values', [...]) to persist values across steps.
 */
final class CspWizardForm extends FormBase {

  use StringTranslationTrait;

  /**
   * Constructs a CspWizardForm.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\csp_wizard\Service\CspPolicyBuilderService $policyBuilder
   *   The CSP policy builder service.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly MessengerInterface $messenger,
    private readonly CspPolicyBuilderService $policyBuilder,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('messenger'),
      $container->get('csp_wizard.policy_builder'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'csp_wizard_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $step = (int) ($form_state->get('step') ?? 1);
    $form_state->set('step', $step);

    $form['#tree'] = TRUE;
    $form['#attributes']['class'][] = 'csp-wizard-form';

    // Progress indicator.
    $form['progress'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<div class="csp-wizard-progress">'
        . $this->t('Step @current of @total', ['@current' => $step, '@total' => 6])
        . '</div>'
      ),
      '#weight' => -100,
    ];

    $stepMethod = 'buildStep' . $step;
    $form = $this->$stepMethod($form, $form_state);

    // Navigation buttons.
    $form['actions'] = ['#type' => 'actions'];

    if ($step > 1) {
      $form['actions']['back'] = [
        '#type'                    => 'submit',
        '#value'                   => $this->t('Back'),
        '#submit'                  => ['::goBack'],
        '#limit_validation_errors' => [],
        '#weight'                  => -10,
      ];
    }

    if ($step < 6) {
      $form['actions']['next'] = [
        '#type'   => 'submit',
        '#value'  => $this->t('Next'),
        '#submit' => ['::goNext'],
        '#weight' => 10,
      ];
    }
    else {
      $form['actions']['save'] = [
        '#type'   => 'submit',
        '#value'  => $this->t('Save Configuration'),
        '#weight' => 10,
      ];
    }

    return $form;
  }

  // ---------------------------------------------------------------------------
  // Step builders
  // ---------------------------------------------------------------------------

  /**
   * Builds Step 1: Introduction and mode selection.
   */
  private function buildStep1(array $form, FormStateInterface $form_state): array {
    $saved = $this->configFactory->get('csp_wizard.settings');
    $values = $form_state->get('wizard_values') ?? [];

    $form['step1'] = [
      '#type'  => 'details',
      '#title' => $this->t('Step 1: Introduction & Mode Selection'),
      '#open'  => TRUE,
    ];

    $form['step1']['intro'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<p>' . $this->t('This wizard will guide you through creating a Content Security Policy tailored to your site. '
          . 'Start in <em>Report-Only</em> mode to observe what would be blocked, then switch to <em>Enforce</em> mode when you are confident the policy is correct.') . '</p>'
      ),
    ];

    $form['step1']['mode'] = [
      '#type'          => 'radios',
      '#title'         => $this->t('CSP Mode'),
      '#options'       => [
        'report_only' => $this->t('Report-Only — log violations without blocking (recommended)'),
        'enforce'     => $this->t('Enforce — actively block policy violations'),
      ],
      '#default_value' => $values['mode'] ?? (string) ($saved->get('mode') ?? 'report_only'),
      '#required'      => TRUE,
    ];

    return $form;
  }

  /**
   * Builds Step 2: Third-party service selection.
   */
  private function buildStep2(array $form, FormStateInterface $form_state): array {
    $saved = $this->configFactory->get('csp_wizard.settings');
    $values = $form_state->get('wizard_values') ?? [];
    $savedServices = $saved->get('services') ?? [];

    $form['step2'] = [
      '#type'  => 'details',
      '#title' => $this->t('Step 2: Third-Party Services'),
      '#open'  => TRUE,
    ];

    $form['step2']['description'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<p>' . $this->t('Select the third-party services your site uses. CSP Wizard will include the correct directives for each selected service.') . '</p>'
      ),
    ];

    $services = [
      'ckeditor5'    => $this->t('CKEditor5 (Drupal rich text editor)'),
      'gtm'          => $this->t('Google Tag Manager'),
      'stripe'       => $this->t('Stripe.js (payment processing)'),
      'youtube'      => $this->t('YouTube embeds'),
      'recaptcha_v2' => $this->t('Google reCAPTCHA v2'),
      'recaptcha_v3' => $this->t('Google reCAPTCHA v3'),
    ];

    foreach ($services as $key => $label) {
      $form['step2'][$key] = [
        '#type'          => 'checkbox',
        '#title'         => $label,
        '#default_value' => $values['services'][$key] ?? (bool) ($savedServices[$key] ?? FALSE),
      ];
    }

    $form['step2']['custom_domains'] = [
      '#type'          => 'textarea',
      '#title'         => $this->t('Custom allowed origins'),
      '#description'   => $this->t('Enter one origin per line (e.g. <code>https://cdn.example.com</code>). These will be added to <code>script-src</code>.'),
      '#default_value' => $values['custom_domains'] ?? implode("\n", $savedServices['custom_domains'] ?? []),
      '#rows'          => 4,
    ];

    return $form;
  }

  /**
   * Builds Step 3: Nonce settings.
   */
  private function buildStep3(array $form, FormStateInterface $form_state): array {
    $saved = $this->configFactory->get('csp_wizard.settings');
    $values = $form_state->get('wizard_values') ?? [];

    $form['step3'] = [
      '#type'  => 'details',
      '#title' => $this->t('Step 3: Nonce Injection'),
      '#open'  => TRUE,
    ];

    $form['step3']['info'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<p>' . $this->t('Nonce injection adds a unique cryptographic token to every inline <code>&lt;script&gt;</code> tag on each page request. '
          . 'This allows a strict CSP without <code>unsafe-inline</code>, providing strong XSS protection.') . '</p>'
      ),
    ];

    $form['step3']['nonce_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable per-request nonce injection'),
      '#default_value' => $values['nonce_enabled'] ?? (bool) ($saved->get('nonce_enabled') ?? TRUE),
    ];

    $form['step3']['nonce_bits'] = [
      '#type'          => 'select',
      '#title'         => $this->t('Nonce entropy'),
      '#options'       => [
        128 => $this->t('128 bits'),
        192 => $this->t('192 bits'),
        256 => $this->t('256 bits (recommended — strongest)'),
      ],
      '#default_value' => $values['nonce_bits'] ?? (int) ($saved->get('nonce_bits') ?? 256),
      '#states'        => [
        'visible' => [':input[name="step3[nonce_enabled]"]' => ['checked' => TRUE]],
      ],
    ];

    $form['step3']['nonce_fallback'] = [
      '#type'          => 'select',
      '#title'         => $this->t('Fallback when nonce cannot be applied'),
      '#options'       => [
        "'unsafe-inline'" => $this->t("'unsafe-inline' (permissive fallback for older browsers)"),
        ''                => $this->t('None (strict — inline scripts will be blocked on non-nonce browsers)'),
      ],
      '#default_value' => $values['nonce_fallback'] ?? (string) ($saved->get('nonce_fallback') ?? "'unsafe-inline'"),
      '#states'        => [
        'visible' => [':input[name="step3[nonce_enabled]"]' => ['checked' => TRUE]],
      ],
    ];

    return $form;
  }

  /**
   * Builds Step 4: Violation reporting.
   */
  private function buildStep4(array $form, FormStateInterface $form_state): array {
    $saved = $this->configFactory->get('csp_wizard.settings');
    $values = $form_state->get('wizard_values') ?? [];

    $form['step4'] = [
      '#type'  => 'details',
      '#title' => $this->t('Step 4: Violation Reporting'),
      '#open'  => TRUE,
    ];

    $form['step4']['report_uri_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable on-site violation report endpoint'),
      '#description'   => $this->t('Browsers will POST violation reports to <code>/csp-wizard/report</code>. Reports are logged to Drupal watchdog under the <code>csp_wizard</code> channel.'),
      '#default_value' => $values['report_uri_enabled'] ?? (bool) ($saved->get('report_uri_enabled') ?? TRUE),
    ];

    $form['step4']['report_siem_url'] = [
      '#type'          => 'url',
      '#title'         => $this->t('External SIEM webhook URL (optional)'),
      '#description'   => $this->t('HTTPS URL to forward violation payloads to an external Security Information and Event Management system. Leave empty to disable.'),
      '#default_value' => $values['report_siem_url'] ?? (string) ($saved->get('report_siem_url') ?? ''),
      '#maxlength'     => 2048,
    ];

    $form['step4']['flood_limit'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Max violation reports per IP per window'),
      '#min'           => 1,
      '#max'           => 3600,
      '#default_value' => $values['flood_limit'] ?? (int) ($saved->get('flood_limit') ?? 60),
    ];

    $form['step4']['flood_window'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Flood control window (seconds)'),
      '#min'           => 1,
      '#max'           => 3600,
      '#default_value' => $values['flood_window'] ?? (int) ($saved->get('flood_window') ?? 60),
    ];

    return $form;
  }

  /**
   * Builds Step 5: PCI DSS 6.4.3 compliance mode.
   */
  private function buildStep5(array $form, FormStateInterface $form_state): array {
    $saved = $this->configFactory->get('csp_wizard.settings');
    $values = $form_state->get('wizard_values') ?? [];
    $savedPci = $saved->get('pci_mode') ?? [];
    $wizardPci = $values['pci_mode'] ?? [];

    $form['step5'] = [
      '#type'  => 'details',
      '#title' => $this->t('Step 5: PCI DSS 6.4.3 Compliance Mode'),
      '#open'  => TRUE,
    ];

    $form['step5']['info'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<p>' . $this->t('PCI DSS v4.0 Requirement 6.4.3 (effective April 2025) mandates that payment pages explicitly authorise every script, verify script integrity, and maintain a script inventory. '
          . 'Enabling this mode applies a stricter CSP to payment-page paths and provides a script inventory export.') . '</p>'
      ),
    ];

    $form['step5']['pci_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable PCI DSS 6.4.3 compliance mode'),
      '#default_value' => $wizardPci['enabled'] ?? (bool) ($savedPci['enabled'] ?? FALSE),
    ];

    $form['step5']['page_patterns'] = [
      '#type'          => 'textarea',
      '#title'         => $this->t('Payment page path patterns'),
      '#description'   => $this->t('One pattern per line. Supports trailing <code>/**</code> wildcard (e.g. <code>/checkout/**</code>). The stricter payment-page CSP is applied only to these paths.'),
      '#default_value' => $wizardPci['page_patterns']
        ? implode("\n", $wizardPci['page_patterns'])
        : implode("\n", $savedPci['page_patterns'] ?? ['/checkout/**', '/cart/**']),
      '#rows'          => 4,
      '#states'        => [
        'visible' => [':input[name="step5[pci_enabled]"]' => ['checked' => TRUE]],
      ],
    ];

    $form['step5']['trusted_types'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Add <code>require-trusted-types-for \'script\'</code> (Chromium browsers only)'),
      '#description'   => $this->t('CSP Level 3 Trusted Types prevents DOM-based XSS. Currently supported in Chrome/Edge 86+ only. Does not affect Firefox or Safari.'),
      '#default_value' => $wizardPci['trusted_types'] ?? (bool) ($savedPci['trusted_types'] ?? FALSE),
      '#states'        => [
        'visible' => [':input[name="step5[pci_enabled]"]' => ['checked' => TRUE]],
      ],
    ];

    $form['step5']['export_format'] = [
      '#type'          => 'select',
      '#title'         => $this->t('Script inventory export format'),
      '#options'       => [
        'csv'  => $this->t('CSV'),
        'json' => $this->t('JSON'),
      ],
      '#default_value' => $wizardPci['export_format'] ?? ($savedPci['export_format'] ?? 'csv'),
      '#states'        => [
        'visible' => [':input[name="step5[pci_enabled]"]' => ['checked' => TRUE]],
      ],
    ];

    return $form;
  }

  /**
   * Builds Step 6: Review and save.
   */
  private function buildStep6(array $form, FormStateInterface $form_state): array {
    $values = $form_state->get('wizard_values') ?? [];

    // Temporarily apply wizard values to config for policy preview.
    $this->applyWizardValuesToConfig($values);
    $previewHeader = $this->policyBuilder->buildHeader();
    $this->configFactory->reset('csp_wizard.settings');

    $form['step6'] = [
      '#type'  => 'details',
      '#title' => $this->t('Step 6: Review & Save'),
      '#open'  => TRUE,
    ];

    $form['step6']['summary'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<p>' . $this->t('Review the generated Content Security Policy header below. Click <strong>Save Configuration</strong> to apply it.') . '</p>'
      ),
    ];

    $form['step6']['policy_preview'] = [
      '#type'        => 'details',
      '#title'       => $this->t('Generated CSP Header'),
      '#open'        => TRUE,
      'header_value' => [
        '#type'   => 'markup',
        '#markup' => Markup::create(
          '<pre style="white-space: pre-wrap; word-break: break-all;">'
          . Html::escape($previewHeader)
          . '</pre>'
        ),
      ],
    ];

    $mode = $values['mode'] ?? 'report_only';
    $form['step6']['mode_summary'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<p>' . $this->t('Mode: <strong>@mode</strong>', [
          '@mode' => $mode === 'enforce' ? 'Enforce' : 'Report-Only',
        ]) . '</p>'
      ),
    ];

    // SRI recommendation.
    $form['step6']['sri_note'] = [
      '#type'   => 'markup',
      '#markup' => Markup::create(
        '<div class="messages messages--info" role="status">'
        . $this->t('<strong>Recommendation:</strong> Consider adding <code>integrity</code> attributes to external <code>&lt;script&gt;</code> tags for Subresource Integrity (SRI) protection. See <a href=":url" target="_blank" rel="noreferrer noopener">Drupal Libraries API SRI documentation</a>.', [
          ':url' => 'https://www.drupal.org/docs/develop/theming-drupal/adding-stylesheets-css-and-javascript-js-to-a-drupal-theme#integrity',
        ])
        . '</div>'
      ),
    ];

    if ($values['services']['ckeditor5'] ?? FALSE) {
      $form['step6']['ckeditor5_note'] = [
        '#type'   => 'markup',
        '#markup' => Markup::create(
          '<div class="messages messages--warning" role="alert">'
          . $this->t('<strong>CKEditor5 note:</strong> CKEditor5 requires <code>style-src \'unsafe-inline\'</code> for the classic build. This is a known limitation of the editor. See <a href=":url" target="_blank" rel="noreferrer noopener">CKEditor5 CSP documentation</a>.', [
            ':url' => 'https://ckeditor.com/docs/ckeditor5/latest/installation/getting-started/predefined-builds.html',
          ])
          . '</div>'
        ),
      ];
    }

    return $form;
  }

  // ---------------------------------------------------------------------------
  // Navigation handlers
  // ---------------------------------------------------------------------------

  /**
   * Submit handler that advances to the next step.
   */
  public function goNext(array &$form, FormStateInterface $form_state): void {
    $step = (int) ($form_state->get('step') ?? 1);
    $this->persistStepValues($step, $form_state);
    $form_state->set('step', $step + 1);
    $form_state->setRebuild(TRUE);
  }

  /**
   * Submit handler that goes back to the previous step.
   */
  public function goBack(array &$form, FormStateInterface $form_state): void {
    $step = (int) ($form_state->get('step') ?? 1);
    $form_state->set('step', max(1, $step - 1));
    $form_state->setRebuild(TRUE);
  }

  // ---------------------------------------------------------------------------
  // Validation
  // ---------------------------------------------------------------------------

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $step = (int) ($form_state->get('step') ?? 1);

    if ($step === 2) {
      $customDomainsRaw = trim((string) ($form_state->getValue(['step2', 'custom_domains']) ?? ''));
      if ($customDomainsRaw !== '') {
        foreach (explode("\n", $customDomainsRaw) as $domain) {
          $domain = trim($domain);
          if ($domain === '') {
            continue;
          }
          if (!preg_match('/^[a-zA-Z0-9\-\.\:\_\*\/]+$/', $domain)) {
            $form_state->setErrorByName(
              'step2][custom_domains',
              $this->t('Invalid custom domain "@domain". Only alphanumeric characters, hyphens, dots, colons, underscores, asterisks, and slashes are allowed.', ['@domain' => Html::escape($domain)])
            );
          }
        }
      }
    }

    if ($step === 4) {
      $siemUrl = trim((string) ($form_state->getValue(['step4', 'report_siem_url']) ?? ''));
      if ($siemUrl !== '') {
        if (!UrlHelper::isValid($siemUrl, TRUE) || !str_starts_with($siemUrl, 'https://')) {
          $form_state->setErrorByName('step4][report_siem_url', $this->t('The SIEM webhook URL must be a valid HTTPS URL.'));
        }
      }
    }

    if ($step === 5) {
      $patternsRaw = trim((string) ($form_state->getValue(['step5', 'page_patterns']) ?? ''));
      if ($patternsRaw !== '') {
        foreach (explode("\n", $patternsRaw) as $pattern) {
          $pattern = trim($pattern);
          if ($pattern === '') {
            continue;
          }
          if (!str_starts_with($pattern, '/')) {
            $form_state->setErrorByName(
              'step5][page_patterns',
              $this->t('Payment page patterns must begin with a forward slash (/). Invalid pattern: @pattern', ['@pattern' => Html::escape($pattern)])
            );
          }
          if (str_contains($pattern, "\r") || str_contains($pattern, "\n")) {
            $form_state->setErrorByName('step5][page_patterns', $this->t('Payment page patterns must not contain newline characters.'));
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Final save
  // ---------------------------------------------------------------------------

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $values = $form_state->get('wizard_values') ?? [];

    $config = $this->configFactory->getEditable('csp_wizard.settings');

    $config->set('mode', $values['mode'] ?? 'report_only');
    $config->set('nonce_enabled', (bool) ($values['nonce_enabled'] ?? TRUE));
    $config->set('nonce_bits', (int) ($values['nonce_bits'] ?? 256));
    $config->set('nonce_fallback', $values['nonce_fallback'] ?? "'unsafe-inline'");
    $config->set('report_uri_enabled', (bool) ($values['report_uri_enabled'] ?? TRUE));
    $config->set('report_siem_url', trim((string) ($values['report_siem_url'] ?? '')));
    $config->set('flood_limit', (int) ($values['flood_limit'] ?? 60));
    $config->set('flood_window', (int) ($values['flood_window'] ?? 60));

    // Services.
    $services = [
      'ckeditor5'    => (bool) ($values['services']['ckeditor5'] ?? FALSE),
      'gtm'          => (bool) ($values['services']['gtm'] ?? FALSE),
      'stripe'       => (bool) ($values['services']['stripe'] ?? FALSE),
      'youtube'      => (bool) ($values['services']['youtube'] ?? FALSE),
      'recaptcha_v2' => (bool) ($values['services']['recaptcha_v2'] ?? FALSE),
      'recaptcha_v3' => (bool) ($values['services']['recaptcha_v3'] ?? FALSE),
      'custom_domains' => $this->parseTextareaToList((string) ($values['custom_domains'] ?? '')),
    ];
    $config->set('services', $services);

    // PCI mode.
    $pciValues = $values['pci_mode'] ?? [];
    $config->set('pci_mode', [
      'enabled'       => (bool) ($pciValues['enabled'] ?? FALSE),
      'page_patterns' => $this->parseTextareaToList((string) ($pciValues['page_patterns'] ?? '')),
      'trusted_types' => (bool) ($pciValues['trusted_types'] ?? FALSE),
      'export_format' => (string) ($pciValues['export_format'] ?? 'csv'),
    ]);

    $config->save();

    $this->messenger->addStatus($this->t('CSP Wizard configuration has been saved.'));
    $form_state->setRedirectUrl(Url::fromRoute('csp_wizard.settings'));
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Persists form values for the given step into $form_state.
   */
  private function persistStepValues(int $step, FormStateInterface $form_state): void {
    $existing = $form_state->get('wizard_values') ?? [];

    switch ($step) {
      case 1:
        $existing['mode'] = (string) ($form_state->getValue(['step1', 'mode']) ?? 'report_only');
        break;

      case 2:
        $existing['services'] = [
          'ckeditor5'    => (bool) $form_state->getValue(['step2', 'ckeditor5']),
          'gtm'          => (bool) $form_state->getValue(['step2', 'gtm']),
          'stripe'       => (bool) $form_state->getValue(['step2', 'stripe']),
          'youtube'      => (bool) $form_state->getValue(['step2', 'youtube']),
          'recaptcha_v2' => (bool) $form_state->getValue(['step2', 'recaptcha_v2']),
          'recaptcha_v3' => (bool) $form_state->getValue(['step2', 'recaptcha_v3']),
        ];
        $existing['custom_domains'] = (string) ($form_state->getValue(['step2', 'custom_domains']) ?? '');
        break;

      case 3:
        $existing['nonce_enabled'] = (bool) $form_state->getValue(['step3', 'nonce_enabled']);
        $existing['nonce_bits']    = (int) ($form_state->getValue(['step3', 'nonce_bits']) ?? 256);
        $existing['nonce_fallback'] = (string) ($form_state->getValue(['step3', 'nonce_fallback']) ?? "'unsafe-inline'");
        break;

      case 4:
        $existing['report_uri_enabled'] = (bool) $form_state->getValue(['step4', 'report_uri_enabled']);
        $existing['report_siem_url']    = (string) ($form_state->getValue(['step4', 'report_siem_url']) ?? '');
        $existing['flood_limit']        = (int) ($form_state->getValue(['step4', 'flood_limit']) ?? 60);
        $existing['flood_window']       = (int) ($form_state->getValue(['step4', 'flood_window']) ?? 60);
        break;

      case 5:
        $existing['pci_mode'] = [
          'enabled'       => (bool) $form_state->getValue(['step5', 'pci_enabled']),
          'page_patterns' => (string) ($form_state->getValue(['step5', 'page_patterns']) ?? ''),
          'trusted_types' => (bool) $form_state->getValue(['step5', 'trusted_types']),
          'export_format' => (string) ($form_state->getValue(['step5', 'export_format']) ?? 'csv'),
        ];
        break;
    }

    $form_state->set('wizard_values', $existing);
  }

  /**
   * Temporarily writes wizard values into config for policy preview.
   *
   * @param array<string, mixed> $values
   *   The wizard_values array from $form_state.
   */
  private function applyWizardValuesToConfig(array $values): void {
    $config = $this->configFactory->getEditable('csp_wizard.settings');
    if (!empty($values['services'])) {
      $config->set('services', $values['services']);
    }
    if (isset($values['nonce_enabled'])) {
      $config->set('nonce_enabled', $values['nonce_enabled']);
    }
    // Do NOT save — this is for preview only.
  }

  /**
   * Parses a textarea string (one item per line) into a filtered list.
   *
   * @param string $raw
   *   Newline-separated values.
   *
   * @return list<string>
   *   Trimmed, non-empty values.
   */
  private function parseTextareaToList(string $raw): array {
    return array_values(array_filter(
      array_map('trim', explode("\n", $raw))
    ));
  }

}
