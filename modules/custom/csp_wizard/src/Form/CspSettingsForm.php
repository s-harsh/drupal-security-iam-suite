<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Form;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Quick-edit settings form for CSP Wizard.
 *
 * Provides a flat settings form for administrators who have already run the
 * wizard and need to tweak individual settings (mode, flood, SIEM URL) without
 * re-running all six steps.
 */
final class CspSettingsForm extends ConfigFormBase {

  use StringTranslationTrait;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static($container->get('config.factory'));
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['csp_wizard.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'csp_wizard_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('csp_wizard.settings');
    $mode = (string) ($config->get('mode') ?? 'report_only');

    // Report-Only mode notice banner.
    if ($mode === 'report_only') {
      $form['report_only_banner'] = [
        '#type'       => 'markup',
        '#markup'     => \Drupal\Core\Render\Markup::create(
          '<div class="messages messages--warning" role="alert">'
          . $this->t('<strong>Report-Only mode active</strong> — the Content Security Policy is <em>not</em> blocking anything. Violations are being logged. <a href=":url" data-drupal-confirm="Are you sure you want to switch to enforcement mode? This will immediately block disallowed resources.">Switch to Enforcement mode</a>.', [
            ':url' => Url::fromRoute('csp_wizard.toggle_mode', [], [
              'query' => [\Drupal::service('csrf_token')->get('csp_wizard/toggle-mode') => '1'],
            ])->toString(),
          ])
          . '</div>'
        ),
        '#weight'     => -100,
      ];
    }

    $form['mode_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('CSP Mode'),
      '#open'  => TRUE,
    ];

    $form['mode_section']['mode'] = [
      '#type'          => 'radios',
      '#title'         => $this->t('Content Security Policy mode'),
      '#options'       => [
        'report_only' => $this->t('Report-Only — log violations without blocking (recommended during rollout)'),
        'enforce'     => $this->t('Enforce — actively block policy violations'),
      ],
      '#default_value' => $mode,
      '#required'      => TRUE,
    ];

    $form['nonce_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Nonce Injection'),
      '#open'  => TRUE,
    ];

    $form['nonce_section']['nonce_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable per-request nonce injection'),
      '#description'   => $this->t('Adds a cryptographically random <code>nonce</code> attribute to every inline <code>&lt;script&gt;</code> tag on each request. Required for a strict CSP without <code>unsafe-inline</code>.'),
      '#default_value' => (bool) $config->get('nonce_enabled'),
    ];

    $form['nonce_section']['nonce_bits'] = [
      '#type'          => 'select',
      '#title'         => $this->t('Nonce entropy'),
      '#options'       => [
        128 => $this->t('128 bits'),
        192 => $this->t('192 bits'),
        256 => $this->t('256 bits (recommended)'),
      ],
      '#default_value' => (int) ($config->get('nonce_bits') ?? 256),
    ];

    $form['reporting_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Violation Reporting'),
      '#open'  => TRUE,
    ];

    $form['reporting_section']['report_uri_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable on-site violation report endpoint'),
      '#description'   => $this->t('Configures browsers to POST violation reports to <code>/csp-wizard/report</code> and logs them to the Drupal watchdog.'),
      '#default_value' => (bool) $config->get('report_uri_enabled'),
    ];

    $form['reporting_section']['report_siem_url'] = [
      '#type'          => 'url',
      '#title'         => $this->t('External SIEM webhook URL'),
      '#description'   => $this->t('Optional HTTPS URL to forward raw violation payloads to a Security Information and Event Management system. Must use HTTPS. Leave empty to disable forwarding.'),
      '#default_value' => (string) ($config->get('report_siem_url') ?? ''),
      '#maxlength'     => 2048,
    ];

    $form['flood_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Flood Control'),
      '#open'  => FALSE,
    ];

    $form['flood_section']['flood_limit'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Maximum violation reports per IP per window'),
      '#min'           => 1,
      '#max'           => 3600,
      '#default_value' => (int) ($config->get('flood_limit') ?? 60),
      '#description'   => $this->t('Requests exceeding this limit per window receive HTTP 429.'),
    ];

    $form['flood_section']['flood_window'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Flood control window (seconds)'),
      '#min'           => 1,
      '#max'           => 3600,
      '#default_value' => (int) ($config->get('flood_window') ?? 60),
    ];

    $form['wizard_link'] = [
      '#type'   => 'markup',
      '#markup' => \Drupal\Core\Render\Markup::create(
        '<p>' . $this->t('<a href=":url">Run the full six-step Policy Wizard</a> to configure third-party service profiles and review the complete generated policy.', [
          ':url' => Url::fromRoute('csp_wizard.wizard')->toString(),
        ]) . '</p>'
      ),
      '#weight' => 100,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    $siemUrl = trim((string) $form_state->getValue('report_siem_url'));
    if ($siemUrl !== '') {
      if (!UrlHelper::isValid($siemUrl, TRUE)) {
        $form_state->setErrorByName('report_siem_url', $this->t('The SIEM webhook URL is not a valid external URL.'));
      }
      elseif (!str_starts_with($siemUrl, 'https://')) {
        $form_state->setErrorByName('report_siem_url', $this->t('The SIEM webhook URL must use HTTPS.'));
      }
    }

    $floodLimit = (int) $form_state->getValue('flood_limit');
    if ($floodLimit < 1 || $floodLimit > 3600) {
      $form_state->setErrorByName('flood_limit', $this->t('Flood limit must be between 1 and 3600.'));
    }

    $floodWindow = (int) $form_state->getValue('flood_window');
    if ($floodWindow < 1 || $floodWindow > 3600) {
      $form_state->setErrorByName('flood_window', $this->t('Flood window must be between 1 and 3600 seconds.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config('csp_wizard.settings')
      ->set('mode', $form_state->getValue('mode'))
      ->set('nonce_enabled', (bool) $form_state->getValue('nonce_enabled'))
      ->set('nonce_bits', (int) $form_state->getValue('nonce_bits'))
      ->set('report_uri_enabled', (bool) $form_state->getValue('report_uri_enabled'))
      ->set('report_siem_url', trim((string) $form_state->getValue('report_siem_url')))
      ->set('flood_limit', (int) $form_state->getValue('flood_limit'))
      ->set('flood_window', (int) $form_state->getValue('flood_window'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
