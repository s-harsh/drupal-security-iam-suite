<?php

declare(strict_types=1);

namespace Drupal\hibp_password_guard\Form;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Administration settings form for the HIBP Password Guard module.
 *
 * Exposes the five configuration keys from hibp_password_guard.settings:
 *   - enabled: global on/off switch
 *   - cache_ttl: HIBP range response cache lifetime in seconds
 *   - fail_mode: fail_open or fail_closed degradation behaviour
 *   - http_timeout: Guzzle connect + read timeout in seconds
 *   - api_base_url: override for self-hosted or proxied HIBP instances
 */
final class HibpPasswordGuardSettingsForm extends ConfigFormBase {

  /**
   * The module settings config object name.
   */
  private const CONFIG_NAME = 'hibp_password_guard.settings';

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
    return [self::CONFIG_NAME];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'hibp_password_guard_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config(self::CONFIG_NAME);

    $form['global'] = [
      '#type' => 'details',
      '#title' => $this->t('Global settings'),
      '#open' => TRUE,
    ];

    $form['global']['enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable HIBP breach checking'),
      '#description' => $this->t(
        'When unchecked, the HIBP Password Guard constraint plugin always passes without making any HTTP call. Individual constraint instances within password policies are still visible in the UI but are effectively disabled.',
      ),
      '#default_value' => (bool) $config->get('enabled'),
    ];

    $form['api'] = [
      '#type' => 'details',
      '#title' => $this->t('API settings'),
      '#open' => TRUE,
    ];

    $form['api']['api_base_url'] = [
      '#type' => 'textfield',
      '#title' => $this->t('HIBP API base URL'),
      '#description' => $this->t(
        'The base URL for the Pwned Passwords Range API. Use the default <code>https://api.pwnedpasswords.com</code> for the official service. Override only if you operate a local mirror, corporate proxy, or self-hosted instance. TLS certificate verification is always enforced.',
      ),
      '#default_value' => (string) $config->get('api_base_url'),
      '#required' => TRUE,
      '#maxlength' => 255,
    ];

    $form['api']['http_timeout'] = [
      '#type' => 'number',
      '#title' => $this->t('HTTP request timeout'),
      '#description' => $this->t(
        'Maximum wall-clock time in seconds for a single HIBP API request (connect + read combined). Minimum 1, maximum 30.',
      ),
      '#default_value' => (int) $config->get('http_timeout'),
      '#required' => TRUE,
      '#min' => 1,
      '#max' => 30,
      '#step' => 1,
      '#field_suffix' => $this->t('seconds'),
    ];

    $form['caching'] = [
      '#type' => 'details',
      '#title' => $this->t('Caching'),
      '#open' => TRUE,
    ];

    $form['caching']['cache_ttl'] = [
      '#type' => 'number',
      '#title' => $this->t('Cache TTL'),
      '#description' => $this->t(
        'How long (in seconds) a successful HIBP API response is cached per 5-character SHA-1 prefix. Default is 86400 (24 hours). Set to 0 to disable caching — not recommended for production as each password entry will trigger an outbound HTTP request.',
      ),
      '#default_value' => (int) $config->get('cache_ttl'),
      '#required' => TRUE,
      '#min' => 0,
      '#step' => 1,
      '#field_suffix' => $this->t('seconds'),
    ];

    $form['degradation'] = [
      '#type' => 'details',
      '#title' => $this->t('Degradation mode'),
      '#open' => TRUE,
    ];

    $form['degradation']['fail_mode'] = [
      '#type' => 'radios',
      '#title' => $this->t('API unavailability behaviour'),
      '#description' => $this->t(
        '<strong>Fail open</strong> (default): when the HIBP API cannot be reached, the password check is skipped and the password is accepted. A watchdog notice is logged. Recommended for most sites to avoid locking users out during transient API outages.<br><strong>Fail closed</strong>: when the HIBP API is unreachable, the password change is blocked with a user-facing message. Recommended for high-security environments where enforcement takes priority over availability.',
      ),
      '#options' => [
        'fail_open' => $this->t('Fail open — accept password when API is unavailable'),
        'fail_closed' => $this->t('Fail closed — block password when API is unavailable'),
      ],
      '#default_value' => (string) $config->get('fail_mode'),
      '#required' => TRUE,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    $cacheTtl = $form_state->getValue('cache_ttl');
    if (!is_numeric($cacheTtl) || (int) $cacheTtl < 0) {
      $form_state->setErrorByName('cache_ttl', $this->t('Cache TTL must be a non-negative integer.'));
    }

    $httpTimeout = $form_state->getValue('http_timeout');
    if (!is_numeric($httpTimeout) || (int) $httpTimeout < 1 || (int) $httpTimeout > 30) {
      $form_state->setErrorByName('http_timeout', $this->t('HTTP timeout must be an integer between 1 and 30.'));
    }

    $failMode = $form_state->getValue('fail_mode');
    if (!in_array($failMode, ['fail_open', 'fail_closed'], strict: true)) {
      $form_state->setErrorByName('fail_mode', $this->t('Degradation mode must be either "fail_open" or "fail_closed".'));
    }

    $apiBaseUrl = trim((string) $form_state->getValue('api_base_url'));
    if (!UrlHelper::isValid($apiBaseUrl, absolute: true)) {
      $form_state->setErrorByName('api_base_url', $this->t('The HIBP API base URL must be a valid absolute URL (e.g. https://api.pwnedpasswords.com).'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config(self::CONFIG_NAME)
      ->set('enabled', (bool) $form_state->getValue('enabled'))
      ->set('cache_ttl', (int) $form_state->getValue('cache_ttl'))
      ->set('fail_mode', (string) $form_state->getValue('fail_mode'))
      ->set('http_timeout', (int) $form_state->getValue('http_timeout'))
      ->set('api_base_url', trim((string) $form_state->getValue('api_base_url')))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
