<?php

declare(strict_types=1);

namespace Drupal\hibp_password_guard\Plugin\PasswordConstraint;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\hibp_password_guard\Service\HibpPasswordCheckerService;
use Drupal\password_policy\Plugin\PasswordConstraint\PasswordConstraintBase;
use Drupal\password_policy\PasswordPolicyResult;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Password Policy constraint plugin that rejects pwned passwords via HIBP.
 *
 * Uses the k-anonymity model: only a 5-character SHA-1 prefix is sent to
 * the HIBP Pwned Passwords Range API. The plaintext password never leaves
 * the server. API responses are cached per-prefix for the configured TTL.
 *
 * Plugin ID: hibp_compromised
 *
 * @PasswordConstraint(
 *   id = "hibp_compromised",
 *   label = @Translation("Not Pwned Password"),
 *   description = @Translation("Rejects passwords found in the Have I Been Pwned breach database using k-anonymity.")
 * )
 */
#[\Drupal\password_policy\Attribute\PasswordConstraint(
  id: 'hibp_compromised',
  label: new TranslatableMarkup('Not Pwned Password'),
  description: new TranslatableMarkup('Rejects passwords found in the Have I Been Pwned breach database using k-anonymity. Only a 5-character SHA-1 prefix is sent to the API.'),
)]
final class HibpCompromised extends PasswordConstraintBase {

  /**
   * The HIBP password checker service.
   */
  private HibpPasswordCheckerService $checkerService;

  /**
   * {@inheritdoc}
   */
  public static function create(
    ContainerInterface $container,
    array $configuration,
    $plugin_id,
    $plugin_definition,
  ): static {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->checkerService = $container->get('hibp_password_guard.checker');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function validate(string $password, $policy): PasswordPolicyResult {
    $result = $this->createResult();

    // Empty passwords are handled by other constraints.
    if ($password === '') {
      return $result;
    }

    $checkResult = $this->checkerService->check($password);

    if ($checkResult->apiError) {
      // The API was unavailable; fail_open/fail_closed was already resolved
      // inside HibpPasswordCheckerService. If isPwned is true here, it means
      // fail_closed mode is active.
      if ($checkResult->isPwned) {
        $result->setErrorMessage($this->t(
          'Password breach check is temporarily unavailable. Please try again later.',
        ));
      }
      return $result;
    }

    if ($checkResult->isPwned) {
      $result->setErrorMessage($this->t(
        'This password has appeared in a data breach @count time(s). Please choose a different password.',
        ['@count' => $checkResult->breachCount],
      ));
    }

    return $result;
  }

  /**
   * {@inheritdoc}
   */
  public function getSummary(): TranslatableMarkup {
    return $this->t('Password must not appear in the Have I Been Pwned breach database.');
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state): array {
    $form = parent::buildConfigurationForm($form, $form_state);
    $form['info'] = [
      '#markup' => $this->t(
        'This constraint uses the global <a href=":url">HIBP Password Guard settings</a>. No per-policy configuration is available in this version.',
        [':url' => '/admin/config/security/hibp-password-guard'],
      ),
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state): void {
    // No per-instance configuration to persist.
  }

  /**
   * Creates a new PasswordPolicyResult instance.
   *
   * @return \Drupal\password_policy\PasswordPolicyResult
   *   A new result object.
   */
  private function createResult(): PasswordPolicyResult {
    return new PasswordPolicyResult();
  }

}
