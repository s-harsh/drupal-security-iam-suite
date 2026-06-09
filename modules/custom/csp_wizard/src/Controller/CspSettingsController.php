<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Handles one-click CSP mode toggle (Report-Only ↔ Enforce).
 *
 * Route is CSRF-protected via _csrf_token: 'TRUE' in the routing definition.
 */
final class CspSettingsController implements ContainerInjectionInterface {

  use StringTranslationTrait;

  /**
   * Constructs a CspSettingsController.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly MessengerInterface $messenger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('messenger'),
    );
  }

  /**
   * Toggles the CSP mode between 'report_only' and 'enforce'.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   A redirect back to the CSP Wizard settings page.
   */
  public function toggleMode(): RedirectResponse {
    $config = $this->configFactory->getEditable('csp_wizard.settings');
    $currentMode = (string) ($config->get('mode') ?? 'report_only');
    $newMode = $currentMode === 'enforce' ? 'report_only' : 'enforce';

    $config->set('mode', $newMode)->save();

    $label = $newMode === 'enforce'
      ? $this->t('CSP mode switched to <strong>Enforcement</strong>. The Content-Security-Policy header is now active.')
      : $this->t('CSP mode switched to <strong>Report-Only</strong>. Violations will be logged but not blocked.');

    $this->messenger->addStatus($label);

    return new RedirectResponse(
      Url::fromRoute('csp_wizard.settings')->toString()
    );
  }

}
