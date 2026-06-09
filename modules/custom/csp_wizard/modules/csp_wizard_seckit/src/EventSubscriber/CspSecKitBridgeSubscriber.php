<?php

declare(strict_types=1);

namespace Drupal\csp_wizard_seckit\EventSubscriber;

use Drupal\Core\Config\ConfigEvents;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ConfigCrudEvent;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\csp_wizard\Service\CspPolicyBuilderService;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Synchronises the generated CSP policy into SecKit configuration.
 *
 * When both csp_wizard_seckit and the seckit module are enabled, this
 * subscriber listens for saves to csp_wizard.settings and automatically
 * writes the generated policy header string into seckit.settings.
 *
 * It then sets csp_wizard.settings:seckit_bridge_active = true to signal
 * CspHeaderSubscriber to yield header control to SecKit, preventing duplicate
 * Content-Security-Policy headers.
 */
final class CspSecKitBridgeSubscriber implements EventSubscriberInterface {

  /**
   * Constructs a CspSecKitBridgeSubscriber.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\csp_wizard\Service\CspPolicyBuilderService $policyBuilder
   *   The CSP policy builder service.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly CspPolicyBuilderService $policyBuilder,
    private readonly ModuleHandlerInterface $moduleHandler,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      ConfigEvents::SAVE => ['onConfigSave', 0],
    ];
  }

  /**
   * Syncs the generated CSP policy into SecKit when csp_wizard.settings saved.
   *
   * @param \Drupal\Core\Config\ConfigCrudEvent $event
   *   The config save event.
   *
   * @return void
   */
  public function onConfigSave(ConfigCrudEvent $event): void {
    if ($event->getConfig()->getName() !== 'csp_wizard.settings') {
      return;
    }

    if (!$this->moduleHandler->moduleExists('seckit')) {
      return;
    }

    $policyHeader = $this->policyBuilder->buildHeader();

    $seckitSettings = $this->configFactory->getEditable('seckit.settings');

    // SecKit stores its CSP directives under the 'csp' key.
    // Write the full generated policy string into seckit's custom policy field.
    $seckitSettings
      ->set('csp.policy-uri', '')
      ->set('csp.default-src', $policyHeader)
      ->save();

    // Signal CspHeaderSubscriber to yield control to SecKit.
    $this->configFactory->getEditable('csp_wizard.settings')
      ->set('seckit_bridge_active', TRUE)
      ->save();
  }

}
