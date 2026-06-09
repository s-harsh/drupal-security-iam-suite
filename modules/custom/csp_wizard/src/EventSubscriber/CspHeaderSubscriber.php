<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\csp_wizard\Service\CspPolicyBuilderService;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Writes the Content-Security-Policy header to all HTML responses.
 *
 * Subscribes to KernelEvents::RESPONSE at priority -10 so it runs after the
 * full page is assembled but before the response is sent. Non-HTML responses
 * are skipped. Yields to SecKit when the bridge module has taken ownership.
 * Guards against header injection by rejecting policy strings containing
 * CR or LF characters.
 */
final class CspHeaderSubscriber implements EventSubscriberInterface {

  /**
   * Constructs a CspHeaderSubscriber.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\csp_wizard\Service\CspPolicyBuilderService $policyBuilder
   *   The CSP policy builder service.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler, used to check for conflicting modules.
   * @param \Psr\Log\LoggerInterface $logger
   *   The csp_wizard logger channel.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly CspPolicyBuilderService $policyBuilder,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      KernelEvents::RESPONSE => ['onResponse', -10],
    ];
  }

  /**
   * Writes the CSP header to HTML responses.
   *
   * @param \Symfony\Component\HttpKernel\Event\ResponseEvent $event
   *   The response event.
   *
   * @return void
   */
  public function onResponse(ResponseEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }

    $response = $event->getResponse();
    $contentType = $response->headers->get('Content-Type', '');

    // Skip non-HTML responses (JSON, file downloads, etc.).
    if (!str_contains($contentType, 'text/html')) {
      return;
    }

    $config = $this->configFactory->get('csp_wizard.settings');

    // Yield to SecKit when the bridge sub-module has taken header control.
    if ((bool) $config->get('seckit_bridge_active')) {
      return;
    }

    // Determine whether the current request path is a payment page.
    $request = $event->getRequest();
    $requestPath = $request->getPathInfo();
    $pciMode = $config->get('pci_mode') ?? [];
    $pciEnabled = !empty($pciMode['enabled']);

    if ($pciEnabled && $this->isPaymentPage($requestPath, $pciMode['page_patterns'] ?? [])) {
      $policyString = $this->policyBuilder->buildPaymentHeader();
    }
    else {
      $policyString = $this->policyBuilder->buildHeader();
    }

    // Guard against header injection.
    if (str_contains($policyString, "\r") || str_contains($policyString, "\n")) {
      $this->logger->critical(
        'CSP Wizard: header injection attempt detected in assembled policy. Using empty fallback policy.'
      );
      $policyString = '';
    }

    // An empty policy string means no CSP header is written.
    if ($policyString === '') {
      return;
    }

    $mode = (string) $config->get('mode');
    $headerName = $mode === 'enforce'
      ? 'Content-Security-Policy'
      : 'Content-Security-Policy-Report-Only';

    $response->headers->set($headerName, $policyString);

    // Write Reporting-Endpoints header for Reporting API Level 1 support.
    if ((bool) $config->get('report_uri_enabled')) {
      $reportPath = (string) ($config->get('report_uri_path') ?: '/csp-wizard/report');
      $response->headers->set(
        'Reporting-Endpoints',
        "csp-wizard-endpoint=\"{$reportPath}\""
      );
    }
  }

  /**
   * Checks whether a path matches any of the configured payment page patterns.
   *
   * Patterns support trailing /** wildcards (e.g. /checkout/**).
   *
   * @param string $path
   *   The request path (e.g. /checkout/step-1).
   * @param list<string> $patterns
   *   Glob-style path patterns.
   *
   * @return bool
   *   TRUE if the path matches at least one pattern.
   */
  private function isPaymentPage(string $path, array $patterns): bool {
    foreach ($patterns as $pattern) {
      $pattern = (string) $pattern;
      if (str_ends_with($pattern, '/**')) {
        $prefix = rtrim(substr($pattern, 0, -3), '/');
        if ($path === $prefix || str_starts_with($path, $prefix . '/')) {
          return TRUE;
        }
      }
      elseif ($pattern === $path) {
        return TRUE;
      }
    }
    return FALSE;
  }

}
