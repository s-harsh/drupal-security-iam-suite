<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\csp_wizard\Service\CspPolicyBuilderService;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Streams the PCI DSS 6.4.3 script inventory export.
 *
 * Supports CSV and JSON formats as configured in csp_wizard.settings
 * pci_mode.export_format. The exported inventory satisfies the PCI DSS
 * Requirement 6.4.3 authorised script inventory obligation.
 */
final class CspPciExportController implements ContainerInjectionInterface {

  /**
   * Constructs a CspPciExportController.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\csp_wizard\Service\CspPolicyBuilderService $policyBuilder
   *   The CSP policy builder service.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly CspPolicyBuilderService $policyBuilder,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('csp_wizard.policy_builder'),
    );
  }

  /**
   * Streams the script inventory as CSV or JSON for download.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A streamed file download response.
   */
  public function export(): Response {
    $config = $this->configFactory->get('csp_wizard.settings');
    $format = (string) ($config->get('pci_mode')['export_format'] ?? 'csv');
    $inventory = $this->policyBuilder->buildScriptInventory();

    if ($format === 'json') {
      return $this->exportJson($inventory);
    }

    return $this->exportCsv($inventory);
  }

  /**
   * Streams the inventory as a CSV download.
   *
   * @param list<array{directive: string, origin: string, rationale: string}> $inventory
   *   The script inventory rows.
   *
   * @return \Symfony\Component\HttpFoundation\StreamedResponse
   *   A streamed CSV response.
   */
  private function exportCsv(array $inventory): StreamedResponse {
    $response = new StreamedResponse(function () use ($inventory): void {
      $handle = fopen('php://output', 'w');
      if ($handle === FALSE) {
        return;
      }
      fputcsv($handle, ['Directive', 'Origin', 'Authorisation Rationale', 'Export Date']);
      $date = date('Y-m-d');
      foreach ($inventory as $row) {
        fputcsv($handle, [
          $row['directive'],
          $row['origin'],
          $row['rationale'],
          $date,
        ]);
      }
      fclose($handle);
    });

    $response->headers->set('Content-Type', 'text/csv; charset=UTF-8');
    $response->headers->set(
      'Content-Disposition',
      'attachment; filename="pci-script-inventory-' . date('Y-m-d') . '.csv"'
    );
    return $response;
  }

  /**
   * Returns the inventory as a JSON download.
   *
   * @param list<array{directive: string, origin: string, rationale: string}> $inventory
   *   The script inventory rows.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A JSON response with download headers.
   */
  private function exportJson(array $inventory): Response {
    $payload = json_encode(
      [
        'export_date' => date('Y-m-d'),
        'standard'    => 'PCI DSS v4.0 Requirement 6.4.3',
        'inventory'   => $inventory,
      ],
      JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    );

    $response = new Response($payload);
    $response->headers->set('Content-Type', 'application/json; charset=UTF-8');
    $response->headers->set(
      'Content-Disposition',
      'attachment; filename="pci-script-inventory-' . date('Y-m-d') . '.json"'
    );
    return $response;
  }

}
