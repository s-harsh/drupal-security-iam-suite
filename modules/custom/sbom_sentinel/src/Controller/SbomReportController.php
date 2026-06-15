<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\sbom_sentinel\Service\NisRiskScorer;
use Drupal\sbom_sentinel\Service\SbomGenerator;
use Drupal\sbom_sentinel\Value\CveResult;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller for the SBOM Sentinel component risk report page.
 *
 * Renders a sortable admin table of installed Composer components showing
 * CVE count, NIS2 severity badge, max CVSS score, and direct OSV links.
 * Triggers a fresh scan if no cached results exist.
 */
final class SbomReportController extends ControllerBase {

  /**
   * NIS2 badge CSS colour classes for each risk level.
   */
  private const BADGE_CLASSES = [
    NisRiskScorer::LEVEL_CRITICAL => 'error',
    NisRiskScorer::LEVEL_HIGH => 'error',
    NisRiskScorer::LEVEL_MEDIUM => 'warning',
    NisRiskScorer::LEVEL_LOW => 'status',
    NisRiskScorer::LEVEL_NONE => 'status',
  ];

  /**
   * Constructs an SbomReportController.
   *
   * @param \Drupal\sbom_sentinel\Service\SbomGenerator $sbomGenerator
   *   The SBOM generator service.
   */
  public function __construct(
    private readonly SbomGenerator $sbomGenerator,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static($container->get('sbom_sentinel.sbom_generator'));
  }

  /**
   * Renders the component risk report page.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request (used for sort query parameters).
   *
   * @return array<string, mixed>
   *   A Drupal render array.
   */
  public function reportPage(Request $request): array {
    $scanData = $this->sbomGenerator->getCachedResults();
    if ($scanData === NULL) {
      // No cached results — run a fresh scan on first visit.
      $scanData = $this->sbomGenerator->scan();
    }

    /** @var array<string, CveResult> $results */
    $results = $scanData['results'] ?? [];
    $componentCount = (int) ($scanData['component_count'] ?? 0);
    $scannedAt = isset($scanData['scanned_at'])
      ? date('Y-m-d H:i:s', (int) $scanData['scanned_at'])
      : $this->t('unknown');

    // Determine sort parameters.
    $orderBy = (string) $request->query->get('order', 'risk');
    $direction = strtolower((string) $request->query->get('sort', 'desc'));
    $direction = in_array($direction, ['asc', 'desc'], strict: true) ? $direction : 'desc';

    $rows = $this->buildRows($results, $orderBy, $direction);

    $build = [];

    // Summary header.
    $vulnerableCount = count(array_filter($results, fn($r) => $r->hasVulnerabilities()));
    $errorCount = count(array_filter($results, fn($r) => $r->apiError));

    $build['summary'] = [
      '#type' => 'html_tag',
      '#tag' => 'p',
      '#value' => $this->t(
        'Scanned @total components on @date. @vuln vulnerable, @errors with scan errors.',
        [
          '@total' => $componentCount,
          '@date' => $scannedAt,
          '@vuln' => $vulnerableCount,
          '@errors' => $errorCount,
        ],
      ),
    ];

    // Export links.
    $build['export_links'] = [
      '#theme' => 'item_list',
      '#title' => $this->t('Export SBOM'),
      '#items' => [
        [
          '#markup' => '<a href="' . Url::fromRoute('sbom_sentinel.export.json')->toString() . '">'
            . $this->t('Download CycloneDX 1.6 JSON') . '</a>',
        ],
        [
          '#markup' => '<a href="' . Url::fromRoute('sbom_sentinel.export.xml')->toString() . '">'
            . $this->t('Download CycloneDX 1.6 XML') . '</a>',
        ],
      ],
    ];

    // Component risk table.
    $build['table'] = [
      '#type' => 'table',
      '#header' => $this->buildHeader($orderBy, $direction),
      '#rows' => $rows,
      '#empty' => $this->t('No components found. Ensure composer.lock exists at the configured path.'),
      '#attributes' => ['class' => ['sbom-sentinel-report']],
      '#caption' => $this->t(
        'NIS2 Article 21 supply chain risk assessment — @count component(s)',
        ['@count' => count($results)],
      ),
    ];

    $build['#cache'] = [
      'max-age' => 0,
    ];

    return $build;
  }

  /**
   * Builds the table header with sort links.
   *
   * @param string $orderBy
   *   The current sort column.
   * @param string $direction
   *   The current sort direction.
   *
   * @return array<int, mixed>
   *   A Drupal table header array.
   */
  private function buildHeader(string $orderBy, string $direction): array {
    $toggleDir = $direction === 'asc' ? 'desc' : 'asc';
    $baseRoute = 'sbom_sentinel.report';

    $sortLink = function (string $label, string $col) use ($orderBy, $direction, $toggleDir, $baseRoute): array {
      $sortDir = $col === $orderBy ? $toggleDir : 'asc';
      $indicator = '';
      if ($col === $orderBy) {
        $indicator = $direction === 'asc' ? ' ▲' : ' ▼';
      }
      return [
        'data' => [
          '#markup' => '<a href="' . Url::fromRoute($baseRoute, [], [
            'query' => ['order' => $col, 'sort' => $sortDir],
          ])->toString() . '">' . $label . $indicator . '</a>',
        ],
      ];
    };

    return [
      $sortLink($this->t('Package')->render(), 'name'),
      $sortLink($this->t('Version')->render(), 'version'),
      $sortLink($this->t('CVE Count')->render(), 'cve_count'),
      $sortLink($this->t('NIS2 Risk')->render(), 'risk'),
      $sortLink($this->t('Max CVSS')->render(), 'cvss'),
      ['data' => $this->t('Vulnerability IDs')],
      ['data' => $this->t('Status')],
    ];
  }

  /**
   * Builds and sorts the report table rows.
   *
   * @param array<string, CveResult> $results
   *   Scan results keyed by package name.
   * @param string $orderBy
   *   The sort column identifier.
   * @param string $direction
   *   'asc' or 'desc'.
   *
   * @return array<int, array<string, mixed>>
   *   Drupal table rows.
   */
  private function buildRows(array $results, string $orderBy, string $direction): array {
    // Sort the results.
    $sortedResults = array_values($results);
    usort($sortedResults, function (CveResult $a, CveResult $b) use ($orderBy): int {
      return match ($orderBy) {
        'name' => strcmp($a->packageName, $b->packageName),
        'version' => strcmp($a->packageVersion, $b->packageVersion),
        'cve_count' => $a->cveCount() <=> $b->cveCount(),
        'cvss' => $a->maxCvssScore <=> $b->maxCvssScore,
        'risk' => $this->riskLevelOrder($a->nisRiskLevel) <=> $this->riskLevelOrder($b->nisRiskLevel),
        default => $this->riskLevelOrder($a->nisRiskLevel) <=> $this->riskLevelOrder($b->nisRiskLevel),
      };
    });

    if ($direction === 'desc') {
      $sortedResults = array_reverse($sortedResults);
    }

    $rows = [];
    foreach ($sortedResults as $result) {
      $rows[] = $this->buildRow($result);
    }
    return $rows;
  }

  /**
   * Builds a single table row for one CveResult.
   *
   * @param \Drupal\sbom_sentinel\Value\CveResult $result
   *   The scan result for a single package.
   *
   * @return array<string, mixed>
   *   A Drupal table row.
   */
  private function buildRow(CveResult $result): array {
    // NIS2 severity badge.
    $badgeClass = self::BADGE_CLASSES[$result->nisRiskLevel] ?? 'status';
    $badgeLabel = $result->apiError
      ? $this->t('Scan error')
      : strtoupper($result->nisRiskLevel);
    $badge = '<span class="messages messages--' . $badgeClass . '" style="padding:2px 8px;display:inline-block">'
      . $badgeLabel . '</span>';

    // OSV vulnerability ID links.
    $osvLinks = [];
    foreach ($result->osvIds() as $osvId) {
      $osvUrl = 'https://osv.dev/vulnerability/' . htmlspecialchars($osvId, ENT_QUOTES, 'UTF-8');
      $osvLinks[] = '<a href="' . $osvUrl . '" target="_blank" rel="noopener noreferrer">'
        . htmlspecialchars($osvId, ENT_QUOTES, 'UTF-8') . '</a>';
    }
    $osvLinksMarkup = empty($osvLinks) ? '—' : implode(', ', $osvLinks);

    // Status column.
    if ($result->apiError) {
      $status = '<span title="' . htmlspecialchars($result->errorMessage, ENT_QUOTES, 'UTF-8')
        . '">' . $this->t('API error') . '</span>';
    }
    elseif ($result->hasVulnerabilities()) {
      $status = $this->t('Vulnerabilities found');
    }
    else {
      $status = $this->t('Clean');
    }

    return [
      'data' => [
        ['data' => ['#markup' => htmlspecialchars($result->packageName, ENT_QUOTES, 'UTF-8')]],
        ['data' => ['#markup' => htmlspecialchars($result->packageVersion, ENT_QUOTES, 'UTF-8')]],
        ['data' => ['#markup' => (string) $result->cveCount()]],
        ['data' => ['#markup' => $badge]],
        ['data' => ['#markup' => $result->maxCvssScore > 0 ? number_format($result->maxCvssScore, 1) : '—']],
        ['data' => ['#markup' => $osvLinksMarkup]],
        ['data' => ['#markup' => $status]],
      ],
    ];
  }

  /**
   * Returns a numeric sort order for a NIS2 risk level.
   *
   * @param string $level
   *   One of: 'critical', 'high', 'medium', 'low', 'none'.
   *
   * @return int
   *   A sort weight (higher = more severe).
   */
  private function riskLevelOrder(string $level): int {
    return match ($level) {
      NisRiskScorer::LEVEL_CRITICAL => 4,
      NisRiskScorer::LEVEL_HIGH => 3,
      NisRiskScorer::LEVEL_MEDIUM => 2,
      NisRiskScorer::LEVEL_LOW => 1,
      default => 0,
    };
  }

}
