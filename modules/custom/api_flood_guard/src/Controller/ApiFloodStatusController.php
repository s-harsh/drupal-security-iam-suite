<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Controller;

use Drupal\Component\Utility\Html;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Link;
use Drupal\Core\Render\Markup;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller for the API Flood Guard log and flood state data endpoints.
 */
final class ApiFloodStatusController extends ControllerBase {

  public function __construct(
    private readonly Connection $database,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static($container->get('database'));
  }

  /**
   * Renders the recent block events log page.
   *
   * Queries the watchdog table for api_flood_guard entries, filtered by
   * optional severity, with pagination.
   */
  public function logPage(Request $request): array {
    $severity = $request->query->get('severity', '');
    $page = max(0, (int) $request->query->get('page', 0));
    $limit = 50;

    $rows = [];
    $total = 0;

    if (!$this->database->schema()->tableExists('watchdog')) {
      return [
        '#markup' => $this->t('The dblog module is not enabled. Enable it to view block event logs here.'),
      ];
    }

    $query = $this->database->select('watchdog', 'w')
      ->fields('w', ['wid', 'severity', 'timestamp', 'message', 'variables', 'hostname'])
      ->condition('w.type', 'api_flood_guard');

    if ($severity !== '' && is_numeric($severity)) {
      $query->condition('w.severity', (int) $severity);
    }

    $countQuery = clone $query;
    $total = (int) $countQuery->countQuery()->execute()->fetchField();

    $entries = $query
      ->orderBy('w.timestamp', 'DESC')
      ->range($page * $limit, $limit)
      ->execute()
      ->fetchAll();

    $severityLabels = [
      0 => $this->t('Emergency'),
      1 => $this->t('Alert'),
      2 => $this->t('Critical'),
      3 => $this->t('Error'),
      4 => $this->t('Warning'),
      5 => $this->t('Notice'),
      6 => $this->t('Info'),
      7 => $this->t('Debug'),
    ];

    foreach ($entries as $entry) {
      $variables = @unserialize((string) $entry->variables, ['allowed_classes' => FALSE]);
      if (!is_array($variables)) {
        $variables = [];
      }

      $message = $entry->message;
      foreach ($variables as $key => $value) {
        $message = str_replace($key, Html::escape((string) $value), $message);
      }

      $rows[] = [
        date('Y-m-d H:i:s', (int) $entry->timestamp),
        $severityLabels[$entry->severity] ?? $entry->severity,
        Markup::create($message),
        $entry->hostname,
      ];
    }

    $build = [];

    // Severity filter.
    $build['filter_form'] = [
      '#type'   => 'html_tag',
      '#tag'    => 'p',
      '#value'  => '',
    ];

    $build['table'] = [
      '#type'    => 'table',
      '#header'  => [
        $this->t('Timestamp'),
        $this->t('Severity'),
        $this->t('Message'),
        $this->t('Hostname'),
      ],
      '#rows'    => $rows,
      '#empty'   => $this->t('No API Flood Guard block events found.'),
      '#caption' => $this->t('Showing @count of @total entries.', [
        '@count' => count($rows),
        '@total' => $total,
      ]),
    ];

    // Pagination links.
    if ($total > $limit) {
      $totalPages = (int) ceil($total / $limit);
      $pagerLinks = [];
      for ($i = 0; $i < min($totalPages, 20); $i++) {
        $pagerLinks[] = Link::fromTextAndUrl(
          (string) ($i + 1),
          Url::fromRoute('api_flood_guard.log', [], ['query' => ['page' => $i]])
        )->toString();
      }
      $build['pager'] = [
        '#markup' => '<p>' . $this->t('Pages: @links', ['@links' => implode(' | ', $pagerLinks)]) . '</p>',
      ];
    }

    return $build;
  }

  /**
   * Returns current flood state as JSON for the auto-refresh endpoint.
   *
   * Used by flood-state-refresh.js to update the table without a full page
   * reload.
   */
  public function floodStateData(): JsonResponse {
    $now = time();

    $entries = $this->database->select('flood', 'f')
      ->fields('f', ['fid', 'event', 'identifier', 'expiration'])
      ->condition('f.event', 'api_flood_guard.%', 'LIKE')
      ->condition('f.expiration', $now, '>')
      ->orderBy('f.expiration', 'DESC')
      ->range(0, 200)
      ->execute()
      ->fetchAll();

    $data = [];
    foreach ($entries as $entry) {
      $identifier = (string) $entry->identifier;
      $data[] = [
        'fid'        => (int) $entry->fid,
        'event'      => $entry->event,
        'identifier' => strlen($identifier) > 20 ? substr($identifier, 0, 20) . '...' : $identifier,
        'expiration' => date('H:i:s', (int) $entry->expiration),
        'remaining'  => max(0, (int) $entry->expiration - $now),
      ];
    }

    return new JsonResponse([
      'entries'   => $data,
      'timestamp' => $now,
      'count'     => count($data),
    ]);
  }

}
