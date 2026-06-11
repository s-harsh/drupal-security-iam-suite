<?php

declare(strict_types=1);

namespace Drupal\paranoia_reborn\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Datetime\DateFormatterInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Renders the Paranoia Reborn audit log page.
 *
 * Reads watchdog entries of type 'paranoia_reborn' and presents them in a
 * sortable table with the most recent entries first. Pagination is applied
 * at 50 rows per page.
 */
final class AuditLogController extends ControllerBase {

  /**
   * Constructs an AuditLogController.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Datetime\DateFormatterInterface $dateFormatter
   *   The date formatter service.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly DateFormatterInterface $dateFormatter,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('database'),
      $container->get('date.formatter'),
    );
  }

  /**
   * Builds and returns the audit log render array.
   *
   * @return array<string, mixed>
   *   A Drupal render array containing a paged table and summary.
   */
  public function page(): array {
    $header = [
      ['data' => $this->t('Timestamp'), 'field' => 'w.timestamp', 'sort' => 'desc'],
      ['data' => $this->t('Severity'), 'field' => 'w.severity'],
      ['data' => $this->t('Message')],
      ['data' => $this->t('Hostname'), 'field' => 'w.hostname'],
      ['data' => $this->t('UID'), 'field' => 'w.uid'],
    ];

    $query = $this->database->select('watchdog', 'w')
      ->fields('w', ['wid', 'timestamp', 'severity', 'message', 'variables', 'hostname', 'uid'])
      ->condition('w.type', 'paranoia_reborn')
      ->extend('Drupal\Core\Database\Query\PagerSelectExtender')
      ->limit(50)
      ->extend('Drupal\Core\Database\Query\TableSortExtender')
      ->orderByHeader($header);

    $rows = [];

    try {
      $results = $query->execute();

      foreach ($results as $record) {
        // Unserialize variables for message substitution.
        $variables = @unserialize((string) $record->variables, ['allowed_classes' => FALSE]);
        $message   = is_array($variables)
          ? strtr((string) $record->message, $variables)
          : (string) $record->message;

        $rows[] = [
          $this->dateFormatter->format((int) $record->timestamp, 'short'),
          $this->severityLabel((int) $record->severity),
          ['data' => ['#markup' => htmlspecialchars($message, ENT_QUOTES, 'UTF-8')]],
          (string) $record->hostname,
          (string) $record->uid,
        ];
      }
    }
    catch (\Exception $e) {
      $rows[] = [
        [
          'data'    => ['#markup' => $this->t('Unable to query audit log: @msg', ['@msg' => $e->getMessage()])],
          'colspan' => 5,
        ],
      ];
    }

    $build['table'] = [
      '#type'       => 'table',
      '#header'     => $header,
      '#rows'       => $rows,
      '#empty'      => $this->t('No blocked-access attempts have been logged yet.'),
      '#attributes' => ['class' => ['paranoia-reborn-audit-log']],
    ];

    $build['pager'] = ['#type' => 'pager'];

    return $build;
  }

  /**
   * Converts a watchdog severity integer to a human-readable label.
   *
   * @param int $severity
   *   WATCHDOG_* severity constant.
   *
   * @return string
   */
  private function severityLabel(int $severity): string {
    return match ($severity) {
      0 => 'Emergency',
      1 => 'Alert',
      2 => 'Critical',
      3 => 'Error',
      4 => 'Warning',
      5 => 'Notice',
      6 => 'Info',
      7 => 'Debug',
      default => (string) $severity,
    };
  }

}
