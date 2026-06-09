<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Form;

use Drupal\Core\Database\Connection;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Flood state dashboard form.
 *
 * Displays active flood entries for api_flood_guard.* namespaces and provides
 * per-row clear actions and a bulk "Clear all" operation.
 */
final class ApiFloodStateForm extends FormBase {

  public function __construct(
    private readonly FloodInterface $flood,
    private readonly Connection $database,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('flood'),
      $container->get('database'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'api_flood_guard_flood_state_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $form['#attached']['library'][] = 'api_flood_guard/flood_state_refresh';

    $now = time();
    $entries = $this->getFloodEntries();

    $form['summary'] = [
      '#markup' => $this->t(
        '<p>Active flood entries for API Flood Guard namespaces as of @time. Auto-refreshes every 30 seconds.</p>',
        ['@time' => date('Y-m-d H:i:s', $now)]
      ),
    ];

    $header = [
      'fid'        => $this->t('ID'),
      'event'      => $this->t('Event'),
      'identifier' => $this->t('Identifier'),
      'expiration' => $this->t('Expires'),
      'operations' => $this->t('Operations'),
    ];

    $rows = [];
    foreach ($entries as $entry) {
      $expiry = (int) $entry->expiration;
      $remaining = max(0, $expiry - $now);
      $identifier = strlen((string) $entry->identifier) > 20
        ? substr((string) $entry->identifier, 0, 20) . '…'
        : (string) $entry->identifier;

      $rows[$entry->fid] = [
        'fid'        => $entry->fid,
        'event'      => $entry->event,
        'identifier' => $identifier,
        'expiration' => $this->t('@expiry (@remaining seconds remaining)', [
          '@expiry'    => date('H:i:s', $expiry),
          '@remaining' => $remaining,
        ]),
        'operations' => [
          'data' => [
            '#type'  => 'submit',
            '#name'  => 'clear_' . $entry->fid,
            '#value' => $this->t('Clear'),
            '#submit' => ['::clearSingleEntry'],
            '#flood_fid' => $entry->fid,
            '#flood_event' => $entry->event,
            '#flood_identifier' => $entry->identifier,
            '#limit_validation_errors' => [],
          ],
        ],
      ];
    }

    $form['entries'] = [
      '#type'    => 'table',
      '#header'  => $header,
      '#rows'    => [],
      '#empty'   => $this->t('No active API flood entries.'),
    ];

    // Build table with individual clear buttons as form elements.
    foreach ($entries as $entry) {
      $expiry = (int) $entry->expiration;
      $remaining = max(0, $expiry - $now);
      $identifier = strlen((string) $entry->identifier) > 20
        ? substr((string) $entry->identifier, 0, 20) . '…'
        : (string) $entry->identifier;

      $form['entries'][$entry->fid]['fid'] = [
        '#markup' => $entry->fid,
      ];
      $form['entries'][$entry->fid]['event'] = [
        '#markup' => $entry->event,
      ];
      $form['entries'][$entry->fid]['identifier'] = [
        '#markup' => $identifier,
      ];
      $form['entries'][$entry->fid]['expiration'] = [
        '#markup' => $this->t('@expiry (@remaining seconds remaining)', [
          '@expiry'    => date('H:i:s', $expiry),
          '@remaining' => $remaining,
        ]),
      ];
      $form['entries'][$entry->fid]['operations'] = [
        '#type'                    => 'submit',
        '#name'                    => 'clear_fid_' . $entry->fid,
        '#value'                   => $this->t('Clear'),
        '#submit'                  => ['::clearSingleEntry'],
        '#flood_fid'               => $entry->fid,
        '#flood_event'             => $entry->event,
        '#flood_identifier'        => $entry->identifier,
        '#limit_validation_errors' => [],
      ];
    }

    // Bulk operations.
    $form['bulk_actions'] = [
      '#type'  => 'details',
      '#title' => $this->t('Bulk Actions'),
      '#open'  => TRUE,
    ];

    $form['bulk_actions']['clear_all'] = [
      '#type'                    => 'submit',
      '#value'                   => $this->t('Clear all API flood entries'),
      '#submit'                  => ['::clearAllEntries'],
      '#limit_validation_errors' => [],
      '#attributes'              => ['class' => ['button--danger']],
    ];

    $form['bulk_actions']['clear_all_ip'] = [
      '#type'                    => 'submit',
      '#value'                   => $this->t('Clear all IP flood entries'),
      '#submit'                  => ['::clearAllIpEntries'],
      '#limit_validation_errors' => [],
    ];

    $form['bulk_actions']['clear_all_user'] = [
      '#type'                    => 'submit',
      '#value'                   => $this->t('Clear all username flood entries'),
      '#submit'                  => ['::clearAllUserEntries'],
      '#limit_validation_errors' => [],
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    // Default submit — does nothing; individual clear actions use named submits.
  }

  /**
   * Clears a single flood entry identified by the submit button's #flood_* properties.
   */
  public function clearSingleEntry(array &$form, FormStateInterface $form_state): void {
    $trigger = $form_state->getTriggeringElement();
    $event = $trigger['#flood_event'] ?? '';
    $identifier = $trigger['#flood_identifier'] ?? '';

    if ($event !== '' && $identifier !== '') {
      $this->flood->clear($event, $identifier);
      $this->messenger()->addStatus($this->t('Flood entry cleared.'));
    }

    $form_state->setRebuild(TRUE);
  }

  /**
   * Clears all api_flood_guard.* flood entries.
   */
  public function clearAllEntries(array &$form, FormStateInterface $form_state): void {
    $this->database->delete('flood')
      ->condition('event', 'api_flood_guard.%', 'LIKE')
      ->execute();

    $this->messenger()->addStatus($this->t('All API Flood Guard flood entries have been cleared.'));
    $form_state->setRebuild(TRUE);
  }

  /**
   * Clears only api_flood_guard.ip flood entries.
   */
  public function clearAllIpEntries(array &$form, FormStateInterface $form_state): void {
    $this->database->delete('flood')
      ->condition('event', 'api_flood_guard.ip')
      ->execute();

    $this->messenger()->addStatus($this->t('All API Flood Guard IP flood entries have been cleared.'));
    $form_state->setRebuild(TRUE);
  }

  /**
   * Clears only api_flood_guard.user flood entries.
   */
  public function clearAllUserEntries(array &$form, FormStateInterface $form_state): void {
    $this->database->delete('flood')
      ->condition('event', 'api_flood_guard.user')
      ->execute();

    $this->messenger()->addStatus($this->t('All API Flood Guard username flood entries have been cleared.'));
    $form_state->setRebuild(TRUE);
  }

  /**
   * Retrieves active (non-expired) flood entries for api_flood_guard.* namespaces.
   *
   * @return array
   *   Array of stdClass objects from the flood table.
   */
  private function getFloodEntries(): array {
    return $this->database->select('flood', 'f')
      ->fields('f', ['fid', 'event', 'identifier', 'expiration'])
      ->condition('f.event', 'api_flood_guard.%', 'LIKE')
      ->condition('f.expiration', time(), '>')
      ->orderBy('f.expiration', 'DESC')
      ->range(0, 200)
      ->execute()
      ->fetchAll();
  }

}
