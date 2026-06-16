<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Entity;

use Drupal\Core\Entity\Annotation\ContentEntityType;
use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;
use Drupal\zero_standing_privilege\Value\ElevationStatus;

/**
 * Defines the Elevation Request entity type.
 *
 * @ContentEntityType(
 *   id = "elevation_request",
 *   label = @Translation("Elevation Request"),
 *   label_collection = @Translation("Elevation Requests"),
 *   label_singular = @Translation("elevation request"),
 *   label_plural = @Translation("elevation requests"),
 *   label_count = @PluralTranslation(
 *     singular = "@count elevation request",
 *     plural = "@count elevation requests",
 *   ),
 *   handlers = {
 *     "storage" = "Drupal\Core\Entity\Sql\SqlContentEntityStorage",
 *     "list_builder" = "Drupal\Core\Entity\EntityListBuilder",
 *   },
 *   base_table = "zero_standing_privilege_request",
 *   entity_keys = {
 *     "id" = "id",
 *     "uuid" = "uuid",
 *     "label" = "id",
 *   },
 *   admin_permission = "administer zero standing privilege",
 * )
 */
class ElevationRequest extends ContentEntityBase implements ElevationRequestInterface {

  /**
   * {@inheritdoc}
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type): array {
    $fields = parent::baseFieldDefinitions($entity_type);

    $fields['requester_uid'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Requester UID'))
      ->setDescription(t('The UID of the user who submitted this elevation request.'))
      ->setRequired(TRUE)
      ->setSetting('unsigned', TRUE)
      ->setDefaultValue(0);

    $fields['target_role'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Target Role'))
      ->setDescription(t('The machine name of the role being requested.'))
      ->setRequired(TRUE)
      ->setSetting('max_length', 64);

    $fields['reason'] = BaseFieldDefinition::create('string_long')
      ->setLabel(t('Reason'))
      ->setDescription(t('The justification provided by the requester.'))
      ->setRequired(TRUE)
      ->setDefaultValue('');

    $fields['duration_minutes'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Duration (minutes)'))
      ->setDescription(t('Requested elevation duration in minutes.'))
      ->setRequired(TRUE)
      ->setSetting('unsigned', TRUE)
      ->setDefaultValue(60);

    $fields['status'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Status'))
      ->setDescription(t('Current status of the elevation request.'))
      ->setRequired(TRUE)
      ->setSetting('max_length', 16)
      ->setDefaultValue(ElevationStatus::Pending->value);

    $fields['approver_uid'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Approver UID'))
      ->setDescription(t('The UID of the user who approved or denied this request.'))
      ->setSetting('unsigned', TRUE)
      ->setDefaultValue(0);

    $fields['approver_comment'] = BaseFieldDefinition::create('string_long')
      ->setLabel(t('Approver Comment'))
      ->setDescription(t('Optional comment from the approver (e.g. denial reason).'))
      ->setDefaultValue('');

    $fields['created'] = BaseFieldDefinition::create('created')
      ->setLabel(t('Created'))
      ->setDescription(t('The Unix timestamp when the request was created.'));

    $fields['granted_at'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Granted At'))
      ->setDescription(t('Unix timestamp when the elevation was approved and the role granted.'))
      ->setSetting('unsigned', TRUE)
      ->setDefaultValue(0);

    $fields['expires_at'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Expires At'))
      ->setDescription(t('Unix timestamp when the elevation will expire.'))
      ->setSetting('unsigned', TRUE)
      ->setDefaultValue(0);

    $fields['revocation_token'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Revocation Token'))
      ->setDescription(t('One-time token allowing instant self-revocation from email link.'))
      ->setSetting('max_length', 64)
      ->setDefaultValue('');

    return $fields;
  }

  // ---------------------------------------------------------------------------
  // ElevationRequestInterface implementation
  // ---------------------------------------------------------------------------

  /**
   * {@inheritdoc}
   */
  public function getRequesterId(): int {
    return (int) $this->get('requester_uid')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getTargetRole(): string {
    return (string) $this->get('target_role')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getReason(): string {
    return (string) $this->get('reason')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getDurationMinutes(): int {
    return (int) $this->get('duration_minutes')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantedAt(): int {
    return (int) $this->get('granted_at')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getExpiresAt(): int {
    return (int) $this->get('expires_at')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function isExpired(): bool {
    $expiresAt = $this->getExpiresAt();
    if ($expiresAt === 0) {
      return FALSE;
    }
    return \time() >= $expiresAt;
  }

  /**
   * {@inheritdoc}
   */
  public function getApproverId(): int {
    return (int) $this->get('approver_uid')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getApproverComment(): string {
    return (string) $this->get('approver_comment')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getStatus(): ElevationStatus {
    return ElevationStatus::from((string) $this->get('status')->value);
  }

  /**
   * {@inheritdoc}
   */
  public function setStatus(ElevationStatus $status): static {
    $this->set('status', $status->value);
    return $this;
  }

  /**
   * {@inheritdoc}
   */
  public function getRevocationToken(): string {
    return (string) $this->get('revocation_token')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function generateRevocationToken(): string {
    $token = bin2hex(random_bytes(24));
    $this->set('revocation_token', $token);
    return $token;
  }

  /**
   * {@inheritdoc}
   *
   * Prevent saving a request that has already been approved without expiry set.
   */
  public function preSave(EntityStorageInterface $storage): void {
    parent::preSave($storage);

    $status = $this->getStatus();
    if ($status === ElevationStatus::Approved && $this->getGrantedAt() === 0) {
      $now = \time();
      $this->set('granted_at', $now);
      $this->set('expires_at', $now + ($this->getDurationMinutes() * 60));
    }
  }

}
