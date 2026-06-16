<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Entity;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\zero_standing_privilege\Value\ElevationStatus;

/**
 * Interface for the ElevationRequest content entity.
 */
interface ElevationRequestInterface extends ContentEntityInterface {

  // ---------------------------------------------------------------------------
  // Requester
  // ---------------------------------------------------------------------------

  /**
   * Returns the UID of the user who submitted this request.
   */
  public function getRequesterId(): int;

  /**
   * Returns the target role machine name being requested.
   */
  public function getTargetRole(): string;

  /**
   * Returns the requester-supplied justification text.
   */
  public function getReason(): string;

  // ---------------------------------------------------------------------------
  // Duration & expiry
  // ---------------------------------------------------------------------------

  /**
   * Returns the requested elevation duration in minutes.
   */
  public function getDurationMinutes(): int;

  /**
   * Returns the Unix timestamp when the elevation was granted (approved), or 0.
   */
  public function getGrantedAt(): int;

  /**
   * Returns the Unix timestamp when the elevation will expire (granted_at + duration), or 0.
   */
  public function getExpiresAt(): int;

  /**
   * Returns true if the elevation is currently past its expiry time.
   */
  public function isExpired(): bool;

  // ---------------------------------------------------------------------------
  // Approval
  // ---------------------------------------------------------------------------

  /**
   * Returns the UID of the approver, or 0 if not yet reviewed.
   */
  public function getApproverId(): int;

  /**
   * Returns the approver's comment / denial reason, or empty string.
   */
  public function getApproverComment(): string;

  // ---------------------------------------------------------------------------
  // Status
  // ---------------------------------------------------------------------------

  /**
   * Returns the current ElevationStatus enum value.
   */
  public function getStatus(): ElevationStatus;

  /**
   * Sets the status of this request.
   *
   * @param \Drupal\zero_standing_privilege\Value\ElevationStatus $status
   *   The new status.
   *
   * @return $this
   */
  public function setStatus(ElevationStatus $status): static;

  // ---------------------------------------------------------------------------
  // Revocation token
  // ---------------------------------------------------------------------------

  /**
   * Returns the one-time revocation token (or empty string if not set).
   */
  public function getRevocationToken(): string;

  /**
   * Generates and stores a new revocation token, returning it.
   */
  public function generateRevocationToken(): string;

}
