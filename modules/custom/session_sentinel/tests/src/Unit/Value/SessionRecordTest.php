<?php

declare(strict_types=1);

namespace Drupal\Tests\session_sentinel\Unit\Value;

use Drupal\session_sentinel\Value\SessionRecord;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for the SessionRecord value object.
 *
 * @group session_sentinel
 * @coversDefaultClass \Drupal\session_sentinel\Value\SessionRecord
 */
final class SessionRecordTest extends UnitTestCase {

  // ---------------------------------------------------------------------------
  // createNew()
  // ---------------------------------------------------------------------------

  /**
   * Tests that createNew() produces a record with id=0 and correct fields.
   *
   * @covers ::createNew
   */
  public function testCreateNewProducesUnsavedRecord(): void {
    $now = time();
    $record = SessionRecord::createNew(
      uid: 42,
      sessionIdHash: 'abc123',
      deviceFingerprint: 'fp1',
      ipAddress: '10.0.0.1',
      userAgent: 'Mozilla/5.0',
      now: $now,
    );

    $this->assertSame(0, $record->id);
    $this->assertSame(42, $record->uid);
    $this->assertSame('abc123', $record->sessionIdHash);
    $this->assertSame('fp1', $record->deviceFingerprint);
    $this->assertSame('10.0.0.1', $record->ipAddress);
    $this->assertSame('Mozilla/5.0', $record->userAgent);
    $this->assertSame($now, $record->created);
    $this->assertSame($now, $record->lastActive);
    $this->assertFalse($record->flaggedDeviceChange);
  }

  /**
   * Tests that createNew() truncates the User-Agent to 512 characters.
   *
   * @covers ::createNew
   */
  public function testCreateNewTruncatesLongUserAgent(): void {
    $longUa = str_repeat('X', 600);
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.2.3.4', $longUa, time());
    $this->assertSame(512, strlen($record->userAgent));
  }

  // ---------------------------------------------------------------------------
  // fromRow()
  // ---------------------------------------------------------------------------

  /**
   * Tests that fromRow() correctly maps a database row object.
   *
   * @covers ::fromRow
   */
  public function testFromRowMapsStdClassRow(): void {
    $row = (object) [
      'id'                   => 7,
      'uid'                  => 5,
      'session_id_hash'      => 'hash7',
      'device_fingerprint'   => 'fp7',
      'ip_address'           => '192.168.1.50',
      'user_agent'           => 'TestBrowser/1.0',
      'created'              => 1700000000,
      'last_active'          => 1700001000,
      'flagged_device_change' => 1,
    ];

    $record = SessionRecord::fromRow($row);

    $this->assertSame(7, $record->id);
    $this->assertSame(5, $record->uid);
    $this->assertSame('hash7', $record->sessionIdHash);
    $this->assertSame('fp7', $record->deviceFingerprint);
    $this->assertSame('192.168.1.50', $record->ipAddress);
    $this->assertSame('TestBrowser/1.0', $record->userAgent);
    $this->assertSame(1700000000, $record->created);
    $this->assertSame(1700001000, $record->lastActive);
    $this->assertTrue($record->flaggedDeviceChange);
  }

  /**
   * Tests that fromRow() works with an array input.
   *
   * @covers ::fromRow
   */
  public function testFromRowMapsArrayRow(): void {
    $row = [
      'id'                   => 3,
      'uid'                  => 9,
      'session_id_hash'      => 'arrHash',
      'device_fingerprint'   => 'arrFp',
      'ip_address'           => '::1',
      'user_agent'           => 'cURL/7.88',
      'created'              => 1000,
      'last_active'          => 2000,
      'flagged_device_change' => 0,
    ];

    $record = SessionRecord::fromRow($row);

    $this->assertSame(3, $record->id);
    $this->assertSame(9, $record->uid);
    $this->assertFalse($record->flaggedDeviceChange);
  }

  // ---------------------------------------------------------------------------
  // withLastActive() / withDeviceFlagged()
  // ---------------------------------------------------------------------------

  /**
   * Tests that withLastActive() returns an immutable copy with a new timestamp.
   *
   * @covers ::withLastActive
   */
  public function testWithLastActiveReturnsCopyWithNewTimestamp(): void {
    $original = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', 1000);
    $updated  = $original->withLastActive(2000);

    $this->assertSame(1000, $original->lastActive);  // original unchanged
    $this->assertSame(2000, $updated->lastActive);
    $this->assertSame($original->sessionIdHash, $updated->sessionIdHash);
    $this->assertSame($original->uid, $updated->uid);
  }

  /**
   * Tests that withDeviceFlagged() returns an immutable copy with the flag set.
   *
   * @covers ::withDeviceFlagged
   */
  public function testWithDeviceFlaggedReturnsCopyWithFlagTrue(): void {
    $original = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', 1000);
    $flagged  = $original->withDeviceFlagged();

    $this->assertFalse($original->flaggedDeviceChange);
    $this->assertTrue($flagged->flaggedDeviceChange);
    $this->assertSame($original->lastActive, $flagged->lastActive);
  }

  // ---------------------------------------------------------------------------
  // idleSeconds() / isIdle()
  // ---------------------------------------------------------------------------

  /**
   * Tests idleSeconds() returns the correct elapsed time.
   *
   * @covers ::idleSeconds
   */
  public function testIdleSecondsReturnsElapsedTime(): void {
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', 1000);
    $record = $record->withLastActive(1000);

    $this->assertSame(500, $record->idleSeconds(1500));
    $this->assertSame(0, $record->idleSeconds(1000));
  }

  /**
   * Tests idleSeconds() returns 0 when now is before last_active (clock drift).
   *
   * @covers ::idleSeconds
   */
  public function testIdleSecondsReturnsZeroOnClockDrift(): void {
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', 2000);
    $this->assertSame(0, $record->idleSeconds(1000));
  }

  /**
   * Tests isIdle() returns true when idle time exceeds timeout.
   *
   * @covers ::isIdle
   */
  public function testIsIdleReturnsTrueWhenExceeded(): void {
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', 0);
    $record = $record->withLastActive(0);

    $this->assertTrue($record->isIdle(1800, 1900));
  }

  /**
   * Tests isIdle() returns false when idle time is below timeout.
   *
   * @covers ::isIdle
   */
  public function testIsIdleReturnsFalseWhenBelowTimeout(): void {
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', 0);
    $record = $record->withLastActive(1000);

    $this->assertFalse($record->isIdle(1800, 1500));
  }

  /**
   * Tests isIdle() returns false when timeout is 0 (disabled).
   *
   * @covers ::isIdle
   */
  public function testIsIdleReturnsFalseWhenTimeoutIsZero(): void {
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', 0);
    $record = $record->withLastActive(0);

    // Even very old session should not be considered idle when timeout = 0.
    $this->assertFalse($record->isIdle(0, 9999999));
  }

  /**
   * Tests isIdle() at the exact boundary is considered idle.
   *
   * @covers ::isIdle
   */
  public function testIsIdleAtExactBoundaryIsIdle(): void {
    $record = SessionRecord::createNew(1, 'h', 'fp', '1.1.1.1', 'UA', 0);
    $record = $record->withLastActive(1000);

    // now - lastActive = 1800, timeout = 1800 → exactly at boundary → idle.
    $this->assertTrue($record->isIdle(1800, 2800));
  }

}
