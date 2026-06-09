<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Unit\Value;

use Drupal\api_flood_guard\Value\FloodDecision;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for the FloodDecision value object.
 *
 * @group api_flood_guard
 * @coversDefaultClass \Drupal\api_flood_guard\Value\FloodDecision
 */
final class FloodDecisionTest extends UnitTestCase {

  /**
   * Tests the pass() named constructor creates an allowed decision.
   *
   * @covers ::pass
   */
  public function testPassCreatesAllowedDecision(): void {
    $decision = FloodDecision::pass('192.168.1.1');

    $this->assertTrue($decision->allowed);
    $this->assertSame('passed', $decision->reason);
    $this->assertSame('192.168.1.1', $decision->identifier);
    $this->assertSame(0, $decision->retryAfter);
  }

  /**
   * Tests pass() with empty identifier (no credentials provided).
   *
   * @covers ::pass
   */
  public function testPassWithEmptyIdentifier(): void {
    $decision = FloodDecision::pass();

    $this->assertTrue($decision->allowed);
    $this->assertSame('passed', $decision->reason);
    $this->assertSame('', $decision->identifier);
    $this->assertSame(0, $decision->retryAfter);
  }

  /**
   * Tests the allowlisted() named constructor.
   *
   * @covers ::allowlisted
   */
  public function testAllowlistedCreatesAllowedDecisionWithAllowlistReason(): void {
    $decision = FloodDecision::allowlisted('10.0.0.1');

    $this->assertTrue($decision->allowed);
    $this->assertSame('allowlist', $decision->reason);
    $this->assertSame('10.0.0.1', $decision->identifier);
    $this->assertSame(0, $decision->retryAfter);
  }

  /**
   * Tests block() with reason 'ip'.
   *
   * @covers ::block
   */
  public function testBlockWithIpReason(): void {
    $decision = FloodDecision::block(
      reason: 'ip',
      identifier: '5.5.5.5',
      retryAfter: 3600,
    );

    $this->assertFalse($decision->allowed);
    $this->assertSame('ip', $decision->reason);
    $this->assertSame('5.5.5.5', $decision->identifier);
    $this->assertSame(3600, $decision->retryAfter);
  }

  /**
   * Tests block() with reason 'user'.
   *
   * @covers ::block
   */
  public function testBlockWithUserReason(): void {
    $hash = hash('sha256', 'admin');
    $decision = FloodDecision::block(
      reason: 'user',
      identifier: $hash,
      retryAfter: 900,
    );

    $this->assertFalse($decision->allowed);
    $this->assertSame('user', $decision->reason);
    $this->assertSame($hash, $decision->identifier);
    $this->assertSame(900, $decision->retryAfter);
  }

  /**
   * Tests block() with reason 'reputation'.
   *
   * @covers ::block
   */
  public function testBlockWithReputationReason(): void {
    $decision = FloodDecision::block(
      reason: 'reputation',
      identifier: '1.2.3.4',
      retryAfter: 3600,
    );

    $this->assertFalse($decision->allowed);
    $this->assertSame('reputation', $decision->reason);
    $this->assertSame('1.2.3.4', $decision->identifier);
    $this->assertSame(3600, $decision->retryAfter);
  }

  /**
   * Tests block() with default retryAfter = 0.
   *
   * @covers ::block
   */
  public function testBlockDefaultRetryAfterIsZero(): void {
    $decision = FloodDecision::block(reason: 'ip', identifier: '1.2.3.4');

    $this->assertFalse($decision->allowed);
    $this->assertSame(0, $decision->retryAfter);
  }

  /**
   * Tests that allowed decisions have retryAfter = 0.
   *
   * @covers ::pass
   * @covers ::allowlisted
   */
  public function testAllowedDecisionsHaveZeroRetryAfter(): void {
    $pass = FloodDecision::pass('1.2.3.4');
    $allowlisted = FloodDecision::allowlisted('10.0.0.1');

    $this->assertSame(0, $pass->retryAfter);
    $this->assertSame(0, $allowlisted->retryAfter);
  }

  /**
   * Tests that block decisions have allowed = false.
   *
   * @covers ::block
   */
  public function testBlockDecisionIsNotAllowed(): void {
    $decision = FloodDecision::block(reason: 'ip', identifier: '1.1.1.1', retryAfter: 1800);

    $this->assertFalse($decision->allowed);
  }

  /**
   * Tests that the value object is readonly — cannot overwrite 'allowed'.
   *
   * @covers ::__construct
   */
  public function testReadonlyAllowedCannotBeModified(): void {
    $decision = FloodDecision::pass('1.2.3.4');

    $this->expectException(\Error::class);
    // @phpstan-ignore-next-line
    $decision->allowed = FALSE;
  }

  /**
   * Tests that the value object is readonly — cannot overwrite 'reason'.
   *
   * @covers ::__construct
   */
  public function testReadonlyReasonCannotBeModified(): void {
    $decision = FloodDecision::block(reason: 'ip', identifier: '1.2.3.4');

    $this->expectException(\Error::class);
    // @phpstan-ignore-next-line
    $decision->reason = 'passed';
  }

  /**
   * Tests the direct constructor as used by named constructors.
   *
   * @covers ::__construct
   */
  public function testDirectConstructorSetsAllFields(): void {
    $decision = new FloodDecision(
      allowed: FALSE,
      reason: 'ip',
      identifier: '9.9.9.9',
      retryAfter: 7200,
    );

    $this->assertFalse($decision->allowed);
    $this->assertSame('ip', $decision->reason);
    $this->assertSame('9.9.9.9', $decision->identifier);
    $this->assertSame(7200, $decision->retryAfter);
  }

  /**
   * Tests that multiple distinct decisions are independent objects.
   *
   * @covers ::pass
   * @covers ::block
   */
  public function testTwoDecisionsAreIndependent(): void {
    $pass = FloodDecision::pass('10.0.0.1');
    $block = FloodDecision::block(reason: 'ip', identifier: '10.0.0.2', retryAfter: 3600);

    $this->assertTrue($pass->allowed);
    $this->assertFalse($block->allowed);
    $this->assertNotSame($pass->identifier, $block->identifier);
  }

}
