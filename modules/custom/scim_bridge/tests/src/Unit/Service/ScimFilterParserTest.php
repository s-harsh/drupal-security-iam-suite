<?php

declare(strict_types=1);

namespace Drupal\Tests\scim_bridge\Unit\Service;

use Drupal\scim_bridge\Service\ScimFilterParser;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for ScimFilterParser.
 *
 * Covers: parse(), toEntityQueryConditions(), matchesSimple().
 *
 * @coversDefaultClass \Drupal\scim_bridge\Service\ScimFilterParser
 * @group scim_bridge
 */
final class ScimFilterParserTest extends UnitTestCase {

  private ScimFilterParser $parser;

  protected function setUp(): void {
    parent::setUp();
    $this->parser = new ScimFilterParser();
  }

  // ---------------------------------------------------------------------------
  // parse() — empty / null
  // ---------------------------------------------------------------------------

  /**
   * @covers ::parse
   */
  public function testParseReturnsNullForEmptyString(): void {
    $this->assertNull($this->parser->parse(''));
  }

  /**
   * @covers ::parse
   */
  public function testParseReturnsNullForWhitespaceOnly(): void {
    $this->assertNull($this->parser->parse('   '));
  }

  // ---------------------------------------------------------------------------
  // parse() — simple comparisons
  // ---------------------------------------------------------------------------

  /**
   * @covers ::parse
   */
  public function testParseSimpleEq(): void {
    $result = $this->parser->parse('userName eq "john"');

    $this->assertNotNull($result);
    $this->assertSame('userName', $result['attr']);
    $this->assertSame('=', $result['op']);
    $this->assertSame('john', $result['value']);
  }

  /**
   * @covers ::parse
   */
  public function testParseEmailContains(): void {
    $result = $this->parser->parse('emails.value co "@example.com"');

    $this->assertNotNull($result);
    $this->assertSame('emails.value', $result['attr']);
    $this->assertSame('CONTAINS', $result['op']);
    $this->assertSame('@example.com', $result['value']);
  }

  /**
   * @covers ::parse
   */
  public function testParseStartsWith(): void {
    $result = $this->parser->parse('userName sw "admin"');

    $this->assertNotNull($result);
    $this->assertSame('STARTS_WITH', $result['op']);
    $this->assertSame('admin', $result['value']);
  }

  /**
   * @covers ::parse
   */
  public function testParseEndsWith(): void {
    $result = $this->parser->parse('emails.value ew "@corp.com"');

    $this->assertNotNull($result);
    $this->assertSame('ENDS_WITH', $result['op']);
  }

  /**
   * @covers ::parse
   */
  public function testParsePresent(): void {
    $result = $this->parser->parse('title pr');

    $this->assertNotNull($result);
    $this->assertSame('title', $result['attr']);
    $this->assertSame('PRESENT', $result['op']);
    $this->assertNull($result['value']);
  }

  /**
   * @covers ::parse
   */
  public function testParseNotEqual(): void {
    $result = $this->parser->parse('active ne "false"');

    $this->assertNotNull($result);
    $this->assertSame('!=', $result['op']);
    $this->assertSame('active', $result['attr']);
  }

  /**
   * @covers ::parse
   */
  public function testParseStripsFilterExpressionFromAttr(): void {
    $result = $this->parser->parse('emails[type eq "work"].value eq "test@example.com"');

    $this->assertNotNull($result);
    // Bracketed filter stripped: emails[type eq "work"].value → emails.value
    $this->assertSame('emails.value', $result['attr']);
  }

  // ---------------------------------------------------------------------------
  // parse() — logical operators
  // ---------------------------------------------------------------------------

  /**
   * @covers ::parse
   */
  public function testParseAndLogic(): void {
    $result = $this->parser->parse('userName eq "alice" and active eq "true"');

    $this->assertNotNull($result);
    $this->assertSame('and', $result['logic']);
    $this->assertCount(2, $result['conditions']);
  }

  /**
   * @covers ::parse
   */
  public function testParseOrLogic(): void {
    $result = $this->parser->parse('userName eq "alice" or userName eq "bob"');

    $this->assertNotNull($result);
    $this->assertSame('or', $result['logic']);
    $this->assertCount(2, $result['conditions']);
  }

  /**
   * @covers ::parse
   */
  public function testParseNotLogic(): void {
    $result = $this->parser->parse('not (active eq "false")');

    $this->assertNotNull($result);
    $this->assertSame('not', $result['logic']);
    $this->assertCount(1, $result['conditions']);
  }

  /**
   * @covers ::parse
   */
  public function testParseOuterParenthesesAreStripped(): void {
    $result    = $this->parser->parse('(userName eq "wrapped")');
    $resultRaw = $this->parser->parse('userName eq "wrapped"');

    $this->assertEquals($resultRaw, $result);
  }

  /**
   * @covers ::parse
   */
  public function testParseAndConditionsContainCorrectAttributes(): void {
    $result = $this->parser->parse('userName eq "alice" and displayName co "Alice"');

    $this->assertNotNull($result);
    $conditions = $result['conditions'];
    $this->assertSame('userName', $conditions[0]['attr']);
    $this->assertSame('displayName', $conditions[1]['attr']);
  }

  // ---------------------------------------------------------------------------
  // matchesSimple() tests
  // ---------------------------------------------------------------------------

  /**
   * @covers ::matchesSimple
   */
  public function testMatchesSimpleEqCaseInsensitive(): void {
    $criteria = ['attr' => 'userName', 'op' => '=', 'value' => 'John'];
    $this->assertTrue($this->parser->matchesSimple('john', $criteria));
    $this->assertTrue($this->parser->matchesSimple('JOHN', $criteria));
    $this->assertFalse($this->parser->matchesSimple('jane', $criteria));
  }

  /**
   * @covers ::matchesSimple
   */
  public function testMatchesSimpleContains(): void {
    $criteria = ['attr' => 'emails.value', 'op' => 'CONTAINS', 'value' => '@example'];
    $this->assertTrue($this->parser->matchesSimple('user@example.com', $criteria));
    $this->assertFalse($this->parser->matchesSimple('user@other.com', $criteria));
  }

  /**
   * @covers ::matchesSimple
   */
  public function testMatchesSimpleStartsWith(): void {
    $criteria = ['attr' => 'userName', 'op' => 'STARTS_WITH', 'value' => 'admin'];
    $this->assertTrue($this->parser->matchesSimple('admin_user', $criteria));
    $this->assertFalse($this->parser->matchesSimple('super_admin', $criteria));
  }

  /**
   * @covers ::matchesSimple
   */
  public function testMatchesSimpleEndsWith(): void {
    $criteria = ['attr' => 'emails.value', 'op' => 'ENDS_WITH', 'value' => '.org'];
    $this->assertTrue($this->parser->matchesSimple('user@company.org', $criteria));
    $this->assertFalse($this->parser->matchesSimple('user@company.com', $criteria));
  }

  /**
   * @covers ::matchesSimple
   */
  public function testMatchesSimpleNotEqual(): void {
    $criteria = ['attr' => 'active', 'op' => '!=', 'value' => 'true'];
    $this->assertTrue($this->parser->matchesSimple('false', $criteria));
    $this->assertFalse($this->parser->matchesSimple('true', $criteria));
  }

  /**
   * @covers ::matchesSimple
   */
  public function testMatchesSimplePresent(): void {
    $criteria = ['attr' => 'title', 'op' => 'PRESENT', 'value' => null];
    $this->assertTrue($this->parser->matchesSimple('Engineer', $criteria));
    $this->assertFalse($this->parser->matchesSimple('', $criteria));
  }

  // ---------------------------------------------------------------------------
  // toEntityQueryConditions() tests
  // ---------------------------------------------------------------------------

  /**
   * @covers ::toEntityQueryConditions
   */
  public function testEntityQueryConditionsForEqFilter(): void {
    $criteria = ['attr' => 'userName', 'op' => '=', 'value' => 'alice'];
    $map      = ['userName' => 'name'];

    $conditions = $this->parser->toEntityQueryConditions($criteria, $map);

    $this->assertCount(1, $conditions);
    $this->assertSame('name', $conditions[0]['field']);
    $this->assertSame('=', $conditions[0]['op']);
    $this->assertSame('alice', $conditions[0]['value']);
  }

  /**
   * @covers ::toEntityQueryConditions
   */
  public function testEntityQueryConditionsReturnsEmptyForUnmappedAttr(): void {
    $criteria = ['attr' => 'unknownAttr', 'op' => '=', 'value' => 'x'];
    $map      = ['userName' => 'name'];

    $conditions = $this->parser->toEntityQueryConditions($criteria, $map);
    $this->assertEmpty($conditions);
  }

  /**
   * @covers ::toEntityQueryConditions
   */
  public function testEntityQueryConditionsForAndLogic(): void {
    $criteria = [
      'logic' => 'and',
      'conditions' => [
        ['attr' => 'userName', 'op' => '=', 'value' => 'alice'],
        ['attr' => 'emails[0].value', 'op' => 'CONTAINS', 'value' => '@example'],
      ],
    ];
    $map = ['userName' => 'name', 'emails[0].value' => 'mail'];

    $conditions = $this->parser->toEntityQueryConditions($criteria, $map);
    $this->assertCount(2, $conditions);
  }

  /**
   * @covers ::toEntityQueryConditions
   */
  public function testEntityQueryConditionsReturnsEmptyForOrLogic(): void {
    // OR cannot be mapped to entity query conditions.
    $criteria = [
      'logic' => 'or',
      'conditions' => [
        ['attr' => 'userName', 'op' => '=', 'value' => 'a'],
        ['attr' => 'userName', 'op' => '=', 'value' => 'b'],
      ],
    ];
    $map = ['userName' => 'name'];

    $conditions = $this->parser->toEntityQueryConditions($criteria, $map);
    $this->assertEmpty($conditions);
  }

  /**
   * @covers ::toEntityQueryConditions
   */
  public function testEntityQueryConditionsForContainsOperator(): void {
    $criteria = ['attr' => 'emails[0].value', 'op' => 'CONTAINS', 'value' => '@example'];
    $map      = ['emails[0].value' => 'mail'];

    $conditions = $this->parser->toEntityQueryConditions($criteria, $map);
    $this->assertCount(1, $conditions);
    $this->assertSame('CONTAINS', $conditions[0]['op']);
  }

}
