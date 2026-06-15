<?php

declare(strict_types=1);

namespace Drupal\Tests\sbom_sentinel\Unit\Value;

use Drupal\sbom_sentinel\Value\SbomComponent;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for SbomComponent value object.
 *
 * @coversDefaultClass \Drupal\sbom_sentinel\Value\SbomComponent
 * @group sbom_sentinel
 */
final class SbomComponentTest extends UnitTestCase {

  /**
   * Creates a fully populated SbomComponent for use in tests.
   */
  private function makeComponent(
    string $name = 'drupal/core',
    string $version = '11.1.0',
    string $type = 'drupal-core',
    string $description = 'Drupal core',
    string $purl = 'pkg:composer/drupal/core@11.1.0',
    string $bomRef = 'abc123',
    array $licenses = ['GPL-2.0-or-later'],
    string $sourceUrl = 'https://github.com/drupal/drupal',
  ): SbomComponent {
    return new SbomComponent(
      name: $name,
      version: $version,
      type: $type,
      description: $description,
      purl: $purl,
      bomRef: $bomRef,
      licenses: $licenses,
      sourceUrl: $sourceUrl,
    );
  }

  // -------------------------------------------------------------------------
  // Construction and property access
  // -------------------------------------------------------------------------

  /**
   * @covers ::__construct
   */
  public function testConstructSetsNameProperty(): void {
    $c = $this->makeComponent(name: 'drupal/core');
    $this->assertSame('drupal/core', $c->name);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructSetsVersionProperty(): void {
    $c = $this->makeComponent(version: '11.1.0');
    $this->assertSame('11.1.0', $c->version);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructSetsTypeProperty(): void {
    $c = $this->makeComponent(type: 'drupal-module');
    $this->assertSame('drupal-module', $c->type);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructSetsDescriptionProperty(): void {
    $c = $this->makeComponent(description: 'A module');
    $this->assertSame('A module', $c->description);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructSetsPurlProperty(): void {
    $c = $this->makeComponent(purl: 'pkg:composer/drupal/core@11.1.0');
    $this->assertSame('pkg:composer/drupal/core@11.1.0', $c->purl);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructSetsBomRefProperty(): void {
    $c = $this->makeComponent(bomRef: 'deadbeef');
    $this->assertSame('deadbeef', $c->bomRef);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructSetsLicensesProperty(): void {
    $c = $this->makeComponent(licenses: ['MIT', 'Apache-2.0']);
    $this->assertSame(['MIT', 'Apache-2.0'], $c->licenses);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructSetsSourceUrlProperty(): void {
    $c = $this->makeComponent(sourceUrl: 'https://github.com/example/package');
    $this->assertSame('https://github.com/example/package', $c->sourceUrl);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructAcceptsEmptyLicensesArray(): void {
    $c = $this->makeComponent(licenses: []);
    $this->assertSame([], $c->licenses);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructAcceptsEmptySourceUrl(): void {
    $c = $this->makeComponent(sourceUrl: '');
    $this->assertSame('', $c->sourceUrl);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructAcceptsEmptyDescription(): void {
    $c = $this->makeComponent(description: '');
    $this->assertSame('', $c->description);
  }

  // -------------------------------------------------------------------------
  // Immutability
  // -------------------------------------------------------------------------

  /**
   * @covers ::__construct
   */
  public function testPropertiesAreReadOnly(): void {
    $c = $this->makeComponent();
    // PHP readonly properties throw Error on assignment.
    $this->expectException(\Error::class);
    // @phpstan-ignore-next-line
    $c->name = 'drupal/something';
  }

  // -------------------------------------------------------------------------
  // withVersion()
  // -------------------------------------------------------------------------

  /**
   * @covers ::withVersion
   */
  public function testWithVersionReturnsNewInstance(): void {
    $original = $this->makeComponent(version: '11.1.0');
    $modified = $original->withVersion('11.2.0');

    $this->assertNotSame($original, $modified);
  }

  /**
   * @covers ::withVersion
   */
  public function testWithVersionUpdatesVersionProperty(): void {
    $modified = $this->makeComponent(version: '11.1.0')->withVersion('11.2.0');
    $this->assertSame('11.2.0', $modified->version);
  }

  /**
   * @covers ::withVersion
   */
  public function testWithVersionUpdatesPurlProperty(): void {
    $modified = $this->makeComponent(
      name: 'drupal/core',
      version: '11.1.0',
    )->withVersion('11.2.0');

    $this->assertSame('pkg:composer/drupal/core@11.2.0', $modified->purl);
  }

  /**
   * @covers ::withVersion
   */
  public function testWithVersionPreservesOriginalVersion(): void {
    $original = $this->makeComponent(version: '11.1.0');
    $original->withVersion('11.2.0');

    $this->assertSame('11.1.0', $original->version);
  }

  /**
   * @covers ::withVersion
   */
  public function testWithVersionPreservesOtherProperties(): void {
    $original = $this->makeComponent(
      name: 'drupal/views',
      type: 'drupal-module',
      description: 'Views module',
      bomRef: 'views-ref',
      licenses: ['GPL-2.0-or-later'],
      sourceUrl: 'https://git.drupalcode.org/project/views',
    );
    $modified = $original->withVersion('11.2.0');

    $this->assertSame($original->name, $modified->name);
    $this->assertSame($original->type, $modified->type);
    $this->assertSame($original->description, $modified->description);
    $this->assertSame($original->bomRef, $modified->bomRef);
    $this->assertSame($original->licenses, $modified->licenses);
    $this->assertSame($original->sourceUrl, $modified->sourceUrl);
  }

  /**
   * @covers ::withVersion
   */
  public function testWithVersionReturnsInstanceOfSameClass(): void {
    $modified = $this->makeComponent()->withVersion('12.0.0');
    $this->assertInstanceOf(SbomComponent::class, $modified);
  }

  // -------------------------------------------------------------------------
  // PURL format
  // -------------------------------------------------------------------------

  /**
   * @covers ::__construct
   */
  public function testPurlFollowsComposerScheme(): void {
    $c = new SbomComponent(
      name: 'vendor/package',
      version: '2.3.4',
      type: 'library',
      description: '',
      purl: 'pkg:composer/vendor/package@2.3.4',
      bomRef: 'ref',
      licenses: [],
      sourceUrl: '',
    );
    $this->assertStringStartsWith('pkg:composer/', $c->purl);
  }

}
