<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Value;

/**
 * Immutable value object representing a single component from composer.lock.
 *
 * Carries the package identity needed to query OSV.dev and to populate a
 * CycloneDX 1.6 component element. All properties are read-only after
 * construction to prevent mutation across service boundaries.
 */
final readonly class SbomComponent {

  /**
   * Constructs an SbomComponent.
   *
   * @param string $name
   *   The Composer package name (e.g. "drupal/core").
   * @param string $version
   *   The installed version string (e.g. "11.1.0").
   * @param string $type
   *   The package type (e.g. "drupal-module", "library").
   * @param string $description
   *   The package description from composer.lock, or empty string.
   * @param string $purl
   *   The Package URL (PURL) in pkg:composer/{name}@{version} format.
   * @param string $bomRef
   *   A unique BOM reference identifier for cross-referencing within the SBOM.
   * @param array<string> $licenses
   *   SPDX licence identifiers declared by the package.
   * @param string $sourceUrl
   *   The package source URL, or empty string if absent.
   */
  public function __construct(
    public readonly string $name,
    public readonly string $version,
    public readonly string $type,
    public readonly string $description,
    public readonly string $purl,
    public readonly string $bomRef,
    public readonly array $licenses,
    public readonly string $sourceUrl,
  ) {}

  /**
   * Returns a new SbomComponent with a different version string.
   *
   * Useful in tests where version normalisation is exercised without
   * constructing a full object graph.
   *
   * @param string $version
   *   The replacement version string.
   *
   * @return static
   *   A new immutable instance with the updated version.
   */
  public function withVersion(string $version): static {
    return new static(
      name: $this->name,
      version: $version,
      type: $this->type,
      description: $this->description,
      purl: 'pkg:composer/' . $this->name . '@' . $version,
      bomRef: $this->bomRef,
      licenses: $this->licenses,
      sourceUrl: $this->sourceUrl,
    );
  }

}
