<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\sbom_sentinel\Service\SbomGenerator;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller for CycloneDX 1.6 SBOM export downloads.
 *
 * Provides two download endpoints:
 *   /admin/reports/sbom-sentinel/export/json — CycloneDX JSON
 *   /admin/reports/sbom-sentinel/export/xml  — CycloneDX XML
 *
 * Both endpoints reuse the most-recent cached scan results, or trigger a
 * fresh scan when no cache entry exists, to avoid redundant OSV.dev calls.
 */
final class SbomExportController extends ControllerBase {

  /**
   * Constructs an SbomExportController.
   *
   * @param \Drupal\sbom_sentinel\Service\SbomGenerator $sbomGenerator
   *   The SBOM generator service.
   */
  public function __construct(
    private readonly SbomGenerator $sbomGenerator,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static($container->get('sbom_sentinel.sbom_generator'));
  }

  /**
   * Exports the SBOM as a CycloneDX 1.6 JSON download.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A file-download response with application/vnd.cyclonedx+json content type.
   */
  public function exportJson(): Response {
    $sbom = $this->getSbom();
    $json = json_encode($sbom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    $filename = 'sbom-' . date('Y-m-d') . '.cdx.json';

    $response = new Response($json ?: '{}');
    $response->headers->set('Content-Type', 'application/vnd.cyclonedx+json');
    $response->headers->set(
      'Content-Disposition',
      'attachment; filename="' . $filename . '"',
    );
    $response->headers->set('Cache-Control', 'no-store, no-cache');
    return $response;
  }

  /**
   * Exports the SBOM as a CycloneDX 1.6 XML download.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A file-download response with application/vnd.cyclonedx+xml content type.
   */
  public function exportXml(): Response {
    $sbom = $this->getSbom();
    $xml = $this->buildCycloneDxXml($sbom);

    $filename = 'sbom-' . date('Y-m-d') . '.cdx.xml';

    $response = new Response($xml);
    $response->headers->set('Content-Type', 'application/vnd.cyclonedx+xml');
    $response->headers->set(
      'Content-Disposition',
      'attachment; filename="' . $filename . '"',
    );
    $response->headers->set('Cache-Control', 'no-store, no-cache');
    return $response;
  }

  /**
   * Returns the SBOM document array, fetching from cache or running a scan.
   *
   * @return array<string, mixed>
   *   The CycloneDX 1.6 SBOM document as an associative array.
   */
  private function getSbom(): array {
    $cached = $this->sbomGenerator->getCachedResults();
    if ($cached !== NULL && !empty($cached['sbom'])) {
      return $cached['sbom'];
    }
    $scanData = $this->sbomGenerator->scan();
    return $scanData['sbom'] ?? [];
  }

  /**
   * Converts the CycloneDX associative array to a well-formed XML string.
   *
   * Generates CycloneDX 1.6 XML conforming to
   * https://cyclonedx.org/docs/1.6/xml/
   *
   * @param array<string, mixed> $sbom
   *   The CycloneDX SBOM document array.
   *
   * @return string
   *   A UTF-8 XML string with the CycloneDX namespace and standard structure.
   */
  private function buildCycloneDxXml(array $sbom): string {
    $dom = new \DOMDocument('1.0', 'UTF-8');
    $dom->formatOutput = TRUE;

    $ns = 'http://cyclonedx.org/schema/bom/1.6';
    $root = $dom->createElementNS($ns, 'bom');
    $root->setAttribute('version', (string) ($sbom['version'] ?? '1'));
    if (!empty($sbom['serialNumber'])) {
      $root->setAttribute('serialNumber', (string) $sbom['serialNumber']);
    }
    $dom->appendChild($root);

    // <metadata>
    $metaArr = $sbom['metadata'] ?? [];
    if (is_array($metaArr)) {
      $meta = $dom->createElementNS($ns, 'metadata');
      $root->appendChild($meta);

      if (!empty($metaArr['timestamp'])) {
        $meta->appendChild($dom->createElementNS($ns, 'timestamp', (string) $metaArr['timestamp']));
      }

      $toolsArr = $metaArr['tools'] ?? [];
      if (is_array($toolsArr) && !empty($toolsArr)) {
        $toolsEl = $dom->createElementNS($ns, 'tools');
        $meta->appendChild($toolsEl);
        foreach ($toolsArr as $tool) {
          if (!is_array($tool)) {
            continue;
          }
          $toolEl = $dom->createElementNS($ns, 'tool');
          $toolsEl->appendChild($toolEl);
          foreach (['vendor', 'name', 'version'] as $key) {
            if (!empty($tool[$key])) {
              $toolEl->appendChild($dom->createElementNS($ns, $key, (string) $tool[$key]));
            }
          }
        }
      }
    }

    // <components>
    $componentsArr = $sbom['components'] ?? [];
    if (is_array($componentsArr) && !empty($componentsArr)) {
      $componentsEl = $dom->createElementNS($ns, 'components');
      $root->appendChild($componentsEl);

      foreach ($componentsArr as $comp) {
        if (!is_array($comp)) {
          continue;
        }
        $compEl = $dom->createElementNS($ns, 'component');
        $compEl->setAttribute('type', (string) ($comp['type'] ?? 'library'));
        if (!empty($comp['bom-ref'])) {
          $compEl->setAttribute('bom-ref', (string) $comp['bom-ref']);
        }
        $componentsEl->appendChild($compEl);

        foreach (['name', 'version', 'description', 'purl'] as $field) {
          if (isset($comp[$field]) && $comp[$field] !== '') {
            $compEl->appendChild($dom->createElementNS($ns, $field, (string) $comp[$field]));
          }
        }

        // Licenses.
        $licensesArr = $comp['licenses'] ?? [];
        if (is_array($licensesArr) && !empty($licensesArr)) {
          $licensesEl = $dom->createElementNS($ns, 'licenses');
          $compEl->appendChild($licensesEl);
          foreach ($licensesArr as $licWrapper) {
            if (!is_array($licWrapper) || !isset($licWrapper['license'])) {
              continue;
            }
            $licEl = $dom->createElementNS($ns, 'license');
            $licensesEl->appendChild($licEl);
            $licId = $licWrapper['license']['id'] ?? '';
            if ($licId !== '') {
              $licEl->appendChild($dom->createElementNS($ns, 'id', (string) $licId));
            }
          }
        }

        // Properties.
        $propsArr = $comp['properties'] ?? [];
        if (is_array($propsArr) && !empty($propsArr)) {
          $propsEl = $dom->createElementNS($ns, 'properties');
          $compEl->appendChild($propsEl);
          foreach ($propsArr as $prop) {
            if (!is_array($prop)) {
              continue;
            }
            $propEl = $dom->createElementNS($ns, 'property', (string) ($prop['value'] ?? ''));
            $propEl->setAttribute('name', (string) ($prop['name'] ?? ''));
            $propsEl->appendChild($propEl);
          }
        }
      }
    }

    // <vulnerabilities>
    $vulnsArr = $sbom['vulnerabilities'] ?? [];
    if (is_array($vulnsArr) && !empty($vulnsArr)) {
      $vulnsEl = $dom->createElementNS($ns, 'vulnerabilities');
      $root->appendChild($vulnsEl);

      foreach ($vulnsArr as $vuln) {
        if (!is_array($vuln)) {
          continue;
        }
        $vulnEl = $dom->createElementNS($ns, 'vulnerability');
        $vulnsEl->appendChild($vulnEl);

        if (!empty($vuln['id'])) {
          $vulnEl->appendChild($dom->createElementNS($ns, 'id', (string) $vuln['id']));
        }
        if (!empty($vuln['description'])) {
          $vulnEl->appendChild($dom->createElementNS($ns, 'description', (string) $vuln['description']));
        }

        $sourceArr = $vuln['source'] ?? [];
        if (is_array($sourceArr) && !empty($sourceArr)) {
          $sourceEl = $dom->createElementNS($ns, 'source');
          $vulnEl->appendChild($sourceEl);
          if (!empty($sourceArr['name'])) {
            $sourceEl->appendChild($dom->createElementNS($ns, 'name', (string) $sourceArr['name']));
          }
          if (!empty($sourceArr['url'])) {
            $sourceEl->appendChild($dom->createElementNS($ns, 'url', (string) $sourceArr['url']));
          }
        }

        $ratingsArr = $vuln['ratings'] ?? [];
        if (is_array($ratingsArr) && !empty($ratingsArr)) {
          $ratingsEl = $dom->createElementNS($ns, 'ratings');
          $vulnEl->appendChild($ratingsEl);
          foreach ($ratingsArr as $rating) {
            if (!is_array($rating)) {
              continue;
            }
            $ratingEl = $dom->createElementNS($ns, 'rating');
            $ratingsEl->appendChild($ratingEl);
            if (!empty($rating['method'])) {
              $ratingEl->appendChild($dom->createElementNS($ns, 'method', (string) $rating['method']));
            }
            if (!empty($rating['vector'])) {
              $ratingEl->appendChild($dom->createElementNS($ns, 'vector', (string) $rating['vector']));
            }
          }
        }
      }
    }

    return (string) $dom->saveXML();
  }

}
