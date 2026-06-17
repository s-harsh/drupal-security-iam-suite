<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Service;

/**
 * Parses SCIM 2.0 filter expressions into structured query criteria.
 *
 * Supports the subset of filter syntax used by major IdPs:
 *   - Comparison operators: eq, ne, co (contains), sw (starts with),
 *     ew (ends with), gt, lt, ge, le, pr (present)
 *   - Logical operators: and, or, not
 *   - Grouped expressions with parentheses
 *   - Attribute paths with sub-attribute access (emails.value)
 *   - Bracketed multi-value filters (emails[type eq "work"].value)
 *
 * The parser emits a flat criteria array suitable for translating into Drupal
 * entity queries. Complex logical operators (and/or/not combining multiple
 * comparisons) are represented as nested arrays.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2.2
 */
final class ScimFilterParser {

  /**
   * Supported comparison operators mapped to their symbolic equivalent.
   */
  private const COMPARISON_OPS = [
    'eq' => '=',
    'ne' => '!=',
    'co' => 'CONTAINS',
    'sw' => 'STARTS_WITH',
    'ew' => 'ENDS_WITH',
    'gt' => '>',
    'lt' => '<',
    'ge' => '>=',
    'le' => '<=',
    'pr' => 'PRESENT',
  ];

  /**
   * Parses a SCIM filter string into a structured criteria array.
   *
   * Returns an array with one of these shapes:
   *   Simple:  ['attr' => string, 'op' => string, 'value' => mixed]
   *   Logical: ['logic' => 'and'|'or'|'not', 'conditions' => [<criteria>, ...]]
   *
   * @param string $filter
   *   The raw SCIM filter string (e.g. 'userName eq "john"').
   *
   * @return array<string, mixed>|null
   *   Structured criteria array, or null when the filter cannot be parsed.
   */
  public function parse(string $filter): ?array {
    $filter = trim($filter);
    if ($filter === '') {
      return null;
    }

    // Strip outer parentheses if the entire expression is wrapped.
    if ($this->isWrappedInParentheses($filter)) {
      return $this->parse(substr($filter, 1, strlen($filter) - 2));
    }

    // Check for 'not (expr)'.
    if (preg_match('/^not\s+\((.+)\)$/is', $filter, $m)) {
      $inner = $this->parse(trim($m[1]));
      if ($inner === null) {
        return null;
      }
      return ['logic' => 'not', 'conditions' => [$inner]];
    }

    // Split on top-level ' and ' / ' or ' (not inside parentheses or brackets).
    foreach (['or', 'and'] as $logicOp) {
      $parts = $this->splitOnLogicalOp($filter, $logicOp);
      if (count($parts) > 1) {
        $conditions = array_map([$this, 'parse'], $parts);
        if (in_array(null, $conditions, true)) {
          return null;
        }
        return ['logic' => $logicOp, 'conditions' => $conditions];
      }
    }

    // Try simple comparison: attr op "value" or attr op value.
    return $this->parseSimple($filter);
  }

  /**
   * Translates a parsed criteria array into a Drupal entity query condition.
   *
   * Returns an array of ['field' => string, 'op' => string, 'value' => mixed]
   * triples that can be applied to an EntityQuery. Only simple eq/co/sw/ew
   * comparisons on known mapped fields are supported at the entity query level;
   * other operators require post-query filtering.
   *
   * @param array<string, mixed> $criteria
   *   Output from parse().
   * @param array<string, string> $attributeMap
   *   SCIM attribute name → Drupal field name map.
   *
   * @return array<int, array{field: string, op: string, value: mixed}>
   *   List of entity query conditions. Empty if criteria cannot be translated.
   */
  public function toEntityQueryConditions(array $criteria, array $attributeMap): array {
    if (isset($criteria['logic'])) {
      // Only 'and' logic maps directly to entity query conditions.
      if ($criteria['logic'] !== 'and') {
        return [];
      }
      $conditions = [];
      foreach ((array) $criteria['conditions'] as $sub) {
        $subConds = $this->toEntityQueryConditions((array) $sub, $attributeMap);
        foreach ($subConds as $cond) {
          $conditions[] = $cond;
        }
      }
      return $conditions;
    }

    $attr       = (string) ($criteria['attr'] ?? '');
    $op         = (string) ($criteria['op'] ?? '');
    $value      = $criteria['value'] ?? null;
    $drupalField = $attributeMap[$attr] ?? null;

    if ($drupalField === null) {
      return [];
    }

    $queryOp = match ($op) {
      '='          => '=',
      '!='         => '<>',
      'CONTAINS'   => 'CONTAINS',
      'STARTS_WITH'=> 'STARTS_WITH',
      default      => null,
    };

    if ($queryOp === null) {
      return [];
    }

    return [['field' => $drupalField, 'op' => $queryOp, 'value' => $value]];
  }

  /**
   * Checks whether a filter value matches a given SCIM criteria.
   *
   * Used for post-query filtering when the criteria cannot be translated to an
   * entity query condition (e.g. 'ne', 'pr', 'ew', 'gt', 'lt').
   *
   * @param mixed $fieldValue
   *   The actual field value to test.
   * @param array<string, mixed> $criteria
   *   Simple criteria from parse() (must have attr/op/value keys).
   *
   * @return bool
   *   TRUE when the field value satisfies the criteria.
   */
  public function matchesSimple(mixed $fieldValue, array $criteria): bool {
    $op    = (string) ($criteria['op'] ?? '');
    $value = (string) ($criteria['value'] ?? '');
    $field = (string) $fieldValue;

    return match ($op) {
      '='           => strcasecmp($field, $value) === 0,
      '!='          => strcasecmp($field, $value) !== 0,
      'CONTAINS'    => str_contains(strtolower($field), strtolower($value)),
      'STARTS_WITH' => str_starts_with(strtolower($field), strtolower($value)),
      'ENDS_WITH'   => str_ends_with(strtolower($field), strtolower($value)),
      '>'           => $field > $value,
      '<'           => $field < $value,
      '>='          => $field >= $value,
      '<='          => $field <= $value,
      'PRESENT'     => $field !== '' && $field !== null,
      default       => false,
    };
  }

  /**
   * Parses a simple comparison expression: attr op "value" or attr op value.
   *
   * @param string $filter
   *   A filter string containing exactly one comparison.
   *
   * @return array<string, mixed>|null
   *   Criteria array with 'attr', 'op', 'value' keys, or null on parse error.
   */
  private function parseSimple(string $filter): ?array {
    // Match: attribute op "quoted value" or attribute op unquotedValue.
    // Also handles: attr pr (present, no value).
    $pattern = '/^([\w.\[\]"= ]+?)\s+(eq|ne|co|sw|ew|gt|lt|ge|le|pr)\s*(?:"([^"]*)"|([\w@.\-+]+))?$/i';

    if (!preg_match($pattern, trim($filter), $m)) {
      return null;
    }

    $rawAttr  = trim($m[1]);
    $op       = strtolower($m[2]);
    $value    = ($op === 'pr') ? null : ($m[3] ?? $m[4] ?? null);
    $mappedOp = self::COMPARISON_OPS[$op] ?? null;

    if ($mappedOp === null) {
      return null;
    }

    // Normalise bracketed sub-attribute: emails[type eq "work"].value → emails.value
    $attr = (string) preg_replace('/\[[^\]]+\]/', '', $rawAttr);

    return ['attr' => $attr, 'op' => $mappedOp, 'value' => $value];
  }

  /**
   * Splits a filter string on a logical operator at the top nesting level.
   *
   * @param string $filter
   *   The filter string.
   * @param string $op
   *   The operator to split on: 'and' or 'or'.
   *
   * @return string[]
   *   Array of sub-expressions. Contains one element when operator not found.
   */
  private function splitOnLogicalOp(string $filter, string $op): array {
    $depth  = 0;
    $parts  = [];
    $start  = 0;
    $len    = strlen($filter);
    $opLen  = strlen($op) + 2; // space + op + space

    for ($i = 0; $i < $len; $i++) {
      $char = $filter[$i];
      if ($char === '(' || $char === '[') {
        $depth++;
      }
      elseif ($char === ')' || $char === ']') {
        $depth--;
      }
      elseif ($depth === 0 && $i + $opLen <= $len) {
        $candidate = strtolower(substr($filter, $i, $opLen));
        if ($candidate === ' ' . $op . ' ') {
          $parts[] = trim(substr($filter, $start, $i - $start));
          $start   = $i + $opLen;
          $i      += $opLen - 1;
        }
      }
    }

    if (!empty($parts)) {
      $parts[] = trim(substr($filter, $start));
    }
    else {
      $parts[] = $filter;
    }

    return $parts;
  }

  /**
   * Returns true if the entire string is wrapped in a matching pair of
   * parentheses at the top level.
   *
   * @param string $str
   *   The string to test.
   *
   * @return bool
   *   TRUE when fully wrapped.
   */
  private function isWrappedInParentheses(string $str): bool {
    if ($str === '' || $str[0] !== '(') {
      return false;
    }
    $depth = 0;
    $len   = strlen($str);
    for ($i = 0; $i < $len; $i++) {
      if ($str[$i] === '(') {
        $depth++;
      }
      elseif ($str[$i] === ')') {
        $depth--;
        if ($depth === 0 && $i !== $len - 1) {
          return false;
        }
      }
    }
    return $depth === 0;
  }

}
