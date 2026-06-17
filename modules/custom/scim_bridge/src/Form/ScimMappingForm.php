<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Attribute mapping configuration form for SCIM Bridge.
 *
 * Allows administrators to control:
 *   - Which SCIM User attributes are written to which Drupal user fields
 *   - Which SCIM Groups (by displayName) map to which Drupal role machine names
 *
 * The form is pre-populated with the default mappings from scim_bridge.mapping
 * and shows all available user fields so administrators can complete the mapping.
 */
final class ScimMappingForm extends ConfigFormBase {

  /**
   * The mapping config object name.
   */
  private const MAPPING_CONFIG = 'scim_bridge.mapping';

  /**
   * The SCIM User attribute paths shown in the mapping UI.
   * These are the SCIM-side keys; values are the default Drupal field names.
   */
  private const DEFAULT_SCIM_ATTRIBUTES = [
    'userName'              => 'name',
    'emails[0].value'       => 'mail',
    'displayName'           => 'field_display_name',
    'name.givenName'        => 'field_first_name',
    'name.familyName'       => 'field_last_name',
    'phoneNumbers[0].value' => 'field_phone',
    'title'                 => 'field_job_title',
    'addresses[0].locality' => 'field_city',
    'addresses[0].country'  => 'field_country',
    'active'                => 'status',
    'externalId'            => 'field_scim_external_id',
  ];

  /**
   * Constructs a ScimMappingForm.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   */
  public function __construct(
    ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {
    parent::__construct($configFactory);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('entity_type.manager'),
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return [self::MAPPING_CONFIG];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'scim_bridge_mapping_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config     = $this->config(self::MAPPING_CONFIG);
    $savedMap   = (array) ($config->get('user_attribute_map') ?? []);
    $savedGroups = (array) ($config->get('group_role_map') ?? []);

    // ---------------------------------------------------------------------------
    // User attribute mapping table
    // ---------------------------------------------------------------------------
    $form['user_mapping'] = [
      '#type'        => 'details',
      '#title'       => $this->t('User attribute mapping'),
      '#open'        => TRUE,
      '#description' => $this->t(
        'Map each SCIM attribute to a Drupal user field machine name. Leave blank to ignore that attribute. The fields <em>name</em>, <em>mail</em>, and <em>status</em> are built-in; others (e.g. field_display_name) must exist on the user entity.',
      ),
    ];

    $form['user_mapping']['user_attribute_map'] = [
      '#type'   => 'table',
      '#header' => [$this->t('SCIM attribute'), $this->t('Drupal field machine name')],
    ];

    // Merge configured attributes with defaults so new attributes appear.
    $attributes = array_merge(self::DEFAULT_SCIM_ATTRIBUTES, $savedMap);

    foreach ($attributes as $scimAttr => $defaultField) {
      $savedValue = $savedMap[$scimAttr] ?? $defaultField;

      $form['user_mapping']['user_attribute_map'][$scimAttr]['scim_attr'] = [
        '#markup' => '<code>' . htmlspecialchars($scimAttr) . '</code>',
      ];
      $form['user_mapping']['user_attribute_map'][$scimAttr]['drupal_field'] = [
        '#type'          => 'textfield',
        '#default_value' => (string) $savedValue,
        '#placeholder'   => $this->t('Drupal field machine name'),
        '#maxlength'     => 128,
        '#size'          => 40,
      ];
    }

    // ---------------------------------------------------------------------------
    // Group-to-role mapping table
    // ---------------------------------------------------------------------------
    $form['group_mapping'] = [
      '#type'        => 'details',
      '#title'       => $this->t('Group → role mapping'),
      '#open'        => TRUE,
      '#description' => $this->t(
        'Map SCIM Group displayNames to Drupal role machine names. When empty, all SCIM Groups are auto-mapped to roles using a machine-name conversion. Explicit entries here override the auto-mapping.',
      ),
    ];

    $groupCount = $form_state->get('group_count');
    if ($groupCount === NULL) {
      $groupCount = max(1, count($savedGroups));
      $form_state->set('group_count', $groupCount);
    }

    $form['group_mapping']['group_role_map'] = [
      '#type'   => 'table',
      '#header' => [$this->t('SCIM displayName'), $this->t('Drupal role machine name')],
      '#empty'  => $this->t('No group mappings configured.'),
    ];

    $groupKeys = array_keys($savedGroups);
    for ($i = 0; $i < $groupCount; $i++) {
      $scimName  = $groupKeys[$i] ?? '';
      $roleId    = $scimName !== '' ? ($savedGroups[$scimName] ?? '') : '';

      $form['group_mapping']['group_role_map'][$i]['scim_name'] = [
        '#type'          => 'textfield',
        '#default_value' => $scimName,
        '#placeholder'   => $this->t('e.g. Engineering'),
        '#maxlength'     => 255,
      ];
      $form['group_mapping']['group_role_map'][$i]['drupal_role'] = [
        '#type'          => 'textfield',
        '#default_value' => (string) $roleId,
        '#placeholder'   => $this->t('e.g. engineer'),
        '#maxlength'     => 64,
      ];
    }

    $form['group_mapping']['add_group_row'] = [
      '#type'   => 'submit',
      '#value'  => $this->t('Add mapping row'),
      '#submit' => ['::addGroupRow'],
      '#limit_validation_errors' => [],
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * Submit handler that adds a new group mapping row.
   *
   * @param array<string, mixed> $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   */
  public function addGroupRow(array &$form, FormStateInterface $form_state): void {
    $count = (int) $form_state->get('group_count');
    $form_state->set('group_count', $count + 1);
    $form_state->setRebuild(TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    // Validate Drupal field names are machine-name safe.
    $attrRows = (array) ($form_state->getValue('user_attribute_map') ?? []);
    foreach ($attrRows as $scimAttr => $row) {
      $field = trim((string) ($row['drupal_field'] ?? ''));
      if ($field !== '' && !preg_match('/^[a-z][a-z0-9_]*$/', $field)) {
        $form_state->setErrorByName(
          "user_attribute_map][$scimAttr][drupal_field",
          $this->t('Drupal field names may only contain lowercase letters, digits, and underscores, and must start with a letter.'),
        );
      }
    }

    // Validate group mapping role IDs.
    $groupRows = (array) ($form_state->getValue('group_role_map') ?? []);
    foreach ($groupRows as $idx => $row) {
      $roleId = trim((string) ($row['drupal_role'] ?? ''));
      if ($roleId !== '' && !preg_match('/^[a-z][a-z0-9_]*$/', $roleId)) {
        $form_state->setErrorByName(
          "group_role_map][$idx][drupal_role",
          $this->t('Drupal role machine names may only contain lowercase letters, digits, and underscores.'),
        );
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    // Build user_attribute_map.
    $attrRows = (array) ($form_state->getValue('user_attribute_map') ?? []);
    $userAttrMap = [];
    foreach ($attrRows as $scimAttr => $row) {
      $field = trim((string) ($row['drupal_field'] ?? ''));
      if ($field !== '') {
        $userAttrMap[$scimAttr] = $field;
      }
    }

    // Build group_role_map.
    $groupRows   = (array) ($form_state->getValue('group_role_map') ?? []);
    $groupRoleMap = [];
    foreach ($groupRows as $row) {
      $scimName = trim((string) ($row['scim_name'] ?? ''));
      $roleId   = trim((string) ($row['drupal_role'] ?? ''));
      if ($scimName !== '' && $roleId !== '') {
        $groupRoleMap[$scimName] = $roleId;
      }
    }

    $this->config(self::MAPPING_CONFIG)
      ->set('user_attribute_map', $userAttrMap)
      ->set('group_role_map', $groupRoleMap)
      ->save();

    parent::submitForm($form, $form_state);
  }

}
