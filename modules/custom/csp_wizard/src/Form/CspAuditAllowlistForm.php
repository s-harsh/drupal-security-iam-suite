<?php

declare(strict_types=1);

namespace Drupal\csp_wizard\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configuration form for the CSP Audit known-safe module allowlist.
 *
 * Presents a table of all installed modules with per-module "mark as reviewed"
 * checkboxes. Allowlisted modules are excluded from the csp_audit report.
 */
final class CspAuditAllowlistForm extends ConfigFormBase {

  /**
   * Constructs a CspAuditAllowlistForm.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler.
   */
  public function __construct(
    ConfigFactoryInterface $configFactory,
    private readonly ModuleHandlerInterface $moduleHandler,
  ) {
    parent::__construct($configFactory);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('module_handler'),
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['csp_audit.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'csp_audit_allowlist_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    // Load settings from csp_audit.settings, falling back to empty.
    $config = $this->config('csp_audit.settings');
    $allowlist = $config->get('allowlist') ?? [];

    $form['description'] = [
      '#type'   => 'markup',
      '#markup' => \Drupal\Core\Render\Markup::create(
        '<p>' . $this->t('Mark modules as reviewed and safe to exclude them from the CSP Audit findings report. Modules on this list will not appear in the audit results even if they contain inline script patterns.') . '</p>'
      ),
    ];

    $modules = $this->moduleHandler->getModuleList();
    ksort($modules);

    $header = [
      $this->t('Module'),
      $this->t('Machine name'),
      $this->t('Mark as reviewed / safe'),
    ];

    $rows = [];
    foreach ($modules as $machineName => $extension) {
      $info = $extension->info;
      $humanName = $info['name'] ?? $machineName;
      $rows[$machineName] = [
        '#attributes' => [],
        'name'        => ['#plain_text' => $humanName],
        'machine'     => ['#plain_text' => $machineName],
        'allowlisted' => [
          '#type'          => 'checkbox',
          '#title'         => $this->t('Reviewed'),
          '#title_display' => 'invisible',
          '#default_value' => in_array($machineName, $allowlist, TRUE) ? 1 : 0,
        ],
      ];
    }

    $form['modules'] = [
      '#type'    => 'table',
      '#header'  => $header,
      '#caption' => $this->t('Enabled modules (@count total)', ['@count' => count($modules)]),
    ] + $rows;

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $modulesValues = $form_state->getValue('modules') ?? [];
    $allowlist = [];
    foreach ($modulesValues as $machineName => $row) {
      if (!empty($row['allowlisted'])) {
        $allowlist[] = $machineName;
      }
    }
    sort($allowlist);

    $this->config('csp_audit.settings')
      ->set('allowlist', $allowlist)
      ->save();

    parent::submitForm($form, $form_state);
  }

}
