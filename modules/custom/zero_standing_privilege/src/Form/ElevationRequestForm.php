<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Url;
use Drupal\zero_standing_privilege\Service\PrivilegeManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Form for authenticated users to request a temporary role elevation.
 */
final class ElevationRequestForm extends FormBase {

  public function __construct(
    private readonly PrivilegeManager $privilegeManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly AccountInterface $currentUser,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('zero_standing_privilege.privilege_manager'),
      $container->get('config.factory'),
      $container->get('entity_type.manager'),
      $container->get('current_user'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'zsp_elevation_request_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->configFactory->get('zero_standing_privilege.settings');
    $maxMin = (int) ($config->get('max_elevation_minutes') ?? 240);
    $defMin = (int) ($config->get('default_elevation_minutes') ?? 60);

    // Build role options.
    $allowedRoles = (array) ($config->get('allowed_target_roles') ?? []);
    $roleOptions  = $this->buildRoleOptions($allowedRoles);

    if (empty($roleOptions)) {
      $form['no_roles'] = [
        '#markup' => '<p>' . $this->t('No elevation-eligible roles are currently configured. Please contact an administrator.') . '</p>',
      ];
      return $form;
    }

    $form['#attributes']['novalidate'] = FALSE;

    $form['target_role'] = [
      '#type'          => 'select',
      '#title'         => $this->t('Role to request'),
      '#description'   => $this->t('Select the role you need for this task.'),
      '#options'       => $roleOptions,
      '#required'      => TRUE,
    ];

    $form['duration_minutes'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Duration (minutes)'),
      '#description'   => $this->t('How long you need the elevated role. Maximum: @max minutes.', ['@max' => $maxMin]),
      '#default_value' => $defMin,
      '#min'           => 1,
      '#max'           => $maxMin,
      '#required'      => TRUE,
    ];

    $form['reason'] = [
      '#type'          => 'textarea',
      '#title'         => $this->t('Business justification'),
      '#description'   => $this->t('Explain why you need this elevation. This is recorded in the audit log and shown to approvers.'),
      '#rows'          => 5,
      '#required'      => TRUE,
      '#maxlength'     => 2000,
    ];

    $form['actions'] = [
      '#type' => 'actions',
    ];

    $form['actions']['submit'] = [
      '#type'  => 'submit',
      '#value' => $this->t('Submit request'),
    ];

    $form['actions']['cancel'] = [
      '#type'  => 'link',
      '#title' => $this->t('Cancel'),
      '#url'   => Url::fromRoute('zero_standing_privilege.my_requests'),
      '#attributes' => ['class' => ['button']],
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $config  = $this->configFactory->get('zero_standing_privilege.settings');
    $maxMin  = (int) ($config->get('max_elevation_minutes') ?? 240);
    $minutes = (int) $form_state->getValue('duration_minutes');

    if ($minutes < 1) {
      $form_state->setErrorByName('duration_minutes', $this->t('Duration must be at least 1 minute.'));
    }

    if ($minutes > $maxMin) {
      $form_state->setErrorByName(
        'duration_minutes',
        $this->t('Duration cannot exceed @max minutes.', ['@max' => $maxMin])
      );
    }

    $reason = trim((string) $form_state->getValue('reason'));
    if (strlen($reason) < 10) {
      $form_state->setErrorByName('reason', $this->t('Please provide a meaningful justification (at least 10 characters).'));
    }

    // Prevent duplicate pending requests for the same role.
    $uid        = (int) $this->currentUser->id();
    $targetRole = (string) $form_state->getValue('target_role');
    $existing = $this->entityTypeManager->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('requester_uid', $uid)
      ->condition('target_role', $targetRole)
      ->condition('status', 'pending')
      ->count()
      ->execute();

    if ($existing > 0) {
      $form_state->setErrorByName(
        'target_role',
        $this->t('You already have a pending elevation request for the @role role.', ['@role' => $targetRole])
      );
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $uid        = (int) $this->currentUser->id();
    $targetRole = (string) $form_state->getValue('target_role');
    $minutes    = (int) $form_state->getValue('duration_minutes');
    $reason     = trim((string) $form_state->getValue('reason'));

    try {
      $request = $this->privilegeManager->createRequest($uid, $targetRole, $reason, $minutes);

      $config = $this->configFactory->get('zero_standing_privilege.settings');
      if ($config->get('require_approval')) {
        $this->messenger()->addStatus(
          $this->t('Your elevation request (#@id) has been submitted and is awaiting approval.', [
            '@id' => $request->id(),
          ])
        );
      }
      else {
        $this->messenger()->addStatus(
          $this->t('Your elevation request (#@id) has been automatically approved. The @role role is now active.', [
            '@id'   => $request->id(),
            '@role' => $targetRole,
          ])
        );
      }

      $form_state->setRedirectUrl(Url::fromRoute('zero_standing_privilege.my_requests'));
    }
    catch (\Exception $e) {
      $this->messenger()->addError(
        $this->t('Your elevation request could not be submitted: @msg', ['@msg' => $e->getMessage()])
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Builds a role options array for the select element, filtered to allowed.
   *
   * @param string[] $allowedRoles
   *   Machine names of allowed roles (empty = all non-system roles).
   *
   * @return array<string, string>
   */
  private function buildRoleOptions(array $allowedRoles): array {
    $roles = $this->entityTypeManager->getStorage('user_role')->loadMultiple();
    $options = [];

    foreach ($roles as $role) {
      if (in_array($role->id(), ['anonymous', 'authenticated'], TRUE)) {
        continue;
      }
      if (!empty($allowedRoles) && !in_array($role->id(), $allowedRoles, TRUE)) {
        continue;
      }
      $options[$role->id()] = $role->label();
    }

    return $options;
  }

}
