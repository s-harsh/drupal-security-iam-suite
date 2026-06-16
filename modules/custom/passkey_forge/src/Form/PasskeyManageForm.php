<?php

declare(strict_types=1);

namespace Drupal\passkey_forge\Form;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Url;
use Drupal\passkey_forge\Service\PasskeyStorage;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * User-facing form for managing their own passkeys.
 *
 * Rendered at /user/{user}/passkeys/register. Provides:
 *   - A registration button that triggers the passkey-register.js WebAuthn
 *     ceremony via the JS/JSON endpoints.
 *   - A table of existing passkeys with a delete (revoke) action per row.
 *
 * This is a standard Drupal Form, not ConfigFormBase, because it does not
 * manage configuration — it manages database-backed credential entities
 * and delegates to JS for the WebAuthn ceremony.
 */
final class PasskeyManageForm extends FormBase {

  /**
   * Constructs a PasskeyManageForm.
   *
   * @param \Drupal\passkey_forge\Service\PasskeyStorage $storage
   *   The passkey credential storage.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user proxy.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   */
  public function __construct(
    private readonly PasskeyStorage $storage,
    private readonly AccountProxyInterface $currentUser,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('passkey_forge.storage'),
      $container->get('current_user'),
      $container->get('entity_type.manager'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'passkey_forge_manage_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, ?int $user = null): array {
    $uid = $user ?? (int) $this->currentUser->id();

    // Access check: users can only manage their own passkeys unless they have
    // the 'administer passkey forge' permission.
    $isAdmin = $this->currentUser->hasPermission('administer passkey forge');
    $isSelf = (int) $this->currentUser->id() === $uid;

    if (!$isSelf && !$isAdmin) {
      return [
        '#markup' => $this->t('You do not have permission to manage passkeys for this account.'),
      ];
    }

    $account = $this->entityTypeManager->getStorage('user')->load($uid);
    if ($account === null) {
      return ['#markup' => $this->t('User not found.')];
    }

    $credentials = $this->storage->loadActiveByUid($uid);

    $form['#attached']['library'][] = 'passkey_forge/passkey_register';
    $form['#attached']['drupalSettings']['passkeyForge'] = [
      'challengeUrl' => Url::fromRoute('passkey_forge.register.challenge')->toString(),
      'completeUrl' => Url::fromRoute('passkey_forge.register.complete')->toString(),
      'uid' => $uid,
    ];

    $form['description'] = [
      '#markup' => '<p>' . $this->t(
        'Passkeys let you sign in securely using your device\'s built-in authenticator (fingerprint, face, PIN) or a hardware security key. No password needed.',
      ) . '</p>',
    ];

    $form['registration'] = [
      '#type' => 'details',
      '#title' => $this->t('Register a new passkey'),
      '#open' => empty($credentials),
    ];

    $form['registration']['label'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Passkey label'),
      '#description' => $this->t('Optional name to identify this passkey (e.g. "Work laptop", "YubiKey 5").'),
      '#maxlength' => 255,
      '#id' => 'passkey-label',
    ];

    $form['registration']['register_button'] = [
      '#type' => 'button',
      '#value' => $this->t('Register new passkey'),
      '#attributes' => [
        'id' => 'passkey-register-btn',
        'class' => ['button', 'button--primary'],
      ],
      '#limit_validation_errors' => [],
    ];

    $form['registration']['status'] = [
      '#markup' => '<div id="passkey-register-status" aria-live="polite"></div>',
    ];

    if (!empty($credentials)) {
      $header = [
        $this->t('Label'),
        $this->t('Registered'),
        $this->t('Last used'),
        $this->t('Transports'),
        $this->t('Actions'),
      ];

      $options = [];
      foreach ($credentials as $credential) {
        $options[$credential->id] = [
          'label' => $credential->label ?? $this->t('(unlabelled)'),
          'created' => date('Y-m-d H:i', $credential->created),
          'last_used' => $credential->lastUsed ? date('Y-m-d H:i', $credential->lastUsed) : $this->t('Never'),
          'transports' => implode(', ', $credential->transports) ?: $this->t('unknown'),
          'actions' => '',
        ];
      }

      $form['existing'] = [
        '#type' => 'details',
        '#title' => $this->t('Registered passkeys (@count)', ['@count' => count($credentials)]),
        '#open' => TRUE,
      ];

      $form['existing']['credentials_table'] = [
        '#type' => 'table',
        '#header' => $header,
        '#rows' => [],
        '#empty' => $this->t('No passkeys registered.'),
        '#attributes' => ['id' => 'passkey-list'],
      ];

      foreach ($credentials as $credential) {
        $form['existing']['credentials_table'][$credential->id] = [
          'label' => ['#markup' => $this->t('@label', ['@label' => $credential->label ?? $this->t('(unlabelled)')])],
          'created' => ['#markup' => date('Y-m-d H:i', $credential->created)],
          'last_used' => ['#markup' => $credential->lastUsed ? date('Y-m-d H:i', $credential->lastUsed) : $this->t('Never')],
          'transports' => ['#markup' => implode(', ', $credential->transports) ?: $this->t('unknown')],
          'actions' => [
            'delete' => [
              '#type' => 'submit',
              '#value' => $this->t('Remove'),
              '#name' => 'remove_' . $credential->id,
              '#submit' => ['::removeCredential'],
              '#attributes' => [
                'data-credential-id' => $credential->id,
                'class' => ['button', 'button--danger'],
              ],
              '#limit_validation_errors' => [],
            ],
          ],
        ];
      }
    }

    $form['uid'] = [
      '#type' => 'hidden',
      '#value' => $uid,
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   *
   * The primary form submit is handled by JS (WebAuthn ceremony).
   * This PHP submit handler is only reached by the "Remove" buttons.
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    // No-op: removal is handled by ::removeCredential().
  }

  /**
   * Submit handler for the "Remove" buttons in the credentials table.
   *
   * @param array<string, mixed> $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   */
  public function removeCredential(array &$form, FormStateInterface $form_state): void {
    $triggeringElement = $form_state->getTriggeringElement();
    $credentialId = (int) ($triggeringElement['#attributes']['data-credential-id'] ?? 0);
    $uid = (int) $form_state->getValue('uid');

    if ($credentialId <= 0) {
      $this->messenger()->addError($this->t('Invalid credential ID.'));
      return;
    }

    // Verify ownership before revoking.
    $isAdmin = $this->currentUser->hasPermission('administer passkey forge');
    $isSelf = (int) $this->currentUser->id() === $uid;

    if (!$isSelf && !$isAdmin) {
      $this->messenger()->addError($this->t('Access denied.'));
      return;
    }

    $revoked = $this->storage->revoke($credentialId, (int) $this->currentUser->id());

    if ($revoked) {
      $this->messenger()->addStatus($this->t('Passkey has been removed.'));
    } else {
      $this->messenger()->addError($this->t('Could not remove the passkey. It may have already been removed.'));
    }

    $form_state->setRedirect('passkey_forge.register', ['user' => $uid]);
  }

}
