<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Unit\Hook;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\StatementInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\csp_wizard\Hook\CspWizardHooks;
use Drupal\csp_wizard\Service\NonceGeneratorService;

/**
 * Unit tests for CspWizardHooks.
 *
 * @coversDefaultClass \Drupal\csp_wizard\Hook\CspWizardHooks
 * @group csp_wizard
 */
final class CspWizardHooksTest extends UnitTestCase {

  /**
   * Creates a CspWizardHooks instance with mock dependencies.
   */
  private function createHooks(
    string $mode = 'report_only',
    bool $nonceEnabled = TRUE,
    bool $cspModuleExists = FALSE,
  ): CspWizardHooks {
    $config = $this->createMock(Config::class);
    $config->method('get')->willReturnCallback(static fn(string $key) => match ($key) {
      'mode'          => $mode,
      'nonce_enabled' => $nonceEnabled,
      default         => NULL,
    });

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')
      ->with('csp_wizard.settings')
      ->willReturn($config);

    $nonceGenerator = $this->createMock(NonceGeneratorService::class);
    $nonceGenerator->method('getNonce')->willReturn('testNonce12345678901234567890123');

    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $moduleHandler->method('moduleExists')
      ->willReturnCallback(static fn(string $m) => $m === 'csp' && $cspModuleExists);

    // Mock database to return NULL for last violation (no watchdog table).
    $statement = $this->createMock(StatementInterface::class);
    $statement->method('fetchField')->willReturn(FALSE);

    $selectQuery = $this->getMockBuilder(\Drupal\Core\Database\Query\Select::class)
      ->disableOriginalConstructor()
      ->getMock();
    $selectQuery->method('fields')->willReturnSelf();
    $selectQuery->method('condition')->willReturnSelf();
    $selectQuery->method('orderBy')->willReturnSelf();
    $selectQuery->method('range')->willReturnSelf();
    $selectQuery->method('execute')->willReturn($statement);

    $database = $this->createMock(Connection::class);
    $database->method('select')->willReturn($selectQuery);

    return new CspWizardHooks($nonceGenerator, $configFactory, $moduleHandler, $database);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsModeModeKeyForRuntime(): void {
    $hooks = $this->createHooks();
    $requirements = $hooks->requirements('runtime');

    $this->assertArrayHasKey('csp_wizard_mode', $requirements);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsViolationsKeyForRuntime(): void {
    $hooks = $this->createHooks();
    $requirements = $hooks->requirements('runtime');

    $this->assertArrayHasKey('csp_wizard_violations', $requirements);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsEmptyArrayForInstallPhase(): void {
    $hooks = $this->createHooks();
    $requirements = $hooks->requirements('install');

    $this->assertSame([], $requirements);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsShowsInfoSeverityInReportOnlyMode(): void {
    $hooks = $this->createHooks(mode: 'report_only');
    $requirements = $hooks->requirements('runtime');

    $this->assertSame(REQUIREMENT_INFO, $requirements['csp_wizard_mode']['severity']);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsShowsWarningWhenCspModuleAlsoEnabled(): void {
    $hooks = $this->createHooks(mode: 'enforce', cspModuleExists: TRUE);
    $requirements = $hooks->requirements('runtime');

    $this->assertSame(REQUIREMENT_WARNING, $requirements['csp_wizard_mode']['severity']);
  }

  /**
   * @covers ::pageAttachmentsAlter
   */
  public function testPageAttachmentsAlterInjectsNonceIntoDrupalSettings(): void {
    $hooks = $this->createHooks(nonceEnabled: TRUE);
    $attachments = ['#attached' => []];
    $hooks->pageAttachmentsAlter($attachments);

    $this->assertArrayHasKey('drupalSettings', $attachments['#attached']);
    $this->assertArrayHasKey('cspWizard', $attachments['#attached']['drupalSettings']);
    $this->assertArrayHasKey('nonce', $attachments['#attached']['drupalSettings']['cspWizard']);
    $this->assertNotEmpty($attachments['#attached']['drupalSettings']['cspWizard']['nonce']);
  }

  /**
   * @covers ::pageAttachmentsAlter
   */
  public function testPageAttachmentsAlterStampsNonceOnInlineScriptElement(): void {
    $hooks = $this->createHooks(nonceEnabled: TRUE);
    $attachments = [
      '#attached' => [
        'html_head' => [
          [
            ['#tag' => 'script', '#value' => 'var x = 1;', '#attributes' => []],
            'my_inline_script',
          ],
        ],
      ],
    ];

    $hooks->pageAttachmentsAlter($attachments);

    $scriptElement = $attachments['#attached']['html_head'][0][0];
    $this->assertArrayHasKey('nonce', $scriptElement['#attributes']);
    $this->assertNotEmpty($scriptElement['#attributes']['nonce']);
  }

  /**
   * @covers ::pageAttachmentsAlter
   */
  public function testPageAttachmentsAlterDoesNotStampNonceOnExternalScript(): void {
    $hooks = $this->createHooks(nonceEnabled: TRUE);
    $attachments = [
      '#attached' => [
        'html_head' => [
          [
            ['#tag' => 'script', '#attributes' => ['src' => 'https://cdn.example.com/app.js']],
            'my_external_script',
          ],
        ],
      ],
    ];

    $hooks->pageAttachmentsAlter($attachments);

    $scriptElement = $attachments['#attached']['html_head'][0][0];
    $this->assertArrayNotHasKey('nonce', $scriptElement['#attributes']);
  }

  /**
   * @covers ::pageAttachmentsAlter
   */
  public function testPageAttachmentsAlterSkipsWhenNonceDisabled(): void {
    $hooks = $this->createHooks(nonceEnabled: FALSE);
    $attachments = ['#attached' => []];
    $hooks->pageAttachmentsAlter($attachments);

    $this->assertArrayNotHasKey('drupalSettings', $attachments['#attached']);
  }

  /**
   * @covers ::elementInfoAlter
   */
  public function testElementInfoAlterAppendsPreRenderCallbackToHtmlTag(): void {
    $hooks = $this->createHooks();
    $types = ['html_tag' => ['#pre_render' => []]];
    $hooks->elementInfoAlter($types);

    $callbacks = $types['html_tag']['#pre_render'];
    $found = FALSE;
    foreach ($callbacks as $cb) {
      if (is_array($cb) && $cb[1] === 'preRenderAddNonce') {
        $found = TRUE;
        break;
      }
    }
    $this->assertTrue($found, 'preRenderAddNonce callback must be present in html_tag #pre_render.');
  }

}
