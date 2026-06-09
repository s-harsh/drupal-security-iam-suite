<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Unit\Service;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\csp_wizard\Service\CspPolicyBuilderService;
use Drupal\csp_wizard\Service\NonceGeneratorService;

/**
 * Unit tests for CspPolicyBuilderService.
 *
 * @coversDefaultClass \Drupal\csp_wizard\Service\CspPolicyBuilderService
 * @group csp_wizard
 */
final class CspPolicyBuilderServiceTest extends UnitTestCase {

  /**
   * Creates a service instance with controlled mock config.
   *
   * @param array<string, mixed> $settingsData
   *   Values for csp_wizard.settings.
   * @param array<string, mixed> $profilesData
   *   Values for csp_wizard.service_profiles.
   * @param string $fixedNonce
   *   A fixed nonce for deterministic tests.
   *
   * @return array{\Drupal\csp_wizard\Service\CspPolicyBuilderService, \Drupal\Core\Messenger\MessengerInterface}
   */
  private function createService(
    array $settingsData,
    array $profilesData = [],
    string $fixedNonce = 'abc123'
  ): array {
    $settingsConfig = $this->createMock(Config::class);
    $settingsConfig->method('get')->willReturnCallback(
      static fn(string $key) => $settingsData[$key] ?? NULL
    );

    $profilesConfig = $this->createMock(Config::class);
    $profilesConfig->method('get')->willReturnCallback(
      static fn(string $key) => $profilesData[$key] ?? NULL
    );

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturnCallback(
      static fn(string $name) => match ($name) {
        'csp_wizard.settings'       => $settingsConfig,
        'csp_wizard.service_profiles' => $profilesConfig,
        default                     => NULL,
      }
    );

    $nonceGenerator = $this->createMock(NonceGeneratorService::class);
    $nonceGenerator->method('getNonce')->willReturn($fixedNonce);

    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $messenger = $this->createMock(MessengerInterface::class);

    $service = new CspPolicyBuilderService(
      $configFactory,
      $nonceGenerator,
      $moduleHandler,
      $messenger,
    );

    return [$service, $messenger];
  }

  /**
   * Provides default settings with no services enabled.
   */
  private function defaultSettings(array $overrides = []): array {
    return array_merge([
      'nonce_enabled' => FALSE,
      'services'      => [
        'ckeditor5'    => FALSE,
        'gtm'          => FALSE,
        'stripe'       => FALSE,
        'youtube'      => FALSE,
        'recaptcha_v2' => FALSE,
        'recaptcha_v3' => FALSE,
        'custom_domains' => [],
      ],
      'directives' => [
        'default_src'     => ["'self'"],
        'script_src'      => [],
        'style_src'       => [],
        'img_src'         => ["'self'", 'data:'],
        'connect_src'     => ["'self'"],
        'frame_src'       => [],
        'font_src'        => ["'self'"],
        'object_src'      => ["'none'"],
        'base_uri'        => ["'self'"],
        'form_action'     => ["'self'"],
        'frame_ancestors' => ["'none'"],
        'upgrade_insecure' => TRUE,
      ],
      'pci_mode' => ['enabled' => FALSE, 'page_patterns' => [], 'trusted_types' => FALSE],
    ], $overrides);
  }

  /**
   * @covers ::buildHeader
   */
  public function testBuildHeaderWithNoServicesContainsBaseDirectives(): void {
    [$service] = $this->createService($this->defaultSettings());
    $header = $service->buildHeader();

    $this->assertStringContainsString("default-src 'self'", $header);
    $this->assertStringContainsString("object-src 'none'", $header);
    $this->assertStringContainsString("upgrade-insecure-requests", $header);
  }

  /**
   * @covers ::buildHeader
   */
  public function testBuildHeaderWithGtmAddsGtmOrigin(): void {
    $settings = $this->defaultSettings([
      'services' => array_merge($this->defaultSettings()['services'], ['gtm' => TRUE]),
    ]);
    $profiles = [
      'gtm' => [
        'script_src' => ['https://www.googletagmanager.com'],
        'connect_src' => ['https://www.google-analytics.com'],
      ],
    ];

    [$service] = $this->createService($settings, $profiles);
    $header = $service->buildHeader();

    $this->assertStringContainsString('https://www.googletagmanager.com', $header);
  }

  /**
   * @covers ::buildHeader
   */
  public function testBuildHeaderWithStripeAddsStripeOrigins(): void {
    $settings = $this->defaultSettings([
      'services' => array_merge($this->defaultSettings()['services'], ['stripe' => TRUE]),
    ]);
    $profiles = [
      'stripe' => [
        'script_src' => ['https://js.stripe.com'],
        'frame_src'  => ['https://js.stripe.com', 'https://hooks.stripe.com'],
        'connect_src' => ['https://api.stripe.com'],
      ],
    ];

    [$service] = $this->createService($settings, $profiles);
    $header = $service->buildHeader();

    $this->assertStringContainsString('https://js.stripe.com', $header);
    $this->assertStringContainsString('https://hooks.stripe.com', $header);
    $this->assertStringContainsString('https://api.stripe.com', $header);
  }

  /**
   * @covers ::buildHeader
   */
  public function testNonceIsIncludedInScriptSrcWhenEnabled(): void {
    $settings = $this->defaultSettings(['nonce_enabled' => TRUE]);

    [$service] = $this->createService($settings, [], 'testNonce123456789012345678901234');
    $header = $service->buildHeader();

    $this->assertStringContainsString("'nonce-testNonce123456789012345678901234'", $header);
  }

  /**
   * @covers ::buildHeader
   */
  public function testStrictDynamicAddedWhenGtmAndNonceEnabled(): void {
    $settings = $this->defaultSettings([
      'nonce_enabled' => TRUE,
      'services' => array_merge($this->defaultSettings()['services'], ['gtm' => TRUE]),
    ]);
    $profiles = [
      'gtm' => ['script_src' => ['https://www.googletagmanager.com'], 'connect_src' => []],
    ];

    [$service] = $this->createService($settings, $profiles, 'fixedNonce1234567890123456789012');
    $header = $service->buildHeader();

    $this->assertStringContainsString("'strict-dynamic'", $header);
  }

  /**
   * @covers ::buildHeader
   */
  public function testStrictDynamicNotAddedWithoutGtm(): void {
    $settings = $this->defaultSettings(['nonce_enabled' => TRUE]);

    [$service] = $this->createService($settings, [], 'fixedNonce1234567890123456789012');
    $header = $service->buildHeader();

    $this->assertStringNotContainsString("'strict-dynamic'", $header);
  }

  /**
   * @covers ::buildHeader
   */
  public function testUnsafeInlineWithNonceEmitsMessengerWarning(): void {
    $settings = $this->defaultSettings([
      'nonce_enabled' => TRUE,
      'directives' => array_merge($this->defaultSettings()['directives'], [
        'script_src' => ["'unsafe-inline'"],
      ]),
    ]);

    [$service, $messenger] = $this->createService($settings, [], 'nonce1234567890123456789012345678');
    $messenger->expects($this->once())->method('addWarning');

    $service->buildHeader();
  }

  /**
   * @covers ::buildHeader
   */
  public function testHeaderStringContainsNoNewlines(): void {
    $settings = $this->defaultSettings(['nonce_enabled' => TRUE]);

    [$service] = $this->createService($settings, [], 'cleanNonce12345678901234567890123');
    $header = $service->buildHeader();

    $this->assertStringNotContainsString("\r", $header);
    $this->assertStringNotContainsString("\n", $header);
  }

  /**
   * @covers ::buildPaymentHeader
   */
  public function testBuildPaymentHeaderUsesPaymentPolicyDirectives(): void {
    $settings = $this->defaultSettings(['nonce_enabled' => FALSE]);

    $paymentConfig = $this->createMock(Config::class);
    $paymentConfig->method('get')->willReturnCallback(static fn(string $key) => match ($key) {
      'directives' => [
        'script_src'  => ["'self'"],
        'connect_src' => ["'self'", 'https://api.stripe.com'],
        'frame_src'   => ['https://js.stripe.com'],
        'trusted_types_policy_names' => [],
      ],
      default => NULL,
    });

    $settingsConfig = $this->createMock(Config::class);
    $settingsConfig->method('get')->willReturnCallback(
      static fn(string $k) => $settings[$k] ?? NULL
    );

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturnCallback(
      static fn(string $name) => match ($name) {
        'csp_wizard.settings'        => $settingsConfig,
        'csp_wizard.payment_policy'  => $paymentConfig,
        'csp_wizard.service_profiles' => $this->createMock(Config::class),
        default => NULL,
      }
    );

    $nonceGenerator = $this->createMock(NonceGeneratorService::class);
    $nonceGenerator->method('getNonce')->willReturn('paymentNonce1234567890123456789');

    $service = new CspPolicyBuilderService(
      $configFactory,
      $nonceGenerator,
      $this->createMock(ModuleHandlerInterface::class),
      $this->createMock(MessengerInterface::class),
    );

    $header = $service->buildPaymentHeader();
    $this->assertStringContainsString('https://api.stripe.com', $header);
    $this->assertStringContainsString('https://js.stripe.com', $header);
  }

}
