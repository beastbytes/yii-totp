<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp\Tests;

use BeastBytes\Yii\Totp\Totp;
use Generator;
use PHPUnit\Framework\Attributes\BeforeClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Symfony\Component\Clock\MockClock;

class TotpTest extends TestCase
{
    private const TEST_SECRET = 'JDDK4U6G3BJLEZ7Y';
    private const EPOCH = 319690800;
    private const INVALID_OTP = '621254';
    private const VALID_OTP = '762124';

    private static array $params;
    private static Totp $totp;

    #[BeforeClass]
    public static function init(): void
    {
        self::$params = require dirname(__DIR__) . '/config/params.php';
        self::$totp = new Totp(
            clock: new MockClock((new \DateTimeImmutable())->setTimestamp(self::EPOCH)),
            digest: self::$params['beastbytes/yii-totp']['totp']['digest'],
            digits: self::$params['beastbytes/yii-totp']['totp']['digits'],
            leeway: self::$params['beastbytes/yii-totp']['totp']['leeway'],
            period: self::$params['beastbytes/yii-totp']['totp']['period'],
            secretLength: self::$params['beastbytes/yii-totp']['totp']['secretLength'],
        );
    }

    #[Test]
    public function totpParameters(): void
    {
        $this->assertSame(
            self::$params['beastbytes/yii-totp']['totp']['digest'],
            self::$totp->getDigest()
        );
        $this->assertSame(
            self::$params['beastbytes/yii-totp']['totp']['digits'],
            self::$totp->getDigits()
        );
        $this->assertSame(
            self::$params['beastbytes/yii-totp']['totp']['leeway'],
            self::$totp->getLeeway()
        );
        $this->assertSame(
            self::$params['beastbytes/yii-totp']['totp']['period']
            , self::$totp->getPeriod()
        );
        $this->assertSame(
            self::$params['beastbytes/yii-totp']['totp']['secretLength'],
            strlen(self::$totp->getSecret())
        );
        $this->assertMatchesRegularExpression(Totp::SECRET_REGEX, self::$totp->getSecret());
    }

    #[Test]
    #[DataProvider('urlParameters')]
    public function provisioningUrl(?string $label, ?string $issuer, array $params, string $pattern): void
    {
        $actual = self::$totp->getProvisioningUri($label, $issuer, $params);
        $this->assertMatchesRegularExpression($pattern, $actual);
    }

    #[Test]
    public function verifyOtp(): void
    {
        $reflectionSecret = new ReflectionProperty(self::$totp, 'secret');
        $reflectionSecret->setValue(self::$totp, self::TEST_SECRET);

        $this->assertFalse(self::$totp->verify(self::INVALID_OTP));
        $this->assertTrue(self::$totp->verify(self::VALID_OTP));
        // Same code can not be valid twice
        $this->assertFalse(self::$totp->verify(self::VALID_OTP));
        $this->assertSame(self::VALID_OTP, self::$totp->getLastCode());
    }

    public static function urlParameters(): Generator
    {
        yield [
            'label' => 'Totp Label',
            'issuer' => null,
            'params' => [],
            'pattern' => '|^'
                . 'otpauth://totp/Totp%20Label'
                . '\?secret=[\dA-Z]{' . Totp::DEFAULT_SECRET_LENGTH . '}'
                . '$|'
        ];
        yield [
            'label' => 'Totp Label',
            'issuer' => 'Totp Issuer',
            'params' => [],
            'pattern' => '|^'
                . 'otpauth://totp/Totp%20Issuer%3ATotp%20Label'
                . '\?issuer=Totp%20Issuer'
                . '\&secret=[\dA-Z]{' . Totp::DEFAULT_SECRET_LENGTH . '}'
                . '$|'
        ];
        yield [
            'label' => 'Totp Label',
            'issuer' => null,
            'params' => ['p1' => 'v1', 'p2' => 'v2'],
            'pattern' => '|^'
                . 'otpauth://totp/Totp%20Label'
                . '\?p1=v1'
                . '\&p2=v2'
                . '\&secret=[\dA-Z]{' . Totp::DEFAULT_SECRET_LENGTH . '}'
                . '$|'
        ];
        yield [
            'label' => 'Totp Label',
            'issuer' => 'Totp Issuer',
            'params' => ['p1' => 'v1', 'p2' => 'v2'],
            'pattern' => '|^'
                . 'otpauth://totp/Totp%20Issuer%3ATotp%20Label'
                . '\?issuer=Totp%20Issuer'
                . '\&p1=v1'
                . '\&p2=v2'
                . '\&secret=[\dA-Z]{' . Totp::DEFAULT_SECRET_LENGTH . '}'
                . '$|'
        ];
    }
}
