<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp\Tests;

use BeastBytes\Yii\Totp\Totp;
use BeastBytes\Yii\Totp\TotpService;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\BeforeClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use Symfony\Component\Clock\MockClock;
use Yiisoft\Security\Crypt;
use Yiisoft\Security\Random;

class TotpServiceTest extends TestCase
{
    use DatabaseTrait;

    private const TEST_SECRET = 'JDDK4U6G3BJLEZ7Y';
    private const EPOCH = 319690800;
    private const INVALID_OTP = '621254';
    private const VALID_OTP = '762124';

    private const LABEL = 'TOTP Test';
    private const ISSUER = 'PupUnit';
    private const QR_CODE_REGEX = '/^data:image\/svg\+xml;base64,[\da-zA-Z]+(\+[\da-zA-Z]+)+=+$/';
    private const USER_ID = '35';

    private static Crypt $crypt;
    private static Totp $totp;

    private TotpService $totpService;

    #[BeforeClass]
    public static function init(): void
    {
        parent::init();

        self::$crypt = new Crypt(self::$params['beastbytes/yii-totp']['crypt']['cipher']);
        self::$totp = new Totp(
            clock: new MockClock((new \DateTimeImmutable())->setTimestamp(self::EPOCH)),
            digest: self::$params['beastbytes/yii-totp']['totp']['digest'],
            digits: self::$params['beastbytes/yii-totp']['totp']['digits'],
            leeway: self::$params['beastbytes/yii-totp']['totp']['leeway'],
            period: self::$params['beastbytes/yii-totp']['totp']['period'],
            secretLength: self::$params['beastbytes/yii-totp']['totp']['secretLength'],
        );
    }

    #[Before]
    protected function before(): void
    {
        $database = $this->getDatabase();
        $this->runMigrations();

        $this->totpService = new TotpService(
            backupCodeCount: self::$params['beastbytes/yii-totp']['backupCode']['count'],
            backupCodeLength: self::$params['beastbytes/yii-totp']['backupCode']['length'],
            crypt: self::$crypt,
            database: $database,
            encryptionKey: self::$params['beastbytes/yii-totp']['crypt']['key'],
            otpBackupCodeTable: self::$params['beastbytes/yii-totp']['database']['otpBackupCodeTable'],
            totp: self::$totp,
            totpTable: self::$params['beastbytes/yii-totp']['database']['totpTable'],
        );
    }

    #[After]
    protected function after(): void
    {
        $this
            ->totpService
            ->disableTotp(self::USER_ID)
        ;
    }

    #[Test]
    public function backupCodes(): void
    {
        $this->assertSame(
            0,
            $this->totpService->countBackupCodes(self::USER_ID),
        );

        $backupCodes = $this
            ->totpService
            ->createBackupCodes(self::USER_ID)
        ;

        $this->assertCount(
            self::$params['beastbytes/yii-totp']['backupCode']['count'],
            $backupCodes,
        );

        foreach ($backupCodes as $backupCode) {
            $this->assertIsString($backupCode);
            $this->assertMatchesRegularExpression(
                '/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?!.*_)(?!.*\W)(?!.* ).{'
                    . self::$params['beastbytes/yii-totp']['backupCode']['length']
                    .'}$/',
                $backupCode,
            );
        }

        do {
            $invalidBackupCode = Random::string(self::$params['beastbytes/yii-totp']['backupCode']['length']);
        } while (
            in_array($invalidBackupCode, $backupCodes)
            || preg_match(TotpService::BACKUP_CODE_REGEX, $invalidBackupCode) === 0)
        ;

        $this->assertFalse(
            $this
                ->totpService
                ->verify($invalidBackupCode, self::USER_ID),
        );

        $backupCode = $backupCodes[array_rand($backupCodes)];

        $this->assertTrue(
            $this
                ->totpService
                ->verify($backupCode, self::USER_ID),
        );

        $this->assertFalse(
            $this
                ->totpService
                ->verify($backupCode, self::USER_ID),
        );

        $this->assertSame(
            self::$params['beastbytes/yii-totp']['backupCode']['count'] - 1,
            $this->totpService->countBackupCodes(self::USER_ID),
        );

        $this->assertCount(
            self::$params['beastbytes/yii-totp']['backupCode']['count'],
            $this
                ->totpService
                ->createBackupCodes(self::USER_ID),
        );
    }

    #[Test]
    public function createTotp(): void
    {
        $this->assertFalse(
            $this
                ->totpService
                ->isTotpEnabled(self::USER_ID),
        );

        $result = $this
            ->totpService
            ->createTotp(self::USER_ID, self::LABEL, self::ISSUER)
        ;

        $this->assertArrayHasKey('qrcode', $result);
        $this->assertArrayHasKey('secret', $result);
        $this->assertIsString($result['qrcode']);
        $this->assertIsString($result['secret']);
        $this->assertMatchesRegularExpression(
            self::QR_CODE_REGEX,
            $result['qrcode'],
        );
        $this->assertMatchesRegularExpression(
            Totp::SECRET_REGEX,
            $result['secret'],
        );
        $this->assertSame(Totp::DEFAULT_SECRET_LENGTH, strlen($result['secret']));

        $this->assertTrue(
            $this
                ->totpService
                ->isTotpEnabled(self::USER_ID),
        );
    }

    #[Test]
    public function disableTotp()
    {
        $this
            ->totpService
            ->createTotp(self::USER_ID, self::LABEL, self::ISSUER)
        ;

        $this->assertTrue(
            $this
                ->totpService
                ->isTotpEnabled(self::USER_ID),
        );

        $this
            ->totpService
            ->disableTotp(self::USER_ID)
        ;

        $this->assertFalse(
            $this
                ->totpService
                ->isTotpEnabled(self::USER_ID),
        );
    }

    #[Test]
    public function verifyOtp(): void
    {
        $reflectionSecret = new ReflectionProperty(self::$totp, 'secret');
        $reflectionSecret->setValue(self::$totp, self::TEST_SECRET);

        $totpService = new TotpService(
            backupCodeCount: self::$params['beastbytes/yii-totp']['backupCode']['count'],
            backupCodeLength: self::$params['beastbytes/yii-totp']['backupCode']['length'],
            crypt: self::$crypt,
            database: $this->getDatabase(),
            encryptionKey: self::$params['beastbytes/yii-totp']['crypt']['key'],
            otpBackupCodeTable: self::$params['beastbytes/yii-totp']['database']['otpBackupCodeTable'],
            totp: self::$totp,
            totpTable: self::$params['beastbytes/yii-totp']['database']['totpTable'],
        );

        $totpService
            ->createTotp(self::USER_ID, self::LABEL, self::ISSUER)
        ;

        $this->assertFalse($totpService->verify(self::INVALID_OTP, self::USER_ID));
        $this->assertTrue($totpService->verify(self::VALID_OTP, self::USER_ID));
        // Same code can not be valid twice
        $this->assertFalse($totpService->verify(self::VALID_OTP, self::USER_ID));
    }
}