<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp;

use chillerlan\QRCode\QRCode;
use Exception;
use JsonException;
use OTPHP\TOTPInterface;
use Psr\Clock\ClockInterface;
use ReflectionException;
use ReflectionProperty;
use Throwable;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Db\Exception\InvalidArgumentException;
use Yiisoft\Db\Exception\InvalidConfigException;
use Yiisoft\Db\Exception\NotSupportedException;
use Yiisoft\Db\Query\Query;
use Yiisoft\Security\Crypt;
use Yiisoft\Security\PasswordHasher;
use Yiisoft\Security\Random;

class TotpService
{
    private const OTP_CODE_REGEX = '/^\d+$/';

    private Crypt $crypt;

    /**
     * @param ClockInterface $clock Clock instance.
     * @param ConnectionInterface $database Yii database connection instance.
     * @param string $otpBackupCodesTable Table name for OTP backup codes.
     * @psalm-param non-empty-string $otpBackupCodesTable Table name for OTP backup codes.
     * @param string $totpTable Table name for TOTP codes and data.
     * @psalm-param non-empty-string $totpTable Table name for OTP codes and data.     *
     * @param string $totpDigest HMAC digest algorithm for TOTP.
     * @psalm-param non-empty-string $totpDigest HMAC digest algorithm for TOTP.
     * @param int $totpDigits Number of digits in the OTP code.
     * @param int $totpLeeway Leeway in seconds that an OTP code is valid before or after the period;
     * @param int $totpPeriod Period in seconds that an OTP code is valid.     *
     * @param int $backupCodeCount Number of backup codes to generate
     * @param int $backupCodeLength Length of each backup code
     * @param PasswordHasher $passwordHasher Password hasher.
     * @param string $cipher Encryption cipher
     * @psalm-param non-empty-string $cipher Encryption cipher
     * @param int $iterations Number of iterations for the key derivation function
     * @param string $kdfAlgorithm Hash algorithm for key derivation
     * @psalm-param non-empty-string $kdfAlgorithm Hash algorithm for key derivation
     * @param string $authorizationKeyInfo HKDF info value for derivation of message authentication key
     * @psalm-param non-empty-string $authorizationKeyInfo HKDF info value for derivation of message authentication key
     * @param string $key Key for encryption and decryption
     * @psalm-param non-empty-string $key Key for encryption and decryption
     */
    public function __construct(
        private readonly ClockInterface $clock,
        private readonly ConnectionInterface $database,
        private readonly string $otpBackupCodesTable,
        private readonly string $totpTable,
        private readonly string $totpDigest,
        private readonly int $totpDigits,
        private readonly int $totpLeeway,
        private readonly int $totpPeriod,
        private readonly int $backupCodeCount,
        private readonly int $backupCodeLength,
        private readonly PasswordHasher $passwordHasher,
        string $cipher,
        int $iterations,
        string $kdfAlgorithm,
        string $authorizationKeyInfo,
        private readonly string $key,
    )
    {
        $crypt = new Crypt($cipher);
        $crypt = $crypt->withDerivationIterations($iterations);
        $crypt = $crypt->withKdfAlgorithm($kdfAlgorithm);
        $crypt = $crypt->withKdfAlgorithm($authorizationKeyInfo);

        $this->crypt = $crypt;
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function backupCodeCount(string $userId): int
    {
        return (new Query($this->database))
            ->from($this->otpBackupCodesTable)
            ->where(['user_id' => $userId])
            ->count()
        ;
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws InvalidArgumentException
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function disable(string $userId): void
    {
        $this
            ->database
            ->createCommand()
            ->delete($this->totpTable, ['user_id' => $userId])
            ->execute()
        ;
        $this
            ->database
            ->createCommand()
            ->delete($this->otpBackupCodesTable, ['user_id' => $userId])
            ->execute()
        ;
    }

    /**
     * @param string $userId
     * @return string[]
     * @throws Exception
     * @throws Throwable
     */
    public function generateBackupCodes(string $userId): array
    {
        $this
            ->database
            ->createCommand()
            ->delete($this->otpBackupCodesTable, ['user_id' => $userId])
            ->execute()
        ;

        $codes = [];
        $rows = [];
        for ($i = 0; $i < $this->backupCodeCount; $i++) {
            do {
                $code = Random::string($this->backupCodeLength);
            } while (str_contains($code, '_') || preg_match(self::OTP_CODE_REGEX, $code) === 1);

            $codes[] = $code;
            $rows[] = [
                $userId,
                $this
                    ->passwordHasher
                    ->hash($code),
            ];
        }

        $this
            ->database
            ->createCommand()
            ->batchInsert(
                $this->otpBackupCodesTable,
                ['user_id', 'code'],
                $rows,
            )
            ->execute()
        ;

        return $codes;
    }

    /**
     * @param TOTPInterface $totp The TOTP object
     * @param ?string $label Label for the TOTP. Usually the organisation or application name.
     * @param ?string $issuer Issuer of the TOTP. Usually the application URL. Ignored if $label in null
     * @return string Base-64 encoded string representation of the QR code
     * @psalm-return  non-empty-string Base-64 encoded string representation of the QR code
     * @throws Exception
     */
    public function generateQrCode(TOTPInterface $totp, ?string $label = null, ?string $issuer = null): string
    {
        $uri = $totp->getProvisioningUri($label, $issuer);

        return (new QRCode())->render($uri);
    }

    public function generateTotp(): Totp
    {
        return new Totp(
            $this->clock,
            $this->totpDigest,
            $this->totpDigits,
            $this->totpLeeway,
            $this->totpPeriod,
        );
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws ReflectionException
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function getTotp(string $userId): ?Totp
    {
        $row = (new Query($this->database))
            ->from($this->totpTable)
            ->where(['user_id' => $userId])
            ->one()
        ;

        return $row === null ? null : $this->createTotp($row, $userId);
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws NotSupportedException
     * @throws \Yiisoft\Db\Exception\Exception
     * @throws JsonException
     */
    public function saveTotp(Totp $totp, string $userId): void
    {
        $this
            ->database
            ->createCommand()
            ->upsert(
                $this->totpTable,
                [
                    'digest' => $totp->getDigest(),
                    'digits' => $totp->getDigits(),
                    'leeway' => $totp->getLeeway(),
                    'last_totp' => $totp->getLastTotp(),
                    'period' => $totp->getPeriod(),
                    'secret' => $this->crypt->encryptByKey($totp->getSecret(), $this->key, $userId),
                    'user_id' => $userId,
                ]
            )
            ->execute()
        ;
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws ReflectionException
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function verifyTotp(string $code, string $userId): bool
    {
        if (preg_match(self::OTP_CODE_REGEX, $code) === 1) {
            $totp = $this->getTotp($userId);
            return $totp instanceof Totp && $totp->verify($code);
        }

        return $this->verifyBackupCode($code, $userId);
    }

    /**
     * @throws ReflectionException
     * @throws Exception
     */
    private function createTotp(array $data, string $userId): Totp
    {
        $totp = $this->generateTotp();

        foreach ([
            'digest' => 'digest',
            'digits' => 'digits',
            'leeway' => 'leeway',
            'last_totp' => 'lastTotp',
            'period' => 'period',
            'secret' => 'secret',
            'user_id' => 'userId',
        ] as $key => $property) {
            $reflectionProperty = new ReflectionProperty($totp, $property);
            $reflectionProperty->setValue(
                $totp,
                $property === 'secret'
                    ? $this->crypt->decryptByKey($data[$key], $this->key, $userId)
                    : $data[$key]
            );
        }

        return $totp;
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws \Yiisoft\Db\Exception\Exception
     */
    private function verifyBackupCode(string $code, string $userId): bool
    {
        $row = (new Query($this->database))
            ->from($this->otpBackupCodesTable)
            ->where(['user_id' => $userId, 'code' => $this->passwordHasher->hash($code)])
            ->one()
        ;

        if ($row !== null) {
            $this
                ->database
                ->createCommand()
                ->delete($this->otpBackupCodesTable, ['id' => $row['id']])
                ->execute()
            ;

            return true;
        }

        return false;
    }
}