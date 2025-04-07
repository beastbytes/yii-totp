<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp;

use chillerlan\QRCode\QRCode;
use Exception;
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
    /**
     * Number of backup codes to generate
     */
    public const BACKUP_CODE_COUNT = 10;
    /**
     * Length of each backup code
     */
    public const BACKUP_CODE_LENGTH = 16;
    /** @var string Backup codes only contain digits and upper and lowercase letters */
    public const BACKUP_CODE_REGEX = '/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?!.*_)(?!.*\W)(?!.* ).+$/';
    /**
     * Derivation iterations count
     */
    public const CRYPT_ITERATIONS = 100000;
    /**
     * Encryption/Decryption key. Should be changed
     */
    public const CRYPT_KEY = 'rstswSLBfzMKLyELbvKSkfT3qkHjAVoSQtVNSkWimeiGbOABqJXA3NqFYtXyewpS';

    /**
     * @param positive-int $backupCodeCount Number of backup codes to generate
     * @param positive-int $backupCodeLength Length of each backup code
     * @param Crypt $crypt Crypt instance
     * @param ConnectionInterface $database Yii database connection instance
     * @psalm-param non-empty-string $encryptionKey Key for encryption and decryption
     * @psalm-param non-empty-string $otpBackupCodeTable Table name for OTP backup codes
     * @param Totp $totp TOTP instance
     * @psalm-param non-empty-string $totpTable Table name for OTP codes and data
     */
    public function __construct(
        private readonly int $backupCodeCount,
        private readonly int $backupCodeLength,
        private readonly Crypt $crypt,
        private readonly ConnectionInterface $database,
        private readonly string $encryptionKey,
        private readonly string $otpBackupCodeTable,
        private readonly Totp $totp,
        private readonly string $totpTable,
    )
    {
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function countBackupCodes(string $userId): int
    {
        return (new Query($this->database))
            ->from($this->otpBackupCodeTable)
            ->where(['user_id' => $userId])
            ->count()
        ;
    }

    /**
     * @param string $userId
     * @return string[]
     * @throws Exception
     * @throws Throwable
     */
    public function createBackupCodes(string $userId): array
    {
        $this
            ->database
            ->createCommand()
            ->delete($this->otpBackupCodeTable, ['user_id' => $userId])
            ->execute()
        ;

        $codes = [];
        $rows = [];
        $passwordHasher = new PasswordHasher();

        for ($i = 0; $i < $this->backupCodeCount; $i++) {
            do {
                $code = Random::string($this->backupCodeLength);
            } while (preg_match(self::BACKUP_CODE_REGEX, $code) === 0);

            $codes[] = $code;
            $rows[] = [
                $userId,
                $passwordHasher
                    ->hash($code)
                ,
            ];
        }

        $this
            ->database
            ->createCommand()
            ->batchInsert(
                $this->otpBackupCodeTable,
                ['user_id', 'code'],
                $rows,
            )
            ->execute()
        ;

        return $codes;
    }

    /**
     * Creates a TOTP for a user and returns the provisioning QR code as a string
     * that can be used as the src attribute of an <img/> tag and the secret value for the TOTP.
     * The application should verify that the user can enter a valid TOTP code after creating a TOTP.
     *
     * @param string $userId id of the user to create a TOTP for.
     * @param string $label Label for the TOTP. Usually the organisation or application name.
     * @param ?string $issuer Issuer of the TOTP.
     * @param array $params Additional parameters for the provisioning URI as key=>value pairs.
     * @psalm-return [qrcode: string, secret: string] QR code and TOTP secret
     * @throws InvalidArgumentException
     * @throws InvalidConfigException
     * @throws NotSupportedException
     * @throws Throwable
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function createTotp(string $userId, string $label, ?string $issuer = null, array $params = []): array
    {
        $this
            ->database
            ->createCommand()
            ->insert(
                $this->totpTable,
                [
                    'digest' => $this->totp->getDigest(),
                    'digits' => $this->totp->getDigits(),
                    'leeway' => $this->totp->getLeeway(),
                    'last_code' => '',
                    'period' => $this->totp->getPeriod(),
                    'secret' => $this->crypt->encryptByKey($this->totp->getSecret(), $this->encryptionKey, $userId),
                    'user_id' => $userId,
                ]
            )
            ->execute()
        ;

        return [
            'qrcode' => (new QRCode())->render(
                $this->totp->getProvisioningUri($label, $issuer, $params)
            ),
            'secret' => $this->totp->getSecret(),
        ];
    }

    /**
     * Disable TOTP for a user by deleting their TOTP and backup codes.
     *
     * @param string $userId id of the user whose TOTP snd backup codes to delete.
     * @return void
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws InvalidArgumentException
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function disableTotp(string $userId): void
    {
        $this
            ->database
            ->createCommand()
            ->delete($this->otpBackupCodeTable, ['user_id' => $userId])
            ->execute()
        ;
        $this
            ->database
            ->createCommand()
            ->delete($this->totpTable, ['user_id' => $userId])
            ->execute()
        ;
    }

    /**
     * Whether TOTP is enabled for a user.
     *
     * @param string $userId ID of the user to check
     * @return bool true if TOTP is enabled, false if TOTP is not enabled
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws InvalidArgumentException
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function isTotpEnabled(string $userId): bool
    {
        return (new Query($this->database))
            ->from($this->totpTable)
            ->where(['user_id' => $userId])
            ->count()
            === 1
        ;
    }

    /**
     * Verifies a TOTP or backup code.
     * If a backup code is being verified and verification is successful, the backup code is deleted to prevent reuse.
     *
     * @param string $code the code to verify.
     * @param string $userId id of the user to verify against.
     * @return bool true is verification is successful, false if it fails
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws ReflectionException
     * @throws \Yiisoft\Db\Exception\Exception
     */
    public function verify(string $code, string $userId): bool
    {
        if (preg_match(self::BACKUP_CODE_REGEX, $code) === 1) {
            return $this->verifyBackupCode($code, $userId);
        }

        return $this->verifyOtpCode($code, $userId);
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws ReflectionException
     * @throws \Yiisoft\Db\Exception\Exception
     */
    private function getTotp(string $userId): ?Totp
    {
        $row = (new Query($this->database))
            ->from($this->totpTable)
            ->where(['user_id' => $userId])
            ->one()
        ;

        if ($row === null) {
            return null;
        }

        foreach ([
            'digest' => 'digest',
            'digits' => 'digits',
            'leeway' => 'leeway',
            'last_code' => 'lastCode',
            'period' => 'period',
            'secret' => 'secret',
        ] as $key => $property) {
            $reflectionProperty = new ReflectionProperty($this->totp, $property);
            $reflectionProperty->setValue(
                $this->totp,
                $property === 'secret'
                    ? $this->crypt->decryptByKey($row[$key], $this->encryptionKey, $userId)
                    : $row[$key]
            );
        };

        return $this->totp;
    }

    /**
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws \Yiisoft\Db\Exception\Exception
     */
    private function verifyBackupCode(string $code, string $userId): bool
    {
        $rows = (new Query($this->database))
            ->from($this->otpBackupCodeTable)
            ->where(['user_id' => $userId])
            ->all()
        ;

        foreach ($rows as $row) {
            if ((new PasswordHasher())->validate($code, $row['code'])) {
                $this
                    ->database
                    ->createCommand()
                    ->delete($this->otpBackupCodeTable, ['id' => $row['id']])
                    ->execute()
                ;

                return true;
            }
        }

        return false;
    }

    /**
     * @throws InvalidConfigException
     * @throws InvalidArgumentException
     * @throws \Yiisoft\Db\Exception\Exception
     * @throws Throwable
     * @throws ReflectionException
     */
    private function verifyOtpCode(string $code, string $userId): bool
    {
        $totp = $this->getTotp($userId);

        if ($totp->verify($code)) {
            $this
                ->database
                ->createCommand()
                ->update(
                    $this->totpTable,
                    [
                        'last_code' => $code,
                    ],
                    [
                        'user_id' => $userId,
                    ]
                )
                ->execute()
            ;

            return true;
        }

        return false;
    }
}