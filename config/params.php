<?php

declare(strict_types=1);

use BeastBytes\Yii\Totp\CryptCipher;
use BeastBytes\Yii\Totp\CryptKdfAlgorithm;
use BeastBytes\Yii\Totp\Totp;
use BeastBytes\Yii\Totp\TotpDigest;
use BeastBytes\Yii\Totp\TotpService;
use OTPHP\OTPInterface;
use OTPHP\TOTPInterface;

return [
    'beastbytes/yii-totp' => [
        'backupCode' => [
            'count' => TotpService::BACKUP_CODE_COUNT,
            'length' => TotpService::BACKUP_CODE_LENGTH,
        ],
        'crypt' => [
            'authorizationKeyInfo' => 'TotpAuthorizationKey',
            'cipher' => CryptCipher::AES_128_CBC, // Encryption cipher: AES-128-CBC, AES-192-CBC, AES-256-CBC
            'iterations' => TotpService::CRYPT_ITERATIONS,
            'kdfAlgorithm' => CryptKdfAlgorithm::sha256->name, // sha256, sha384, sha512
            'key' => TotpService::CRYPT_KEY,
        ],
        'database' => [
            'otpBackupCodeTable' => 'otp_backup_code',
            'totpTable' => 'totp',
        ],
        'totp' => [ // The default values work for authenticator apps like Google Authenticator
            'digest' => TotpDigest::sha1->name,
            'digits' => OTPInterface::DEFAULT_DIGITS,
            'leeway' => TOTP::DEFAULT_LEEWAY,
            'period' => TOTPInterface::DEFAULT_PERIOD,
            'secretLength' => TOTP::DEFAULT_SECRET_LENGTH,
        ]
    ],
];