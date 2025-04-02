<?php

declare(strict_types=1);

use BeastBytes\Yii\Totp\Totp;

return [
    'beastbytes/yii-totp' => [
        'backupCodes' => [
            'count' => 10, // number of backup codes to generate
            'length' => 16, // length of each backup code
        ],
        'crypt' => [
            'authorizationKeyInfo' => 'TotpAuthorizationKey',
            'cipher' => 'AES-128-CBC', // Encryption cipher: AES-128-CBC, AES-192-CBC, AES-256-CBC
            'iterations' => 100000,
            'kdfAlgorithm' => 'sha256', // sha256, sha384, sha512
            'secret' => 'rstswSLBfzMKLyELbvKSkfT3qkHjAVoSQtVNSkWimeiGbOABqJXA3NqFYtXyewpS', // should be changed
        ],
        'database' => [
            'otpBackupCodesTable' => 'otp_backup_codes',
            'totpTable' => 'totp',
        ],
        'totp' => [ // The default values work for authenticator apps like Google Authenticator
            'digest' => Totp::DIGEST, // HMAC digest algorithm; sha1, sha256, sha512
            'digits' => Totp::DIGITS, // number of digits in the OTP code
            'leeway' => Totp::LEEWAY, // leeway in seconds that an OTP code is valid before or after the period; allows time drift; must be less than $period
            'period' => Totp::PERIOD, // OTP time period - how often a new code is generated - in seconds
        ]
    ],
];