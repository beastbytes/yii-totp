<?php

declare(strict_types=1);

use BeastBytes\Yii\Totp\CryptCipher;
use BeastBytes\Yii\Totp\CryptKdfAlgorithm;
use BeastBytes\Yii\Totp\TotpDigest;
use OTPHP\OTPInterface;
use OTPHP\TOTP;
use OTPHP\TOTPInterface;

/**
 * // Number of backup codes to generate
 */
const BACKUP_CODE_COUNT = 10;
/**
 * Length of each backup code
 */
const BACKUP_CODE_LENGTH = 16;
/**
 * Derivation iterations count
 */
const CRYPT_ITERATIONS = 100000;
/**
 * Encryption/Decryption key. Should be changed
 */
const CRYPT_KEY = 'rstswSLBfzMKLyELbvKSkfT3qkHjAVoSQtVNSkWimeiGbOABqJXA3NqFYtXyewpS';

/**
 * Number of digits in the OTP code
 */
const TOTP_DIGITS = 6;
/**
 * Number of seconds that an OTP code is valid before or after the period
 * to allow for clock drift between client and server
 */
const TOTP_LEEWAY = 2;
/**
 * Number of seconds in the OTP period, i.e. how often the OTP code is generated
 */
const TOTP_PERIOD = 30;

return [
    'beastbytes/yii-totp' => [
        'backupCodes' => [
            'count' => BACKUP_CODE_COUNT,
            'length' => BACKUP_CODE_LENGTH,
        ],
        'crypt' => [
            'authorizationKeyInfo' => 'TotpAuthorizationKey',
            'cipher' => CryptCipher::AES_128_CBC, // Encryption cipher: AES-128-CBC, AES-192-CBC, AES-256-CBC
            'iterations' => CRYPT_ITERATIONS,
            'kdfAlgorithm' => CryptKdfAlgorithm::sha256->name, // sha256, sha384, sha512
            'key' => CRYPT_KEY,
        ],
        'database' => [
            'otpBackupCodesTable' => 'otp_backup_codes',
            'totpTable' => 'totp',
        ],
        'totp' => [ // The default values work for authenticator apps like Google Authenticator
            'digest' => TotpDigest::sha1->name, // HMAC digest algorithm for TOTP
            'digits' => OTPInterface::DEFAULT_DIGITS,
            'leeway' => TOTP_LEEWAY,
            'period' => TOTPInterface::DEFAULT_PERIOD,
        ]
    ],
];