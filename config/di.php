<?php

declare(strict_types=1);

use BeastBytes\Yii\Totp\TotpService;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\Clock;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Security\PasswordHasher;

/** @var array $params */

return [
    ClockInterface::class => Clock::class,
    TotpService::class => [
        'class' => TotpService::class,
        '__construct()' => [
            'clock' => ClockInterface::class,
            'database' => ConnectionInterface::class,
            'otpBackupCodesTable' => $params['beastbytes/yii-totp']['database']['otpBackupCodesTable'],
            'totpTable' => $params['beastbytes/yii-totp']['database']['totpTable'],
            'totpDigest' => $params['beastbytes/yii-totp']['totp']['digest'],
            'totpDigits' => $params['beastbytes/yii-totp']['totp']['digits'],
            'totpLeeway' => $params['beastbytes/yii-totp']['totp']['leeway'],
            'totpPeriod' => $params['beastbytes/yii-totp']['totp']['period'],
            'backupCodeCount' => $params['beastbytes/yii-totp']['backupCodes']['count'],
            'backupCodeLength' => $params['beastbytes/yii-totp']['backupCodes']['length'],
            'passwordHasher' => PasswordHasher::class,
            'cipher' => $params['beastbytes/yii-totp']['crypt']['cipher'],
            'iterations' => $params['beastbytes/yii-totp']['crypt']['iterations'],
            'kdfAlgorithm' => $params['beastbytes/yii-totp']['crypt']['kdfAlgorithm'],
            'authorizationKeyInfo' => $params['beastbytes/yii-totp']['crypt']['authorizationKeyInfo'],
            'cryptSecret' => $params['beastbytes/yii-totp']['crypt']['secret'],
        ],
    ]
];