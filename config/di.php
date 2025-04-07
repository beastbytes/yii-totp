<?php

declare(strict_types=1);

use BeastBytes\Yii\Totp\Totp;
use BeastBytes\Yii\Totp\TotpService;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\Clock;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Definitions\Reference;
use Yiisoft\Security\Crypt;

/** @var array $params */

return [
    ClockInterface::class => Clock::class,
    Crypt::class => [
        'class' => Crypt::class,
        '__construct()' => [
            'cipher' => $params['beastbytes/yii-totp']['crypt']['cipher'],
        ],        
        'withDerivationIterations()' => [
            $params['beastbytes/yii-totp']['crypt']['iterations'],
        ],
        'withKdfAlgorithm()' => [
            $params['beastbytes/yii-totp']['crypt']['kdfAlgorithm'],
        ],    
        'withAuthorizationKeyInfo' => [
            $params['beastbytes/yii-totp']['crypt']['authorizationKeyInfo'],
        ],    
    ],
    Totp::class => [
        'class' => Totp::class,
        '__construct()' => [
            'clock' => ClockInterface::class,
            'digest' => $params['beastbytes/yii-totp']['totp']['digest'],
            'digits' => $params['beastbytes/yii-totp']['totp']['digits'],
            'leeway' => $params['beastbytes/yii-totp']['totp']['leeway'],
            'period' => $params['beastbytes/yii-totp']['totp']['period'],
            'secretLength' => $params['beastbytes/yii-totp']['totp']['secretLength'],
        ],
    ],
    TotpService::class => [
        'class' => TotpService::class,
        '__construct()' => [
            'backupCodeCount' => $params['beastbytes/yii-totp']['backupCode']['count'],
            'backupCodeLength' => $params['beastbytes/yii-totp']['backupCode']['length'],
            'crypt' => Reference::to(Crypt::class),
            'database' => ConnectionInterface::class,
            'encryptionKey' => $params['beastbytes/yii-totp']['crypt']['key'],
            'otpBackupCodesTable' => $params['beastbytes/yii-totp']['database']['otpBackupCodeTable'],
            'totp' => Reference::to(Totp::class),
            'totpTable' => $params['beastbytes/yii-totp']['database']['totpTable'],
        ],
    ]
];