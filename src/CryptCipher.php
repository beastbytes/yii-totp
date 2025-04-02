<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp;

enum CryptCipher: string
{
    const AES_128_CBC = 'AES-128-CBC';
    const AES_192_CBC = 'AES-192-CBC';
    const AES_256_CBC = 'AES-256-CBC';
}