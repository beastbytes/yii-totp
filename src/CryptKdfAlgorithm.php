<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp;

enum CryptKdfAlgorithm
{
    case sha256;
    case sha384;
    case sha512;
}
