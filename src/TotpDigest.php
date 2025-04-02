<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp;

enum TotpDigest
{
    case sha1;
    case sha256;
    case sha512;
}
