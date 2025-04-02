<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp;

use Exception;
use OTPHP\TOTP as TOTPHP;
use Psr\Clock\ClockInterface;

final class Totp
{
    /** @var ?string $secret Secret value to generate OTP code; null if OTP not enabled */
    private ?string $secret = null;
    /** @var string $lastTotp Last validated OTP code */
    private string $lastTotp = '';

    public function __construct(
        private readonly ClockInterface $clock,
        private readonly string $digest,
        private readonly int $digits,
        private readonly int $leeway,
        private readonly int $period,
    )
    {
        if ($this->secret === null) {
            $this->generateSecret();
        }
    }

    /**
     * @param ?string $label Label for the TOTP. Usually the organisation or application name.
     * @param ?string $issuer Issuer of the TOTP. Usually the application URL. Ignored if $label in null
     * @return string The provisioning URI for the TOTP. Can be used to generate a QR code for the TOTP.
     * @throws Exception
     */
    public function getProvisioningUri(?string $label = null, ?string $issuer = null): string
    {
        if ($this->secret === null) {
            throw new Exception('OTP not enabled');
        }

        $totp = TOTPHP::create(
            secret: $this->secret,
            period: $this->period,
            digest: $this->digest,
            digits: $this->digits,
            clock: $this->clock,
        );

        if (is_string($label)) {
            $totp->setLabel($label);

            if (is_string($issuer)) {
                $totp->setIssuer($issuer);
            }
        }

        return $totp->getProvisioningUri();
    }

    public function getDigest(): string
    {
        return $this->digest;
    }

    public function getDigits(): int
    {
        return $this->digits;
    }

    public function getLastTotp(): string
    {
        return $this->lastTotp;
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }

    public function getPeriod(): int
    {
        return $this->period;
    }

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * @param string $code The OTP code to verify
     * @psalm-param string $code The OTP code to verify
     * @return bool True if the OTP code is valid, false otherwise
     * @throws Exception
     */
    public function verify(string $code): bool
    {
        if ($this->secret === null) {
            throw new Exception('OTP not enabled');
        }

        if ($code === $this->lastTotp) {
            return false;
        }

        $totp = TOTPHP::create(
            secret: $this->secret,
            period: $this->period,
            digest: $this->digest,
            digits: $this->digits,
            clock: $this->clock,
        );

        if ($totp->verify(otp: $code, leeway: $this->leeway)) {
            $this->lastTotp = $code;
            return true;
        }

        return false;
    }

    private function generateSecret(): void
    {
        $totp = TOTPHP::generate($this->clock);
        $this->secret = $totp->getSecret();
    }
}