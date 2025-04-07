<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp;

use Exception;
use OTPHP\TOTP as OtphpTotp;
use OTPHP\TOTPInterface;
use Psr\Clock\ClockInterface;
use Yiisoft\Security\Random;

final class Totp
{
    /**
     * Number of seconds that an OTP code is valid before or after the period
     * to allow for clock drift between client and server
     */
    const DEFAULT_LEEWAY = 2;
    /**
     * Length of OTP secret
     */
    public const DEFAULT_SECRET_LENGTH = 48;
    /** @var string Only contain digits and uppercase letters */
    public const SECRET_REGEX = '/^[\dA-Z]+$/';

    /** @var ?string $secret Secret value to generate OTP code; null if OTP not enabled */
    private ?string $secret = null;
    /** @var string $lastCode Last validated OTP code */
    private string $lastCode = '';

    public function __construct(
        private ClockInterface $clock,
        private string $digest,
        private int $digits,
        private int $leeway,
        private int $period,
        int $secretLength,
    )
    {
        if ($this->secret === null) {
            $this->generateSecret($secretLength);
        }
    }

    /**
     * @param string $label Label for the TOTP. Usually the organisation or application name.
     * @param ?string $issuer Issuer of the TOTP.
     * @psalm-param <string, string> $parameters Additional parameters as key=>value pairs
     * @return string The provisioning URI for the TOTP. Can be used to generate a QR code for the TOTP.
     * @throws Exception
     */
    public function getProvisioningUri(string $label, ?string $issuer = null, array $parameters = []): string
    {
        if ($this->secret === null) {
            throw new Exception('OTP not enabled');
        }

        $totp = $this->createTotp();

        $totp->setLabel($label);
        if (is_string($issuer)) {
            $totp->setIssuer($issuer);
        }
        foreach ($parameters as $parameter => $value) {
            $totp->setParameter($parameter, $value);
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

    public function getLastCode(): string
    {
        return $this->lastCode;
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
        if ($code === $this->lastCode) {
            return false;
        }

        $totp = $this->createTotp();

        if ($totp->verify(otp: $code, leeway: $this->leeway)) {
            $this->lastCode = $code;
            return true;
        }

        return false;
    }

    private function createTotp(): TOTPInterface
    {
        return OtphpTotp::create(
            secret: $this->secret,
            period: $this->period,
            digest: $this->digest,
            digits: $this->digits,
            clock: $this->clock,
        );
    }

    private function generateSecret(int $length): void
    {
        do {
            $this->secret = strtoupper(Random::string($length));
        } while (preg_match(self::SECRET_REGEX, $this->secret) === 0);
    }
}