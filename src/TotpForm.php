<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp;

use Loytyi\User\Otp\Otp as OtpModel;
use Yiisoft\FormModel\FormModel;
use Yiisoft\Translator\TranslatorInterface;
use Yiisoft\Validator\PropertyTranslator\ArrayPropertyTranslator;
use Yiisoft\Validator\PropertyTranslatorInterface;
use Yiisoft\Validator\PropertyTranslatorProviderInterface;
use Yiisoft\Validator\Result;
use Yiisoft\Validator\Rule\Callback;
use Yiisoft\Validator\Rule\Required;
use Yiisoft\Validator\RulesProviderInterface;

final class TotpForm extends FormModel implements PropertyTranslatorProviderInterface, RulesProviderInterface
{
    private string $otpCode = '';

    public function __construct(
        private readonly TranslatorInterface $translator,
        private readonly OtpModel $otp
    )
    {
    }

    public function getPropertyLabels(): array
    {
        return [
            'otpCode' => $this->translator->translate('otp.label.otp-code'),
        ];
    }

    public function getRules(): array
    {
        return [
            'otpCode' => [
                new Required(),
                new Callback(
                    callback: function (): Result {
                        $result = new Result();

                        if (!$this->otp->verify(str_replace(' ', '', $this->otpCode))) {
                            $result->addError($this->translator->translate('otp.validator.incorrect-otp-code'));
                        }

                        return $result;
                    },
                ),
            ]
        ];
    }

    public function getPropertyTranslator(): ?PropertyTranslatorInterface
    {
        return new ArrayPropertyTranslator($this->getPropertyLabels());
    }
}