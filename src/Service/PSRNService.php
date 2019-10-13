<?php

namespace AVKluchko\X509Bundle\Service;

class PSRNService
{
    public function isPSRN(string $value): bool
    {
        $value = trim($value);

        if (strlen($value) !== 13) {
            return false;
        }

        if (!preg_match('/\d{13}/', $value)) {
            return false;
        }

        $number = (int)substr($value, 0, 12);
        $controlNumber = (int)substr($value, 12);
        $result = (string)$number % 11;
        $lastNumber = (int)substr($result, strlen($result) - 1);

        return $lastNumber === $controlNumber;
    }
}