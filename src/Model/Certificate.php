<?php

namespace AVKluchko\X509Bundle\Model;

class Certificate
{
    private $certificateData;

    private $fingerprint;

    public function __construct(array $certificateData)
    {
        $this->certificateData = $certificateData;
        $this->fingerprint = $certificateData['fingerprint'];
    }

    public function getCertificateData(): array
    {
        return $this->certificateData;
    }

    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }
}