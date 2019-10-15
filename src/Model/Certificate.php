<?php

namespace AVKluchko\X509Bundle\Model;

use AVKluchko\GovernmentBundle\Validator\PSRNValidator;

class Certificate
{
    private $certificateData;

    private $fingerprint;

    private $signTool;

    private $issuer;

    public function __construct(array $data)
    {
        $this->certificateData = $data;
        $this->fingerprint = $data['fingerprint'];

        if (isset($data['extensions'])) {
            $this->signTool = $this->createSignTool($data['extensions']);
        }

        $this->issuer = $this->createIssuer($data['issuer']);
    }

    public function getCertificateData(): array
    {
        return $this->certificateData;
    }

    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }

    public function getSignTool(): ?string
    {
        return $this->signTool;
    }

    public function createSignTool(array $data): ?string
    {
        $signTool = $data['subjectSignTool'] ??
            $data['1.2.643.100.111'] ?? null;

        if (!$signTool) {
            return null;
        }

        return trim($signTool, " +\x00..\x1F");
    }

    public function getIssuer(): array
    {
        return $this->issuer;
    }

    public function createIssuer(array $data): array
    {
        return [
            'shortName' => $data['commonName'],
            'name' => $data['organizationName'],
            'PSRN' => $this->createPSRN($data),
        ];
    }

    public function createPSRN(array $data): ?string
    {

        // if use OpenSSL 1.1
        if (isset($data['OGRN'])) {
            return $data['OGRN'];
        }

        // if use older OpenSSL 1.0
        if (isset($data['undefined'])) {
            $validator = new PSRNValidator();

            foreach ($data['undefined'] as $value) {
                if ($validator->isValid($value)) {
                    return $value;
                }
            }
        }

        return null;
    }
}