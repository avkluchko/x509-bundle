<?php

namespace AVKluchko\X509Bundle\Service;

use AVKluchko\GovernmentBundle\Validator\PSRNValidator;

class Parser
{
    private $reader;

    public function __construct(CertificateReader $reader)
    {
        $this->reader = $reader;
    }

    public function parse(string $filename): array
    {
        $data = $this->reader->loadData($filename);
        
        return [
            'data' => $data,
            'fingerprint' => $data['fingerprint'],
            'issuer' => $this->parseIssuer($data['issuer']),
            'signTool' => isset($data['extensions']) ?
                $this->parseSignTool($data['extensions']) : null,
        ];
    }

    private function parseSignTool(array $data): ?string
    {
        $signTool = $data['subjectSignTool'] ??
            $data['1.2.643.100.111'] ?? null;

        if (!$signTool) {
            return null;
        }

        return trim($signTool, " +\x00..\x1F");
    }

    private function parseIssuer(array $data): array
    {
        return [
            'commonName' => $data['commonName'],
            'name' => $data['organizationName'],
            'unitName' => $data['organizationalUnitName'] ?? null, // optional
            'country' => $data['countryName'],
            'state' => $data['stateOrProvinceName'] ?? null, // optional
            'locality' => $data['localityName'],
            'address' => $data['streetAddress'] ?? null, // optional
            'email' => $data['emailAddress'],
            'PSRN' => $data['OGRN'] ?? null, // optional
            'TIN' => $data['INN'] ?? null, // optional
        ];
    }

//    private function parsePSRN(array $data): ?string
//    {
//        // if use OpenSSL 1.1
//        if (isset($data['OGRN'])) {
//            return $data['OGRN'];
//        }
//
//        // if use older OpenSSL 1.0
//        if (isset($data['undefined'])) {
//            $validator = new PSRNValidator();
//
//            foreach ($data['undefined'] as $value) {
//                if ($validator->isValid($value)) {
//                    return $value;
//                }
//            }
//        }
//
//        return null;
//    }
}