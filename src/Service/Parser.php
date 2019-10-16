<?php

namespace AVKluchko\X509Bundle\Service;

use AVKluchko\GovernmentBundle\Validator\PSRNValidator;

class Parser
{
    const SUBJECT_COMPANY = 'company';
    const SUBJECT_OFFICIAL = 'official';
    const SUBJECT_PERSON = 'person';

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
            'subject' => $this->parseSubject($data['subject']),
            'issuer' => $this->parseIssuer($data['issuer']),
            'signTool' => isset($data['extensions']) ?
                $this->parseSignTool($data['extensions']) : null,
        ];
    }

    private function parseSubject(array $data): array
    {
        $OGRN = $this->parsePSRN($data);

        $type = self::SUBJECT_COMPANY;
        if (isset($data['givenName'])) {
            $type = $OGRN ? self::SUBJECT_OFFICIAL : self::SUBJECT_PERSON;
        }

        $personMiddleName = null;
        $personName = null;

        if (isset($data['givenName'])) {
            [$personName, $personMiddleName] = explode(' ', $data['givenName']);
        }

        return [
            'type' => $type,
            'shortName' => $data['commonName'],
            'company' => $data['organizationName'],
            'title' => $data['title'] ?? null, // optional
            'country' => $data['countryName'],
            'state' => $data['stateOrProvinceName'],
            'locality' => $data['localityName'],
            'address' => $data['streetAddress'] ?? null, // optional
            'email' => isset($data['emailAddress']) ?
                $this->parseEmail($data['emailAddress']) : null,
            'OGRN' => $OGRN,
            'INN' => $data['INN'] ?? null, // optional
            'surname' => $data['surname'] ?? null, // optional
            'name' => $personName,
            'middleName' => $personMiddleName,
            'SNILS' => $data['SNILS'] ?? null, // optional
        ];
    }

    private function parseEmail($email): string
    {
        if (is_array($email)) {
            return $email[count($email) - 1];
        }

        return $email;
    }

    private function parseIssuer(array $data): array
    {
        return [
            'name' => $data['organizationName'],
            'shortName' => $data['commonName'],
            'unitName' => $data['organizationalUnitName'] ?? null, // optional
            'country' => $data['countryName'],
            'state' => $data['stateOrProvinceName'] ?? null, // optional
            'locality' => $data['localityName'],
            'address' => $data['streetAddress'] ?? null, // optional
            'email' => $data['emailAddress'] ?? null,
            'OGRN' => $data['OGRN'] ?? null, // optional
            'INN' => $data['INN'] ?? null, // optional
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

    private function parsePSRN(array $data): ?string
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