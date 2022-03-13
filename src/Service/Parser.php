<?php

namespace AVKluchko\X509Bundle\Service;

use AVKluchko\GovernmentBundle\Validator\INNValidator;
use AVKluchko\GovernmentBundle\Validator\OGRNValidator;
use AVKluchko\GovernmentBundle\Validator\SNILSValidator;
use AVKluchko\X509Bundle\Utils\DateUtils;

class Parser
{
    public const SUBJECT_COMPANY = 'company';
    public const SUBJECT_OFFICIAL = 'official';
    public const SUBJECT_PERSON = 'person';

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
            'validPeriod' => [
                'from' => DateUtils::timeToDatetime($data['validFrom_time_t']),
                'to' => DateUtils::timeToDatetime($data['validTo_time_t'])
            ],
            'subject' => $this->parseSubject($data['subject']),
            'issuer' => $this->parseIssuer($data['issuer']),
            'privateKeyUsagePeriod' => $this->parsePrivateKeyUsagePeriod($data['extensions']),
            'signTool' => $this->parseSignTool($data['extensions']),
            'extendedKeyUsage' => $this->parseExtendedKeyUsage($data['extensions']),
        ];
    }

    public function parsePrivateKeyUsagePeriod(array $extensions): ?array
    {
        if (!isset($extensions['privateKeyUsagePeriod'])) {
            return null;
        }

        // example: Not Before: Jun 10 06:27:34 2019 GMT, Not After: Jun 10 06:05:54 2020 GMT
        preg_match(
            '/^Not Before: (.*), Not After: (.*)$/',
            trim($extensions['privateKeyUsagePeriod']),
            $period
        );

        $from = new \DateTime($period[1]);
        $to = new \DateTime($period[2]);
        $tz = new \DateTimeZone(date_default_timezone_get());

        return [
            'from' => $from->setTimezone($tz),
            'to' => $to->setTimezone($tz)
        ];
    }

    private function parseSubject(array $data): array
    {
        $OGRN = $this->parseOGRN($data);

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
            'title' => $data['title'] ?? null,
            'country' => $data['countryName'],
            'state' => $data['stateOrProvinceName'],
            'locality' => $data['localityName'],
            'address' => $data['streetAddress'] ?? null,
            'email' => isset($data['emailAddress']) ?
                $this->parseEmail($data['emailAddress']) : null,
            'OGRN' => $OGRN,
            'INN' => $this->parseINN($data),
            'SNILS' => $this->parseSNILS($data),
            'surname' => $data['surname'] ?? null,
            'name' => $personName,
            'middleName' => $personMiddleName,
        ];
    }

    public function parseEmail($email): string
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
            'unitName' => $data['organizationalUnitName'] ?? null,
            'country' => $data['countryName'],
            'state' => $data['stateOrProvinceName'] ?? null,
            'locality' => $data['localityName'],
            'address' => $data['streetAddress'] ?? null,
            'email' => $data['emailAddress'] ?? null,
            'OGRN' => $this->parseOGRN($data),
            'INN' => $data['INN'] ?? null,
        ];
    }

    public function parseSignTool(array $data): ?string
    {
        $signTool = $data['subjectSignTool'] ??
            $data['1.2.643.100.111'] ?? null;

        if (!$signTool) {
            return null;
        }

        return trim($signTool, " +\x00..\x1F");
    }

    public function parseINN(array $data): ?string
    {
        // if use OpenSSL 1.1
        if (isset($data['INN'])) {
            return $data['INN'];
        }

        // if use older OpenSSL 1.0
        if (isset($data['undefined'])) {
            $validator = new INNValidator();

            foreach ($data['undefined'] as $value) {
                if ($validator->isValid($value)) {
                    return $value;
                }
            }
        }

        return null;
    }

    public function parseSNILS(array $data): ?string
    {
        $SNILS = $this->getSNILS($data);

        if (!$SNILS) {
            return null;
        }

        return str_replace(['-', ' '], '', $SNILS);
    }

    public function getSNILS(array $data): ?string
    {
        // if use OpenSSL 1.1
        if (isset($data['SNILS'])) {
            return $data['SNILS'];
        }

        // if use older OpenSSL 1.0
        if (isset($data['undefined'])) {
            $validator = new SNILSValidator();

            foreach ($data['undefined'] as $value) {
                if ($validator->isValid($value)) {
                    return $value;
                }
            }
        }

        return null;
    }

    public function parseOGRN(array $data): ?string
    {
        // if use OpenSSL 1.1
        if (isset($data['OGRN'])) {
            return $data['OGRN'];
        }

        // if use older OpenSSL 1.0
        if (isset($data['undefined'])) {
            $validator = new OGRNValidator();

            foreach ($data['undefined'] as $value) {
                if ($validator->isValid($value)) {
                    return $value;
                }
            }
        }

        return null;
    }

    public function parseExtendedKeyUsage(array $data): ?array
    {
        if (!isset($data['extendedKeyUsage'])) {
            return null;
        }

        return explode(', ', $data['extendedKeyUsage']);
    }
}
