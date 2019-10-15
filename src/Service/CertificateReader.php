<?php

namespace AVKluchko\X509Bundle\Service;

use AVKluchko\X509Bundle\Model\Certificate;

class CertificateReader
{
    public function loadData(string $filename, bool $shortNames = false): array
    {
        $content = $this->loadFileContent($filename);
        $data = openssl_x509_parse($content, $shortNames);

        if ($data === false) {
            $content = $this->convertToPemContent($content);
            $data = openssl_x509_parse($content, $shortNames);
        }

        if ($data === false) {
            throw new \Exception(printf('Could not parse certificate %s, unknown format', $filename));
        }

        $data['fingerprint'] = openssl_x509_fingerprint($content);

        return $data;
    }

    public function loadCertificate(string $filename): Certificate
    {
        return new Certificate($this->loadData($filename));
    }

    public function loadFileContent(string $filename): string
    {
        return file_get_contents($filename);
    }


    public function convertToPemContent(string $content): string
    {
        return
            '-----BEGIN CERTIFICATE-----' . PHP_EOL
            . chunk_split(base64_encode($content), 64, PHP_EOL)
            . '-----END CERTIFICATE-----' . PHP_EOL;
    }

}