<?php

namespace AVKluchko\X509Bundle\Service;

class CertificateReader
{
    public function readData(string $filename, bool $shortNames = false): array
    {
        $content = file_get_contents($filename);
        $data = openssl_x509_parse($content, $shortNames);

        if ($data === false) {
            $content = $this->convertToPemContent($content);
            $data = openssl_x509_parse($content, $shortNames);
        }

        if ($data === false) {
            throw new \Exception('Could not parse certificate, unknown format');
        }

        $data['thumbprint'] = openssl_x509_fingerprint($content);

        return $data;
    }

    private function convertToPemContent(string $content): string
    {
        return
            '-----BEGIN CERTIFICATE-----' . PHP_EOL
            . chunk_split(base64_encode($content), 64, PHP_EOL)
            . '-----END CERTIFICATE-----' . PHP_EOL;
    }
}