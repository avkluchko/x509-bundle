<?php

namespace AVKluchko\X509Bundle\Service;

class CertificateReader
{
    private $data = null;

    public function __construct(string $filename, bool $shortNames = false)
    {
        $content = file_get_contents($filename);

        $this->data = $this->readData($content, $shortNames);
    }

    public function getData(): ?array
    {
        return $this->data;
    }

    private function readData(string $content, bool $shortNames = false): array
    {
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