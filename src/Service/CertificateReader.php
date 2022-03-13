<?php

namespace AVKluchko\X509Bundle\Service;

class CertificateReader
{
    private const BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----' . PHP_EOL;
    private const END_CERTIFICATE = '-----END CERTIFICATE-----' . PHP_EOL;

    /**
     * @return array<string, mixed>
     */
    public function loadData(string $filename, bool $shortNames = false): array
    {
        $fileContent = file_get_contents($filename);

        $content = $fileContent;
        $data = openssl_x509_parse($content, $shortNames);

        if ($data === false) {
            $content = self::BEGIN_CERTIFICATE . $fileContent . PHP_EOL . self::END_CERTIFICATE;
            $data = openssl_x509_parse($content, $shortNames);
        }

        if ($data === false) {
            $content = $this->convertToPemContent($fileContent);
            $data = openssl_x509_parse($content, $shortNames);
        }

        if ($data === false) {
            throw new \Exception(sprintf('Could not parse certificate %s, unknown format', $filename));
        }

        $data['fingerprint'] = openssl_x509_fingerprint($content);

        return $data;
    }

    private function convertToPemContent(string $content): string
    {
        return
            self::BEGIN_CERTIFICATE .
            chunk_split(base64_encode($content), 64, PHP_EOL) .
            self::END_CERTIFICATE;
    }
}
