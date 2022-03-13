<?php

namespace AVKluchko\X509Bundle;

use AVKluchko\X509Bundle\DependencyInjection\X509Extension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class X509Bundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        if (null === $this->extension) {
            $this->extension = new X509Extension();
        }

        return $this->extension;
    }
}
