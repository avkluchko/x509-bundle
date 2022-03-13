<?php

namespace AVKluchko\X509Bundle\Tests;

use AVKluchko\X509Bundle\X509Bundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Bundle\BundleInterface;
use Symfony\Component\HttpKernel\Kernel;

class X509TestingKernel extends Kernel
{
    public function __construct()
    {
        parent::__construct('test', true);
    }

    /**
     * @inheritDoc
     *
     * @return iterable|BundleInterface[]
     */
    public function registerBundles(): iterable
    {
        return [
            new X509Bundle(),
        ];
    }

    /**
     * @inheritDoc
     */
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
    }

    /**
     * @inheritDoc
     */
    public function getCacheDir(): string
    {
        return __DIR__ . '/cache/' . spl_object_hash($this);
    }
}
