ARG PHP_VERSION=8.1

FROM php:${PHP_VERSION}-fpm-alpine AS php

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

ENV COMPOSER_ALLOW_SUPERUSER=1

WORKDIR /app
