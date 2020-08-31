up: docker-up
down: docker-down
restart: docker-down docker-up
init: docker-down-clear docker-pull docker-build docker-up composer-install
tests: simple-phpunit

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down --remove-orphans

docker-down-clear:
	docker-compose down -v --remove-orphans

docker-pull:
	docker-compose pull

docker-build:
	docker-compose build

composer-install:
	docker-compose run --rm php-fpm-gost composer install

simple-phpunit:
	docker-compose run --rm php-fpm-gost vendor/bin/simple-phpunit
