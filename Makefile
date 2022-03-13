SHELL=/bin/bash

# Executables (local)
DOCKER_COMP = docker-compose -f docker-compose.yml

# Docker containers
PHP_CONT = $(DOCKER_COMP) run --rm php

# Executables
COMPOSER = $(PHP_CONT) composer
PHPUNIT  = $(PHP_CONT) php ./vendor/bin/simple-phpunit
PHPCS    = $(PHP_CONT) php ./vendor/bin/phpcs
PHPSTAN  = $(PHP_CONT) php ./vendor/bin/phpstan

## —— The Dwelling Makefile —————————————————————————————————————————————————
help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'


## —— Docker 🐳 ——————————————————————————————————————————————————————————————
build: ## Builds the Docker images
	@$(DOCKER_COMP) build --pull

rebuild: ## Builds the Docker images without cache
	@$(DOCKER_COMP) build --pull --no-cache

logs: ## Show live logs
	@$(DOCKER_COMP) logs --tail=0 --follow

sh: ## Connect to the PHP FPM container
	@$(PHP_CONT) sh


## —— Composer ——————————————————————————————————————————————————————————————
composer: ## Run composer, pass the parameter "c=" to run a given command, example: make composer c='req symfony/orm-pack'
	@$(eval c ?=)
	@$(COMPOSER) $(c)

vendor: ## Install vendors according to the current composer.lock file
vendor: c=install --prefer-dist --no-interaction
vendor: composer


## —— Application ———————————————————————————————————————————————————————————
init: ## Full initialization
init: build vendor


## —— Tests —————————————————————————————————————————————————————————————————
test: phpunit.xml.dist check ## Run tests with optional suite and filter
	@$(eval testsuite ?= 'all')
	@$(eval filter ?= '.')
	@$(PHPUNIT) --testsuite=$(testsuite) --filter=$(filter) --stop-on-failure

test-all: phpunit.xml.dist ## Run all tests
	@$(PHPUNIT) --stop-on-failure

lint: phpcs phpstan

phpcs: phpcs.xml.dist ## Run CodeSniffer
	@$(PHPCS)

phpstan: phpstan.neon.dist ## Run PHPStan
	@$(PHPSTAN)
