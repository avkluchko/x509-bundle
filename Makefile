SHELL=/bin/bash

# Executables (local)
DOCKER_COMP = docker-compose -f docker-compose.yml

# Docker containers
PHP_CONT = $(DOCKER_COMP) exec php-fpm-gost

# Executables
COMPOSER = $(PHP_CONT) composer
PHPUNIT  = $(PHP_CONT) php ./vendor/bin/simple-phpunit

## —— The Dwelling Makefile —————————————————————————————————————————————————
help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'


## —— Docker 🐳 ——————————————————————————————————————————————————————————————
build: ## Builds the Docker images
	@$(DOCKER_COMP) build --pull

rebuild: ## Builds the Docker images without cache
	@$(DOCKER_COMP) build --pull --no-cache

up: ## Start the docker hub in detached mode (no logs)
	@$(DOCKER_COMP) up --detach

start: build up ## Build and start the containers

down: ## Stop the docker hub
	@$(DOCKER_COMP) down --remove-orphans

down-clear: ## Stop the docker hub with removing volumes
	@$(DOCKER_COMP) down -v --remove-orphans

restart: down up ## Restart the docker hub

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
init: down-clear build up vendor


## —— Tests —————————————————————————————————————————————————————————————————
test: phpunit.xml.dist check ## Run tests with optional suite and filter
	@$(eval testsuite ?= 'all')
	@$(eval filter ?= '.')
	@$(PHPUNIT) --testsuite=$(testsuite) --filter=$(filter) --stop-on-failure

test-all: phpunit.xml.dist ## Run all tests
	@$(PHPUNIT) --stop-on-failure
