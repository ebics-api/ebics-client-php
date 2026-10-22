# Project Guide — ebics-client-php

## Overview

PHP library to communicate with banks through the **EBICS** protocol (Electronic Banking Internet Communication Standard).  
Supports EBICS versions 2.4, 2.5, 3.0 and signature/encryption variants E002, X002, A005, A006.

## Technology Stack

| Item | Version |
|------|---------|
| **PHP** | 8.5+ (`^8.5`) |
| **PHPUnit** | ~10.5 |
| **PHPStan** | ~2.1 |
| **PHPCS** | ~3.13 (PSR-12) |
| **Composer** | latest |

### Required PHP Extensions

`bcmath`, `curl`, `dom`, `json`, `openssl`, `zip`, `zlib`, `libxml`

## Docker Environment

The project uses Docker for a consistent development environment.

```
docker/
├── docker-compose.yml
└── php-cli/
    ├── Dockerfile          (php:8.5.12-cli + xdebug + extensions)
    └── php.ini
```

### Docker Compose

| Target | Image | Container Name |
|--------|-------|----------------|
| `php-cli-ebics-client-php` | `php-cli-ebics-client-php:8.5.12-cli` | `php-cli-ebics-client-php` |

Network mode: **host** (for easy access to local services).  
Xdebug is pre-installed and enabled (port 9003).

### Makefile Targets

| Command | Alias | Description |
|---------|-------|-------------|
| `make docker-up` | `u`, `start` | Start Docker containers |
| `make docker-down` | `d`, `stop` | Stop Docker containers |
| `make docker-build` | `build` | Rebuild Docker images |
| `make docker-install` | `install` | Run `composer install` in container |
| `make docker-php` | `php` | Open a bash shell in the PHP container |
| `make check` | — | Run PHPCBF, PHPCS, PHPStan, PHPUnit |
| `make credentials-pack` | — | Zip test credentials |
| `make credentials-unpack` | — | Unzip test credentials |

### Composer Scripts (run inside Docker)

| Command | Description |
|---------|-------------|
| `composer code-test` | Run PHPUnit tests |
| `composer code-style` | Run PHPCS |
| `composer code-analyse` | Run PHPStan |

## Directory Structure

```
├── src/                    # PSR-4: EbicsApi\Ebics\
│   ├── Contracts/          # Interfaces
│   ├── Exceptions/         # Custom exception classes
│   ├── Factories/          # Factory classes (Crypt, Signature, etc.)
│   ├── Models/             # Data models (Key, KeyPair, Keyring, Buffer, etc.)
│   ├── Services/           # Business logic services
│   └── EbicsClient.php     # Main client entry point
├── tests/                  # PSR-4: EbicsApi\Ebics\Tests\
│   ├── _data/              # Test data & keyring files
│   ├── _fixtures/          # Test fixtures (XML files, keys)
│   ├── _workspace/         # Generated test artifacts
│   └── AbstractEbicsTestCase.php  # Base test class with helpers
├── doc/schema/             # EBICS XSD schemas
└── docker/                 # Docker configuration
```

## Coding Standards

- **PSR-12** coding style (enforced by PHPCS).
- **PHPStan** level enforced via `phpstan.neon`.
- Source code lives in `src/`; tests live in `tests/`.
- PHPCS targets `src/` only (tests excluded in `phpcs.xml`).
- Tests may use snake_case method names where needed (PHPCS exclusion).

## Running Commands

**CRITICAL: Agents MUST use Docker for all project-related commands (tests, linting, analysis, composer). The local environment does not have PHP installed.**

All commands execute **inside Docker**:

```bash
# Start environment
make docker-up

# Run full quality check
make check

# Or individually:
docker compose -p ebics-client-php exec php-cli-ebics-client-php ./vendor/bin/phpunit
docker compose -p ebics-client-php exec php-cli-ebics-client-php ./vendor/bin/phpcs
docker compose -p ebics-client-php exec php-cli-ebics-client-php ./vendor/bin/phpstan

# Open shell
make docker-php
```

## Testing Conventions

- Base class: `AbstractEbicsTestCase` (provides client setup, keyring, credentials).
- Test groups (PHPUnit `@group`): e.g. `@group crypt-services`.
- Credentials stored in `tests/_data/credentials/credentials_<id>.json`.
- Keyrings stored in `tests/_data/workspace/keyring_<id>.json`.
- Fixtures (static XML/JSON) in `tests/_fixtures/`.

### Client Setup Helpers

```php
// In any test extending AbstractEbicsTestCase:
$client = $this->setupClientV24($credentialsId);  // EBICS 2.4
$client = $this->setupClientV25($credentialsId);  // EBICS 2.5
$client = $this->setupClientV30($credentialsId);  // EBICS 3.0
```

### Fake / Debug HTTP Clients

Pass `$fake = true` or `$debug = true` to `setupClient*()` to use `FakerHttpClient` (returns fixture data) or `DebuggerHttpClient` (logs requests).

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Keyring** | Holds user & bank signatures (A = authentication, X = signing, E = encryption), passwords, and optional X.509 certificates. |
| **Signature A** | Authentication signature (versions A005 / A006). |
| **Signature X** | Transaction signing (version X002). |
| **Signature E** | Encryption (version E002). |
| **CryptService** | All crypto ops: hashing, AES-128-CBC encrypt/decrypt, RSA sign/encrypt, key generation, nonces, order IDs. |
| **KeyPair** | Public key + private key + password bundle. |

## Notable Implementation Details

- Classes marked `@internal` may change without notice.

## Zero-Dependency Policy

**The library must have zero external production dependencies.** This is a core design principle. Only PHP extensions are allowed in `require`.

- `composer.json` `require` section may only contain `php ^8.5` and `ext-*` entries.
- When a PSR interface is needed (e.g. PSR-3 Logger), copy it into `src/Contracts/`.
- PSR-18 HTTP client: the library uses its own `HttpClientInterface` in `src/Contracts/` (not PSR-18).
- PSR-3 Logger: `LoggerInterface` is defined in `src/Contracts/LoggerInterface.php`.

## Logging

The `EbicsClient` uses `LoggerInterface` (PSR-3 compatible) for logging transaction steps, HTTP requests, errors, and other important events.
