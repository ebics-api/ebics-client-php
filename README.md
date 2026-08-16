# EBICS-CLIENT-PHP

[![CI](https://github.com/ebics-api/ebics-client-php/actions/workflows/ci.yml/badge.svg)](https://github.com/ebics-api/ebics-client-php/actions/workflows/ci.yml)
[![Latest Stable Version](https://poser.pugx.org/ebics-api/ebics-client-php/v/stable)](https://packagist.org/packages/ebics-api/ebics-client-php)
[![Total Downloads](https://img.shields.io/packagist/dt/ebics-api/ebics-client-php.svg)](https://packagist.org/packages/ebics-api/ebics-client-php)
[![License](https://poser.pugx.org/ebics-api/ebics-client-php/license)](https://packagist.org/packages/ebics-api/ebics-client-php)

<img src="https://www.ebics.org/typo3conf/ext/siz_ebicsorg_base/Resources/Public/Images/ebics-logo.png" width="300">

PHP library to communicate with a bank through <a href="https://en.wikipedia.org/wiki/Electronic_Banking_Internet_Communication_Standard" target="_blank">EBICS</a> protocol.  
PHP EBICS Client - https://ebics-api.github.io/ebics-client-php/  
Supported EBICS versions: 2.4, 2.5, 3.0; Encryption versions: E002, X002, A005, A006; Switching EBICS T/TS

---

# 💥 (Premium) EBICS API Client

<a href="https://youtu.be/S14Qkt5m0NI" target="_blank"><img src="./doc/ebics_api_client.gif" width="300"></a>

<a href="https://sites.google.com/view/ebics-api-client" target="_blank">EBICS API Client</a> is a standalone microservice that wraps this library into a ready-to-deploy banking integration solution.
Ideal for fintechs, ERPs, payment processors, and enterprises needing a robust EBICS integration without building and maintaining the client layer yourself.

### Premium Features

- **🏦 Multiple Bank connections** — Certificates, activation, keyring in a few clicks. [Bank connections →](https://sites.google.com/view/ebics-api-client/bank-connections?authuser=0)  
- **💸 Bank operations via simple form** — Statements and payments without EBICS protocol plumbing. [Bank operations →](https://sites.google.com/view/ebics-api-client/bank-operations?authuser=0)  
- **📝 Payment builder** — Create multi-order SEPA files in minutes, store and reuse them, send straight to the bank. [Bank operations →](https://sites.google.com/view/ebics-api-client/bank-operations?authuser=0)  
- **⏰ Automation that runs while you sleep** — Scheduled jobs, webhooks, no missed statements. [Scheduler jobs →](https://sites.google.com/view/ebics-api-client/scheduler-jobs?authuser=0)  
- **🚀 Live in minutes** — Docker deployment or Installation scrip, no PHP expertise needed.  
- **🧪 Test without a real bank** — Dummy EBICS server for local development.  
- **🤖 AI agents, connected** — MCP server for Claude, Cursor, and more.  
- **🛡 Priority support** — Direct line to the dev team.  

**👉 [Try the DEMO](https://tinyurl.com/safe-ebics) · [Learn more](https://sites.google.com/view/ebics-api-client) · [Watch the video](https://youtu.be/S14Qkt5m0NI)**

*Already using the open-source library and need more? The Premium microservice is the natural next step — no rewrite, same protocol support, zero configuration debt.*

---

## License

ebics-api/ebics-client-php is licensed under the MIT License, see the LICENSE file for details

## Installation

```bash
$ composer require ebics-api/ebics-client-php
```

## Initialize client

You will need to have this information from your Bank: `HostID`, `HostURL`, `PartnerID`, `UserID`

```php
<?php
use EbicsApi\Ebics\Factories\KeyringFactory;
use EbicsApi\Ebics\Services\FileKeyringManager;
use EbicsApi\Ebics\Models\Bank;
use EbicsApi\Ebics\Models\User;
use EbicsApi\Ebics\EbicsClient;
use EbicsApi\Ebics\Models\X509\BankX509Generator;

// Prepare `workspace` dir in the __PATH_TO_WORKSPACES_DIR__ manually.
// "__EBICS_VERSION__" should have value "VERSION_30" for EBICS 3.0
$keyringPath = __PATH_TO_WORKSPACES_DIR__ . '/workspace/keyring.json';
$keyringManager = new FileKeyringManager();
if (is_file($keyringPath)) {
    $keyring = $keyringManager->loadKeyring($keyringPath, __PASSWORD__, __EBICS_VERSION__);
} else {
    $keyring = $keyringManager->createKeyring(__EBICS_VERSION__);
    $keyring->setPassword(__PASSWORD__);
}
$bank = new Bank(__HOST_ID__, __HOST_URL__);
// Use __IS_CERTIFIED__ true for EBICS 3.0 and/or French banks, otherwise use false.
if(__IS_CERTIFIED__) {
    $certificateGenerator = (new BankX509Generator());
    $certificateGenerator->setCertificateOptionsByBank($bank);
    $keyring->setCertificateGenerator($certificateGenerator);
}
$user = new User(__PARTNER_ID__, __USER_ID__);
$client = new EbicsClient($bank, $user, $keyring);
if (!is_file($keyringPath)) {
    $client->createUserSignatures();
    $keyringManager->saveKeyring($client->getKeyring(), $keyringPath);
}
```

## Global process and interaction with Bank Department

### 1. Create and store your 3 keys and send initialization request.

```php
<?php

use EbicsApi\Ebics\Contracts\EbicsResponseExceptionInterface;

/* @var \EbicsApi\Ebics\EbicsClient $client */

try {
    $client->executeStandardOrder(new \EbicsApi\Ebics\Orders\INI());
    /* @var \EbicsApi\Ebics\Services\FileKeyringManager $keyringManager */
    /* @var \EbicsApi\Ebics\Models\Keyring $keyring */
    $keyringManager->saveKeyring($keyring, $keyringPath);
} catch (EbicsResponseExceptionInterface $exception) {
    echo sprintf(
        "INI request failed. EBICS Error code : %s\nMessage : %s\nMeaning : %s",
        $exception->getResponseCode(),
        $exception->getMessage(),
        $exception->getMeaning()
    );
}

try {
    $client->executeStandardOrder(new \EbicsApi\Ebics\Orders\HIA());
    $keyringManager->saveKeyring($keyring, $keyringPath);
} catch (EbicsResponseExceptionInterface $exception) {
    echo sprintf(
        "HIA request failed. EBICS Error code : %s\nMessage : %s\nMeaning : %s",
        $exception->getResponseCode(),
        $exception->getMessage(),
        $exception->getMeaning()
    );
}
```

### 2. Generate a EBICS letter

```php
/* @var \EbicsApi\Ebics\EbicsClient $client */
$ebicsBankLetter = new \EbicsApi\Ebics\EbicsBankLetter();

$bankLetter = $ebicsBankLetter->prepareBankLetter(
    $client->getBank(),
    $client->getUser(),
    $client->getKeyring()
);

$pdf = $ebicsBankLetter->formatBankLetter($bankLetter, $ebicsBankLetter->createPdfBankLetterFormatter());
```

### 3. Wait for the bank validation and access activation.

### 4. Fetch the bank keys.

```php
try {
    /* @var \EbicsApi\Ebics\EbicsClient $client */
    $client->executeInitializationOrder(new \EbicsApi\Ebics\Orders\HPB());
    /* @var \EbicsApi\Ebics\Services\FileKeyringManager $keyringManager */
    /* @var \EbicsApi\Ebics\Models\Keyring $keyring */
    $keyringManager->saveKeyring($keyring, $keyringPath);
} catch (EbicsResponseExceptionInterface $exception) {
    echo sprintf(
        "HPB request failed. EBICS Error code : %s\nMessage : %s\nMeaning : %s",
        $exception->getResponseCode(),
        $exception->getMessage(),
        $exception->getMeaning()
    );
}
```

### 5. Play with other transactions!

| Transaction | Description                                                                                          |
|-------------|------------------------------------------------------------------------------------------------------|
| HEV         | Download supported protocol versions for the Bank.                                                   |
| INI         | Send to the bank public signature of signature A005.                                                 |
| HIA         | Send to the bank public signatures of authentication (X002) and encryption (E002).                   |
| H3K         | Send to the bank public signatures of signature (A005), authentication (X002) and encryption (E002). |
| HCS         | Upload for renewing user certificates.                                                               |
| HPB         | Download the Bank public signatures authentication (X002) and encryption (E002).                     |
| SPR         | Suspend activated keyring.                                                                           |
| HPD         | Download the bank server parameters.                                                                 |
| HKD         | Download customer's customer and subscriber information.                                             |
| HTD         | Download subscriber's customer and subscriber information.                                           |
| HAA         | Download Bank available order types.                                                                 |
| PTK         | Download transaction status (Plain text).                                                            |
| HAC         | Download transaction status (XML).                                                                   |
| FDL         | Download the files from the bank.                                                                    |
| FUL         | Upload the files to the bank.                                                                        |
| BTD         | Download request files of any BTF structure.                                                         |
| BTU         | Upload the files to the bank.                                                                        |

If you need to parse Cfonb 120, 240, 360 use [ebics-api/cfonb-php](https://github.com/ebics-api/cfonb-php)  
If you need to parse MT942 use [ebics-api/mt942-php](https://github.com/ebics-api/mt942-php)
