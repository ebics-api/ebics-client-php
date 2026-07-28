# EBICS Client PHP Library

**Package:** `ebics-api/ebics-client-php` — Version 3.2.0

> **Purpose of this document:** knowledge base / AI-assistant context for the
> `ebics-client-php` library. It explains in plain language what the library
> can do, how the workflows go, and answers common questions. Each section is
> self-contained.

---

## Table of Contents

- [Description](#description)
- [Installation and Requirements](#installation-and-requirements)
- [How the Library Is Organized](#how-the-library-is-organized)
- [Getting Started: What You Need](#getting-started-what-you-need)
- [Keyring: Your Keys and the Bank's Keys](#keyring-your-keys-and-the-banks-keys)
- [Connection Initialization Workflow](#connection-initialization-workflow)
- [Bank Letter](#bank-letter)
- [Order Types](#order-types)
- [Downloading Files and Statements](#downloading-files-and-statements)
- [Uploading Payments and Files](#uploading-payments-and-files)
- [SEPA Documents](#sepa-documents)
- [Configuration Options](#configuration-options)
- [Certificates (X.509)](#certificates-x509)
- [Error Handling](#error-handling)
- [Testing Without a Bank](#testing-without-a-bank)
- [FAQ](#faq)
- [Related Packages](#related-packages)

---

## Description

`ebics-client-php` is an open-source PHP library for communicating with banks
over the **EBICS** protocol (Electronic Banking Internet Communication
Standard), widely used in Germany, France, Switzerland, Austria, and across
Europe. The library handles the complete EBICS transaction lifecycle:
generating cryptographic keys, registering with the bank, exchanging keys, and
uploading or downloading banking files — including all the protocol details
(segmentation, compression, encryption, digital signatures) automatically.

> **Looking for a ready-to-deploy solution?** The premium
> [EBICS API Client](https://sites.google.com/view/ebics-api-client) wraps this
> library into a standalone REST microservice with an admin panel, scheduler,
> and MCP server for AI agents.

### Supported Standards

| Item | Values |
|------|--------|
| EBICS versions | 2.4, 2.5, 3.0 |
| Encryption / signature versions | E002, X002, A005, A006 |
| Bank modes | EBICS T / EBICS TS switching |

---

## Installation and Requirements

Install via Composer: package name `ebics-api/ebics-client-php`.

| Component | Requirement |
|-----------|-------------|
| PHP | 8.5 or newer |
| PHP extensions | bcmath, curl, dom, json, openssl, zip, zlib, libxml |

Optional companion packages:

| Package | Purpose |
|---------|---------|
| `ebics-api/cfonb-php` | Parse French CFONB 120/240/360 statement formats |
| `ebics-api/mt942-php` | Parse SWIFT MT942 statements |
| `setasign/fpdf` | Generate the bank letter as a PDF |
| Any PSR-18 HTTP client | Replace the default cURL transport |

---

## How the Library Is Organized

The library is built around a few core concepts:

- **Bank** — represents the bank's EBICS server: its Host ID and Host URL.
- **User** — represents you as a subscriber: your Partner ID and User ID.
- **Keyring** — a password-protected container holding your three key pairs
  (signing, authentication, encryption) and the bank's public keys. Stored as
  an encrypted JSON file or array.
- **Client** — the main entry point. It combines Bank, User, and Keyring and
  executes orders against the bank. The EBICS protocol version (2.4/2.5/3.0)
  is taken from the keyring and handled automatically.
- **Orders** — one class per EBICS order type (INI, HPB, HAC, BTU, and so on).
  You create an order, hand it to the client, and receive a result containing
  the downloaded data or the bank's confirmation.

The package also includes a bank letter generator, SEPA document helpers,
schema files for validation, and test utilities.

---

## Getting Started: What You Need

Your bank provides four credentials when you sign an EBICS contract:

| Credential | Meaning |
|------------|---------|
| Host URL | The address of the bank's EBICS server |
| Host ID | The bank's identifier for its EBICS host |
| Partner ID | Your company's identifier at the bank |
| User ID | Your personal subscriber identifier |

You also choose:

- **EBICS version** — as agreed with your bank (2.4, 2.5, or 3.0).
- **Keyring password** — protects your private keys at rest; you pick it.
- **Certificate mode** — required for EBICS 3.0 and most French banks
  (see [Certificates](#certificates-x509)).

First run: the library generates your three key pairs and stores them in the
keyring file. Subsequent runs: the existing keyring is loaded with the
password. Always save the keyring after any operation that creates or receives
keys, otherwise they are lost.

---

## Keyring: Your Keys and the Bank's Keys

The keyring holds five cryptographic identities:

| Key | Owner | Used for |
|-----|-------|----------|
| A (signature) | You | Digitally signing order files |
| X (authentication) | You | Authenticating each request to the bank |
| E (encryption) | You | Decrypting data the bank sends you |
| X (authentication) | Bank | Verifying the bank's responses |
| E (encryption) | Bank | Encrypting data you send to the bank |

Your keys are created locally; the bank's keys are downloaded during
initialization (HPB order). Private keys are encrypted with the keyring
password. The library offers two storage managers: file-based (JSON file on
disk) and array-based (for storing in your own database).

Maintenance operations:

- **Check** the keyring password/state validity.
- **Change password** — re-encrypts all keys with a new password.
- **Renew** user certificates on an active connection (HCS order).
- **Suspend** — block your access on the bank server (SPR order).

---

## Connection Initialization Workflow

Activating a new EBICS subscriber is a handshake defined by the protocol:

1. **Generate keys** — the library creates your three key pairs into the
   keyring (done once).
2. **Send INI** — transmits your public signing key to the bank.
3. **Send HIA** — transmits your public authentication and encryption keys.
   (Some certificate-based banks accept H3K instead, which sends all three
   keys in one order.)
4. **Print and mail the bank letter** — a document listing your key hashes;
   the bank compares it with what it received electronically and activates
   your access. See [Bank Letter](#bank-letter).
5. **Wait for bank activation** — a manual step on the bank's side.
6. **Fetch bank keys (HPB)** — downloads the bank's public keys into your
   keyring. After this succeeds, the connection is fully active and every
   other order type becomes available.

If INI or HIA fails, the bank returns an EBICS error code with a
human-readable meaning (see [Error Handling](#error-handling)); a common cause
is that the subscriber is already initialized or not yet set up on the bank
side.

---

## Bank Letter

The initialization letter contains the fingerprints (hashes) of your three
public keys, your IDs, and signature fields. Your bank verifies the printed
hashes against the electronically transmitted keys before activating you.

The library prepares the letter from your bank, user, and keyring data, and
can format it three ways: plain text, HTML, or PDF (PDF requires the optional
`setasign/fpdf` package).

---

## Order Types

Order types are the operations of the EBICS protocol. The library supports:

| Order | Purpose |
|-------|---------|
| HEV | List which EBICS protocol versions the bank supports |
| INI | Send your public signing key to the bank (initialization) |
| HIA | Send your public authentication and encryption keys |
| H3K | Send all three public keys in one order (certificate-based banks) |
| HCS | Renew/replace your certificates on an active connection |
| HPB | Download the bank's public keys |
| SPR | Suspend (block) your access on the bank server |
| HPD | Download bank server parameters and capabilities |
| HKD | Download your company's configuration (all subscribers) |
| HTD | Download your own subscriber configuration |
| HAA | List which order types the bank offers you |
| PTK | Download transaction log (plain-text protocol report) |
| HAC | Download transaction log (structured XML, with optional date range) |
| FDL | Download files — EBICS 2.4/2.5 (file-format based) |
| FUL | Upload files — EBICS 2.4/2.5 (file-format based) |
| BTD | Download files — EBICS 3.0 (BTF service/message based) |
| BTU | Upload files — EBICS 3.0 (BTF service/message based) |

Order availability per EBICS version:

| Order | 2.4 | 2.5 | 3.0 |
|-------|-----|-----|-----|
| FDL, FUL | Yes | Yes | No |
| BTD, BTU | No | No | Yes |
| All others | Yes | Yes | Yes |

Using an order outside its supported version raises a clear
"method not implemented" error naming the version.

---

## Downloading Files and Statements

Downloads (statements, reports, payment status) are multi-phase EBICS
transactions; the library performs initialization, segment transfer, and
receipt automatically and hands you the decrypted, decompressed content.

- **EBICS 2.4/2.5 (FDL):** you specify the bank's file format code (for
  example `camt.xxx.cfonb120.stm` for French CFONB statements), an optional
  date range, optional country code, and optional bank-specific parameters.
- **EBICS 3.0 (BTD):** you specify the BTF attributes — service name, message
  name (e.g. `camt.053`, `pain.002`), optional version, scope, container type
  — plus an optional date range. The valid combinations are listed in your
  bank's BTF table; the HTD order response also lists what your subscription
  offers.

The result gives you the raw content as text, as parsed XML, or as extracted
files when the bank delivers a ZIP container. Downloaded French CFONB or MT942
content can be parsed with the companion packages.

The audit-trail orders HAC (XML) and PTK (text) work the same way and accept
an optional start/end date range. Note: EBICS date ranges are date-only
(no time of day) per the protocol schema.

---

## Uploading Payments and Files

Uploads (SEPA payments, direct debits, arbitrary files) are also multi-phase:
the library splits the file into segments, encrypts and signs everything, and
returns the bank's confirmation including an order ID.

- **EBICS 2.4/2.5 (FUL):** you specify the file format code (for example a
  pain.001 credit-transfer format), the file content, and optional parameters
  such as a TEST flag or country code.
- **EBICS 3.0 (BTU):** you specify the BTF attributes — service name (e.g.
  MCT for credit transfers, SDD for direct debits), message name (`pain.001`,
  `pain.008`, `csv`, ...), optional version/scope/option — plus a file name
  that is transmitted to the bank alongside the content.

Any content type can be uploaded (XML, CSV, plain text). An electronic
signature flag controls whether the order requests the bank's electronic
signature processing (relevant for EBICS TS setups).

---

## SEPA Documents

The library includes helpers to build SEPA order data:

| Helper | Purpose |
|--------|---------|
| Customer Credit Transfer | Builds pain.001 credit-transfer XML |
| Customer Direct Debit | Builds pain.008 direct-debit XML |
| Postal address models | Structured/unstructured debtor and creditor addresses |

ISO 20022 and EBICS XML schemas (pain.001, pain.008, camt.052, camt.053, and
the EBICS protocol schemas) are bundled under `doc/schema/` for validation.

---

## Configuration Options

Behavior can be customized through an options object passed when creating the
client:

| Option | What it does |
|--------|--------------|
| HTTP client | Swap the default cURL transport for a PSR-18 client, a request debugger (dumps requests without sending), or a faker (canned responses for tests) |
| cURL options | Set timeouts, proxies, TLS settings on the default transport |
| Logger | Attach a PSR-3-style logger to record request/response activity |
| Schema directory | Enable XML schema validation of outgoing requests |
| Crypto overrides | Advanced: replace the RSA, AES, base64, or compression implementations |

---

## Certificates (X.509)

Some banks — all EBICS 3.0 banks and most French banks — require keys to be
wrapped in X.509 certificates rather than sent as bare keys. The library
supports this "certified" mode:

- A built-in generator creates self-signed certificates with subject fields
  derived from the bank's country and address.
- Alternatively, externally issued certificates can be supplied.
- Certificate mode must be enabled on the keyring **before** generating the
  user keys.

The keyring reports whether it is in certified mode, and the bank letter
includes certificate details when applicable.

---

## Error Handling

Two kinds of errors occur:

1. **Bank-reported EBICS errors** — the bank answers with a standardized
   6-digit return code. The library converts each code into a specific
   exception carrying three pieces of information: the response code, a short
   message, and the official meaning text. Examples:

   | Code | Meaning |
   |------|---------|
   | 000000 | OK — request successful |
   | 011000 | Download receipt confirmed (positive acknowledgement) |
   | 090003 | Authentication failed |
   | 090005 | No download data available — the requested range is simply empty; treat as an empty result, not a failure |
   | 091002 | Invalid user or user state — subscriber not (yet) active |
   | 091306 | Bank public key update required |

   The complete error-code catalog is documented in
   [`doc/ebics-errors.md`](./ebics-errors.md).

2. **Library errors** — invalid keyring password, unsupported order for the
   EBICS version, malformed responses, and similar. All derive from a common
   exception base so they can be caught uniformly.

---

## Testing Without a Bank

- **Faker transport** — returns predefined fixture responses so integration
  code can run entirely offline.
- **Debugger transport** — builds and dumps the exact request that would be
  sent, without contacting the bank.
- **Test suite** — the repository ships PHPUnit suites covering every order
  type for EBICS 2.4, 2.5, and 3.0, runnable inside the provided Docker
  environment (`make docker-up`, `make check`).
- **EBICS server stub** — the premium EBICS API Client provides a simulated
  bank server (Host ID `EBICSSTUB`) for end-to-end testing.

---

## FAQ

**Q: Which EBICS versions are supported?**
A: 2.4, 2.5 and 3.0. The version is fixed in the keyring when it is created
and must match what your bank contract specifies. The library adapts all
requests to the chosen version automatically.

**Q: How do I download bank statements?**
A: On EBICS 2.4/2.5 use the FDL order with the bank's file format code (for
example the CFONB statement format). On EBICS 3.0 use the BTD order with the
service and message name from your bank's BTF table (for example camt.053 for
end-of-day statements). Both accept an optional date range.

**Q: How do I upload a SEPA payment (pain.001 / pain.008)?**
A: Build the SEPA XML (with the bundled credit-transfer/direct-debit helpers
or your own generator), then send it with FUL (EBICS 2.4/2.5, using the
agreed file format code) or BTU (EBICS 3.0, using the agreed service and
message name). The bank replies with an order ID confirming acceptance.

**Q: Why do I get a "method not implemented" error?**
A: The order type doesn't exist in your keyring's EBICS version: BTD/BTU
require 3.0, while FDL/FUL only exist in 2.4/2.5. Use the counterpart order
for your version.

**Q: The bank returns error 090005 — is something broken?**
A: No. EBICS_NO_DOWNLOAD_DATA_AVAILABLE means there is no data in the
requested date range. Treat it as an empty result.

**Q: Do I have to save the keyring after operations?**
A: Yes. After generating keys and after INI, HIA, HPB, or HCS, save the
keyring — otherwise newly created or newly downloaded keys are lost and the
connection can end up in a broken state.

**Q: How do I renew keys on an active connection?**
A: Generate a new set of keys and send them with the HCS order; the bank
switches to the new keys. To block your access entirely, send SPR.

**Q: Is certificate (X.509) mode required?**
A: For EBICS 3.0 and most French banks, yes. Enable certificate mode on the
keyring before generating your keys; the library can create self-signed
certificates automatically.

**Q: How is the keyring stored — is it safe?**
A: As JSON (file or array), with the private keys encrypted by your keyring
password. The password can be changed at any time, and the keyring can be
verified without contacting the bank.

**Q: Can I test my integration without a real bank?**
A: Yes — use the faker transport (canned responses), the debugger transport
(inspect requests without sending), or the premium product's EBICS server
stub for full end-to-end simulation.

**Q: What if my bank uses a proxy or needs longer timeouts?**
A: Configure cURL options (timeout, proxy, TLS) via the client options, or
plug in your own PSR-18 HTTP client.

---

## Related Packages

| Package | Purpose |
|---------|---------|
| [ebics-api/cfonb-php](https://github.com/ebics-api/cfonb-php) | Parse CFONB 120/240/360 |
| [ebics-api/mt942-php](https://github.com/ebics-api/mt942-php) | Parse MT942 |
| [EBICS API Client](https://sites.google.com/view/ebics-api-client) | Premium REST microservice built on this library |
