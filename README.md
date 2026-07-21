# MTProto DC Config Generator

`mtproto-dc-config` is a standalone Rust program that generates the Telegram
datacenter endpoint table used by Surge's MTProto inbound proxy.

The generator establishes a direct MTProto connection, performs the
authorization-key handshake, calls `help.getConfig`, supplements that response
with Telegram's recovery endpoints, and writes the merged result as JSON. It
does not require a Telegram account or user authorization.

The implementation is cross-platform and uses Rust implementations of AES,
SHA, big integers, gzip, TLS, and JSON. It does not depend on Foundation,
CommonCrypto, OpenSSL, or another platform-native library.

## Endpoint sources

Endpoints are merged in the following order:

1. The live `help.getConfig` response.
2. Every applicable endpoint from Telegram's signed and encrypted
   `apv3.stel.com` backup configuration, retrieved through Google DNS-over-HTTPS.
3. The production IPv4 and IPv6 bootstrap endpoints bundled with the official
   Telegram iOS and Desktop clients.

The backup configuration may contain different rules for different phone-number
prefixes. The generator unions the endpoints from all of those rules because
the generated file must also work before Surge knows the Telegram account's
phone number.

Backup and bootstrap endpoints are marked with Telegram's `static` flag.
When a fallback endpoint is already present in `help.getConfig`, its existing
entry is upgraded in place. Exact duplicates are then removed without changing
the remaining source order.

Fetching the backup configuration is best-effort. If it cannot be downloaded or
validated, generation continues with `help.getConfig` and the built-in bootstrap
table. At least one MTProto bootstrap connection must succeed; otherwise no
output is written.

### Scope

This tool covers the normal `help.getConfig` response, the public
`apv3.stel.com` recovery channel, and the bootstrap tables embedded in the
official clients.

It intentionally does not access Telegram iOS's private CloudKit emergency
configuration channel. Consequently, an address observed in an iOS client is
not guaranteed to appear in the generated file if it is available only through
CloudKit or retained in that client's local cache.

## Build

Install the stable Rust toolchain and run:

```sh
cargo build --release
```

The executable is written to:

- macOS and Linux: `target/release/mtproto-dc-config`
- Windows: `target\release\mtproto-dc-config.exe`

## Generate JSON

On macOS or Linux:

```sh
./target/release/mtproto-dc-config [output.json|-] [host] [port]
```

On Windows PowerShell:

```powershell
.\target\release\mtproto-dc-config.exe [output.json|-] [host] [port]
```

All arguments are optional:

- `output.json` defaults to `mtproto-dc-config.json`.
- `-` writes JSON to stdout.
- `host` and `port` override the endpoint used to call `help.getConfig`.
- `port` defaults to `443` when `host` is specified.
- Without an explicit host, the generator tries its built-in production
  bootstrap endpoints in order until one succeeds.

For example:

```sh
cargo run --release -- mtproto-dc-config.json
cargo run --release -- - 149.154.167.50 443
```

Progress and warnings are written to stderr, so stdout remains valid JSON when
`-` is used.

## Output format

The root object currently has the following fields:

- `version`: generator output schema version.
- `date`: `help.getConfig` generation time supplied by Telegram.
- `expires`: `help.getConfig` expiration time supplied by Telegram.
- `this_dc`: the DC that answered `help.getConfig`.
- `options`: merged DC endpoint objects in selection order.

Each option contains `id`, `ip`, `port`, and Telegram's numeric `flags`.
Endpoints carrying an MTProto secret also contain `secret`, encoded as Base64.
IPv4 and IPv6 endpoints are retained together; the consumer decides which
address family is usable.

The top-level `expires` value is preserved as upstream metadata. It does not
control Surge's download schedule. Surge persists a downloaded file and checks
its modification date; after 30 days, the next MTProto access triggers a
non-blocking refresh while the current in-memory table remains usable.

## Publishing and Surge integration

The generated JSON can be bundled with a client or published over HTTPS. Surge
uses this default update endpoint:

```text
https://raw.githubusercontent.com/surge-networks/MTProtoDCConfigGenerator/refs/heads/main/mtproto-dc-config.json
```

An alternative published file can be selected in the Surge configuration:

```ini
[MTProto]
dc-config-url = https://example.com/mtproto-dc-config.json
```

The published file should retain the generated schema and be served over a
stable HTTPS URL. Surge validates the downloaded JSON before replacing its
persisted copy. A failed update does not discard the bundled or cached table.

## Validation

Run the unit tests and lint checks before publishing a new file:

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

## Upstream references

The backup decoder, cryptographic validation, and built-in endpoint seeds follow
the official Telegram client implementations:

- [Telegram iOS backup address signals](https://github.com/TelegramMessenger/Telegram-iOS/blob/master/submodules/MtProtoKit/Sources/MTBackupAddressSignals.m)
- [Telegram iOS backup cryptography](https://github.com/TelegramMessenger/Telegram-iOS/blob/master/submodules/MtProtoKit/Sources/MTEncryption.m)
- [Telegram iOS network bootstrap configuration](https://github.com/TelegramMessenger/Telegram-iOS/blob/master/submodules/TelegramCore/Sources/Network/Network.swift)
- [Telegram Desktop source tree](https://github.com/telegramdesktop/tdesktop)
