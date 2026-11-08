# Agents.md

This file provides guidance to coding Agents when working with code in this directory.

## What this directory is

A git submodule (`epp-server`, remote `origin` = `pawel-kow/epp`, `upstream` = `xpanel/epp`). It holds the XPanel EPP registry server 1.0.15, with the parent's changes applied: Perl CGI scripts, a MariaDB schema, Apache configs and cron jobs. The parent repo (`EPP-server-docker`) packages it in Docker. Read the parent's `Agents.md` for the stack.

**The parent's Docker build copies this checkout.** `cgi-bin/` and `etc/registry/` go into the EPP image and `sql/registry.sql` into the `mariadb_prep` image, so edits here reach the stack on the next `--build`, committed or not.

There is no build system, test suite or linter. Perl cannot run outside the container because the scripts hardcode `/var/www/cgi-bin/epp/lib` and `/etc/registry/registry.conf`. Check a change by reading it, `perl -c` where the modules are installed, or by running the parent stack.

## Layout

| Path | Contents |
| --- | --- |
| `cgi-bin/epp/command/` | `command-{check,create,delete,info,poll,renew,transfer,update}.cgi`: one script per EPP command, each handling the domain, contact and host objects. `create` and `update` are about 2,000 lines each. |
| `cgi-bin/epp/session/` | `session-{hello,login,logout}.cgi` |
| `cgi-bin/epp/error/` | `error-*.cgi`: response generators for the errors `mod_epp` detects (schema, parse, login, protocol, auth required, internal) |
| `cgi-bin/epp/lib/EPP/` | `Config.pm` (parses `registry.conf` into `%EPP::Config::c`), `EPPWriter.pm` (builds the response XML), `EPPResultCode.pm`, `PostalInfo.pm` (patterns for `loc` postal data), `SecDNS.pm` (RFC 5910 DS data), `IDN.pm` (punycode, A-label validation and the `idn-1.0` extension), `Session.pm` (the `objURI`/`extURI` choice of a login, kept per `mod_epp` session cookie), `Transaction.pm`, `Date.pm`, `Version.pm` |
| `cgi-bin/epp/cron/` | `write-zone.pl`, `change-domain-status.pl`, `auto-approve-transfer.pl`, `auto-clean-unused-contact-and-host.pl`, `clean-epp-sessions.pl`, `statistics.pl`, `send-invoice.pl`, with mail and PDF templates in `src/` |
| `cgi-bin/epp/htpasswd/.htpasswd` | Sample Basic-auth file; unused when auth goes through `mod_authn_dbd` |
| `cgi-bin/{whois,das}/` | PHP WHOIS and DAS front ends |
| `etc/` | `registry/registry.conf`, `httpd/conf.d/{epp,whois,das}.conf`, `cron.d/registry` |
| `sql/registry.sql` | Schema for the `registry` and `registryTransaction` databases, plus `CREATE USER` and `GRANT` lines |
| `backup/registry_db_backup.pl` | Installed to `/usr/local/registry/` by the cron entry |
| `epp_extensions.html`, `identExt-1.0.xsd` | Documentation and schema for the identity extension |
| `Documentation.txt`, `INSTALL`, `TODO`, `ChangeLog` | Manual installation steps and history. `INSTALL` only points to `Documentation.txt`. |

## Conventions in the code

- Every CGI script starts with `use lib '/var/www/cgi-bin/epp/lib'`, aliases `%c` to `%EPP::Config::c`, and connects with `DBI` using `mysql_*` keys from `registry.conf`. Adding a config key means adding it to `etc/registry/registry.conf` and reading it as `$c{'key'}`.
- `Config.pm` parses lines as `key = value` and strips `#` comments. A value cannot contain `#`.
- Scripts are plain `.cgi` files run through `SetHandler cgi-script`. `mod_epp` maps each EPP command to an `Alias` in `etc/httpd/conf.d/epp.conf`. A new script needs an alias there.
- Each command opens its `registryTransaction` row with `record_cl_transaction` (`EPP/Transaction.pm`), which stores the `clTRID` per registrar as `<registrar id>:<clTRID>`, answers `2400` and exits on a reuse, and completes the row with `update_transaction`. The `header()` is printed before that point, so a `die` leaves the client with no reply.
- Cron jobs write logs to `/var/log/epp/*.log`; the schedule is in `etc/cron.d/registry`.
- Files carry the Apache License 2.0 header and the XPanel copyright. Keep the header on new files.

## Things to know before changing code

- `sql/registry.sql` creates users with default passwords (`EPPRegistry`, `EPPRegistrySELECT`, `EPPRegistryUPDATE`). The parent repo filters those lines out and creates its own user, so do not rely on them.
- `registrar.pw` is checked by Apache through `EPPAuthURI`, and again by `session-login.cgi`. It must be `{SHA}base64(sha1(pwd))`.
- `etc/httpd/conf.d/epp.conf` is the stock server config (`www.xpanel.com`, `SSLVerifyClient require`, certificate paths under `/etc/pki`). The parent repo replaces it with its own `epp_server_common.conf`, so changes here do not carry over.
- `etc/registry/registry.conf` here is a reference copy. The parent's `etc/registry/registry.conf` overwrites it in the image, so a new key has to be added to both, and to the parent's `x-registry-env` if it comes from the environment.
- `write-zone.pl` reads `zone_ns1` and `zone_ns2`. `command-transfer.cgi` reads `transfer_lock_days` and `transfer_waiting_minutes`; the waiting period is in minutes, unlike upstream's 5 days.
- `write-zone.pl` reloads BIND with `rndc -s nameserver`, which assumes the parent's `nameserver` service and the `rndc.key` it generates in `/var/named`.
- `host_addr.ip` must be stored as `v4` or `v6`. Upstream's `$addr_type =~ s/\D//g;` in `command-create.cgi` made MariaDB store an empty enum, so `write-zone.pl` and `EPPWriter.pm` derive the type from the address to cope with old rows.
- Contact IDs must start with the registrar's `prefix` plus `-`. `prefix` is `char(2)` and unique.
- `EPP/SecDNS.pm` offers the RFC 5910 DS data interface only: `keyData` on its own answers `2306`. The `secdns` columns set two more limits, both `2306`: no digest type 4 (`digest` is `varchar(64)`) and no `pubKey` over 255 characters. `maxSigLife` is stored on each row, so it cannot be set on a domain without DS data. `write-zone.pl` does not publish DS records yet.
- `EPP/IDN.pm` uses the `idn_table` table and the `domain`.`idn_table` and `idn_uname` columns, which `sql/registry.sql` does not have: the parent repo adds them in its migration `.docker/mariadb_prep/migrations/001_idn.sql`. Domain names are uppercased before `validate_label`, so the A-label test there is `/^XN--/`; `idn_alabel_error` lowercases before decoding. The `validate_label` in `check`, `create` and `info` is the same code three times; keep them in step. Hosts with `xn--` labels are not validated as IDNs.
- `secdns` has a `RESTRICT` foreign key on `domain`, so anything that deletes a domain must clear it first.
- A reply carries only the extensions the client chose at login. `record_cl_transaction` puts them in `$blob->{exturis}` (`EPP/Session.pm`, the `epp_session` table from the parent's migration `002_epp_session.sql`), and the writer checks each extension with `_chosen`. A new extension in a reply needs that check. `undef` means the choice is unknown and lets everything through, so a database without the table behaves as before.
- `command-info.cgi` is not valid UTF-8. Edit it as bytes.
- Strings are characters inside the scripts and UTF-8 at the edges. `EPPWriter.pm` sets the `STDOUT` layer, and every command and session script connects with `mysql_enable_utf8`, so a new script that talks to the DB needs it too. The exceptions are `frame` and `clTRID`, which CGI hands over as bytes: `_postamble` decodes `clTRID`, so pass it to the writer undecoded. Non-ASCII literals in a module need `use utf8`.
- `postalInfo type="loc"` accepts UTF-8 through `EPP/PostalInfo.pm`; `type="int"` stays ASCII, as RFC 5733 requires. `contact:pc` is ASCII in both. Characters beyond the BMP answer `2005`, because the columns are `utf8` rather than `utf8mb4`.

## Working with the submodule

- Commit inside `epp-server/` first, push to `origin` (the fork), then commit the updated submodule pointer in the parent. A parent commit that points at an unpushed submodule commit breaks fresh clones.
- To pull upstream changes, merge from the `upstream` remote.
- The `.gitmodules` URL is SSH (`git@github.com:...`), so cloning needs a GitHub SSH key.
