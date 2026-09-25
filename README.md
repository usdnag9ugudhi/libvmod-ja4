# libvmod-ja4

## About

A Varnish VMOD to compute [JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
TLS Client Hello fingerprints.

The VMOD parses the raw Client Hello wire bytes captured via an OpenSSL
message callback, not OpenSSL's parsed representation. This keeps the
full extension list and field order accurate, matching reference
implementations like Wireshark.

The message callback is installed automatically on every `SSL_CTX` via
an OpenSSL ex\_data `new_func` hook, so all connections -- including the
very first one after startup -- are captured.

OpenSSL copies the message callback into every connection, where it
can't be unregistered, so the VMOD is linked with `-z nodelete` and stays
in memory after the last VCL importing it is discarded. Until a VCL
imports it again, the callback does nothing. This has some consequences:

* The VMOD must be imported by the VCL that Varnish starts with. If it
  is first imported later, Varnish has already created its TLS contexts,
  and the `ja4.*()` functions return empty strings until a restart.
* Discarding every VCL that imports it and importing it again later is
  fine: fingerprints keep working.
* Installing a new build of the VMOD takes effect only after a restart
  of Varnish. Until then, the old copy's callback stays on the TLS
  contexts and the new copy returns empty strings.

Note that Varnish supports **JA3** natively via vmod-tls (set the
`tls_ja3` parameter and call `tls.ja3()`), which may be sufficient if
you do not specifically need JA4.

## Requirements

To build this VMOD you will need:

* make
* a C compiler, e.g. GCC or clang
* pkg-config
* python3-docutils or docutils in macOS [1]
* Varnish Cache 9.1 or later from https://varnish.org/
* libssl-dev in Debian/Ubuntu, openssl-devel in Fedora/RHEL.
  See also https://www.openssl.org/

If you are building from Git, you will also need:

* autoconf
* automake
* libtool

You will also need to set `PKG_CONFIG_PATH` to the directory where
**varnishapi.pc** is located before running `./bootstrap` and
`./configure`. For example:

```
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

## Installation

### From the Git repository

To install from Git, clone this repository and run:

```
./bootstrap
./configure
make
make check
sudo make install
```

The `make check` step is optional but it's good to know whether the
tests are passing on your platform.

## Example

```
import ja4;

sub vcl_recv {
    set req.http.X-JA4 = ja4.ja4();
}
```

Four variants are available, controlled by two independent dimensions
(sorted vs original wire order, hashed vs raw):

| Function      | Order    | Output |
|---------------|----------|--------|
| `ja4.ja4()`   | sorted   | hashed |
| `ja4.ja4_r()` | sorted   | raw    |
| `ja4.ja4_o()` | original | hashed |
| `ja4.ja4_ro()` | original | raw   |

## Troubleshooting

JA4 is only available when the **client** connection to Varnish is over
**TLS**. A common cause of an empty return value is the client connecting
over plain HTTP instead of HTTPS.

## License

This VMOD is licensed under the Unlicense. See LICENSE for details.

### Note

1. Using Homebrew, https://github.com/Homebrew/brew/.
