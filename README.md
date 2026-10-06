# libvmod-ja4

## About

A Varnish VMOD to compute [JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
TLS Client Hello fingerprints. Once this VMOD is loaded, there is no possibility to unload it.

Note that Varnish supports **JA3** natively via vmod-tls (set the
`tls_ja3` parameter and call `tls.ja3()`), which may be sufficient if
you do not specifically need JA4.

## Requirements

To build this VMOD you will need:

* make
* a C compiler, e.g. GCC or clang
* pkg-config
* python3-docutils or docutils in macOS [1]
* Varnish Enterprise 6.0 with in-process TLS (`varnish-plus-dev`).
  For Varnish Cache 9.1 or later, use the `main` branch.
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

`make check` needs a Varnish Enterprise license with TLS listen sockets
(`tls-client`). varnishtest reads it from `VARNISH_LICENSE`:

```
VARNISH_LICENSE=/etc/varnish/varnish-enterprise.lic make check
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

## License

This VMOD is licensed under the Unlicense. See LICENSE for details.

### Note

1. Using Homebrew, https://github.com/Homebrew/brew/.
