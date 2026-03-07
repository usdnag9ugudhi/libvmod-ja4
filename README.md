# libvmod-ja4

## About

A Varnish VMOD to compute [JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
TLS Client Hello fingerprints.

The VMOD parses the raw Client Hello wire bytes captured via an OpenSSL
message callback, not OpenSSL's parsed representation. This keeps the
full extension list and field order accurate, matching reference
implementations like Wireshark.

## Requirements

To build this VMOD you will need:

* make
* a C compiler, e.g. GCC or clang
* pkg-config
* python3-docutils or docutils in macOS [1]
* Varnish 7.5 or later from https://varnish.org/
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

### From a tarball

To install this VMOD, run the following commands:

```
./configure
make
make check
sudo make install
```

The `make check` step is optional but it's good to know whether the
tests are passing on your platform.

### From the Git repository

To install from Git, clone this repository and run:

```
./bootstrap
```

And then follow the instructions above for installing from a tarball.

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
**TLS**. Common causes of an empty return value:

1. The client is connecting over plain HTTP instead of HTTPS.
2. Varnish is not listening with a TLS endpoint.
3. The very first TLS connection after Varnish starts will not have a
   JA4 fingerprint. The OpenSSL message callback is installed lazily on
   the first request, so the Client Hello for that connection has
   already been processed. All subsequent connections are captured.

## License

This VMOD is licensed under the Unlicense. See LICENSE for details.

### Note

1. Using Homebrew, https://github.com/Homebrew/brew/.
