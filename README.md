# ocaml-dkim

`ocaml-dkim` is a pure implementation of DKIM in OCaml. It permits to verify and
sign an incoming email. It can be use as a SMTP filter service (verify) or as a
SMTP submission service (sign).

## Usage

### How to install it?

You must have an OPAM environment. Then, `ocaml-dkim` can be installed with:

```sh
$ opam install dkim
$ opam install dkim-bin
```

### How to use it?

`ocaml-dkim` provides 2 binaries, one to verify, the second to sign an email.

```sh
$ dkim.verify test/raw/001.mail
[ok]: sendgrid.info
[ok]: github.com
```

It shows all domains which signed the given email and whether the signature is
correct or not (for the last case, it shows you the _selector_). `ocaml-dkim` is
able to sign an email from a private RSA key and a specific domain such as:

```sh
$ dkim.sign -k private-key.pem --selector admin --hostname x25519.net \
  test/raw/001.mail
DKIM-Signature: ...
Rest of the email
```

It prints the signed email then. The user is able to use a specific RSA private
key or it can use a seed used to generate the RSA private key with the _fortuna_
random number generator.

### Note about _end-of-line_ characters

`ocaml-dkim` was designed to work with an SMTP flow where lines are delimited by
`\r\n`. In this sense, `ocaml-dkim` can work with `\n` as the line delimiter
(the default behavior for distributed binaries) or `\r\n` (see the `--newline`
argument). Be sure to recognize the end-of-line delimiter of your incoming
emails! For instance, if you use binaries with an email which terminates lines
by `\r\n`, you will get an error.

### DNS servers used to verify

The `dkim.verify` gives the opportunity to the user to specify the nameserver
he/she wants to get DKIM public keys. The user can use DNS or DNS over TLS with
values required to verify certificates.

For instance, you can use [unicast.uncensoreddns.org][uncensoreddns]:
```sh
$ dkim.verify test/raw/001.mail \
  --nameserver 'tls:89.233.43.71!cert-fp:sha256:ZGDOiBng2T0tx11GsrQDifAV8hVWFcI8kBfqz4mf9U4='
[ok]: sendgrid.info
[ok]: github.com
```

## Usage on bigger projects

`ocaml-dkim` is used by an implementation of an SMTP server available here:
[`ptt`][ptt]. You can follow a mini tutorial to download/deploy the unikernel
which can sign incoming emails here: [Deploy an SMTP service (2/3)][blog]

The project is also used by a simple client to manipulate emails: [blaze][blaze]

## Designs & considerations

`ocaml-dkim` was made with the objective to **stream** the verification. Unlike
other implementations, ocaml-dkim only makes one pass to check your email. In
this sense, it can have a predictable memory consumption (corresponding to a
_chunk_ that will be filled concurrently with the analysis).

The calculation of the signature, as well as the production of the
`DKIM-Signature` field, also requires only one pass. However, to add the field
to the email, you will need to keep the whole email somewhere and add the new
field beforehand.

### Unikernels compatibility

`ocaml-dkim` has been designed so that the core library does not depend on
POSIX. Thus, the project can be integrated into a [_unikernel_][unikernel]
without difficulties.

`ocaml-dkim` has received funding from the Next Generation Internet Initiative
(NGI) within the framework of the DAPSI Project.

[ptt]: https://github.com/mirage/ptt
[blog]: https://blog.osau.re/articles/smtp_2.html
[blaze]: https://github.com/dinosaure/blaze.git
[unikernel]: https://en.wikipedia.org/wiki/Unikernel
[uncensoreddns]: https://blog.uncensoreddns.org/
