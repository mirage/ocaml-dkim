ocaml-dkim
----------

`ocaml-dkim` is a pure implementation of DKIM in OCaml. It use
[`mrmime`](https://github.com/mirage/mrmime.git) to parse and extract DKIM field
from an e-mail. Then, it use `x509` and `nocrypto` to verify signature (with
[`digestif`](https://github.com/mirage/digestif.git)). Finally, it asks via
[`udns`](https://github.com/roburio/udns.git) public key.

It provides an Unix and a LWT backend as a part of the
[MirageOS](https://mirage.io) project. It provides an executable `dkim.verify`
which can verify an e-mail from a
[`maildir`](https://github.com/dinosaure/ocaml-maildir.git) in one pass.

It follows mostly RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures.
