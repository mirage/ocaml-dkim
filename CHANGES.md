### v0.8.0 2025-04-28 - Paris (France)

- Fix unknown tag (@dinosaure, #46)
- Remove the high-kinded polymorphism (@dinosaure, #47)
- Expose useful functions (@dinosaure, #48, #53, #55)
- Fix generated signature (@dinosaure, #49)
- Export the `Decoder` module (@dinosaure, #50)
- Lint dependencies for the mirage-layer (@hannesm, #51)
- Factorize the way we digest things (@dinosaure, #54)
- Be compatible with `X509.Public_key.t` (@dinosaure, #56)
- Add `x-maintenance-intent` (@dinosaure, #52)

### v0.7.0 2024-09-18 - Paris (France)

- Remove `mirage-random` and upgrade to `tls.1.0.0` (@hannesm, @dinosaure, #44)

### v0.6.0 2024-31-05 Paris (France)

- Improve binaries provided by the distribution (#40, @dinosaure)
- Upgrade `ocaml-dkim` with `dns-client-mirage.8.0.0` (#42, @dinosaure)

### v0.5.0 2023-03-01 Paris (France)

- Separate binaries provided by dkim into a new package `dkim-bin` (@dinosaure, #38)
- Upgrade tests with `mirage-crypto-rng.0.11.0` (@dinosaure, #38)
- Adapt to `dns-client.7.0.0` repackaging (@hannesm, #38)
- Really delete the `rresult` package (@dinosaure, #39)

### v0.4.0 2022-11-30 Paris (France)

- Upgrade the distribuction with:
  `ocamlformat.0.23.0.`
  `cmdliner.1.1.0`
  `dns.6.4.0` (@dinosaure, @hannesm, #36)

### v0.3.1 2021-11-30 Paris (France)

- Remove `rresult` dependency (#32, @dinosaure)

### v0.3.0 2021-11-15 Paris (France)

- Upgrade to the new interface of `mrmime` (#15, @dinosaure)
- Fix how we parse AUID (#16, @dinosaure)
- Implement a real memory bounded verify function (#19, @dinosaure)
- Homogeneize DNS interface (with `ocaml-spf`) (#20, @dinosaure)
- Add some accessors to be able to get some info from DMARC (#21, #22, @dinosaure)
- Add a comparison function on server values (#24, @dinosaure)
- Fix stream implementation on `dkim-mirage` (#26, @dinosaure)
- Upgrade to the new DNS interface (#25, @dinosaure)
- Fix when we got an empty prelude (and don't raise end-of-stream in that case) (#27, @dinosaure)
- Upgrade ocamlformat and fmt.0.8.7 (#28, @dinosaure)
- Use the lastest version of DNS (with DNS-over-TLS) (#30, @dinosaure)

### v0.2.0 2021-04-27 Paris (France)

- Upgrade to `tls.0.13.0` and `dns.5.0.0` (@dinosaure, #9)
- Support of Ed25519 key (@dinosaure, #9)
- `dkim-mirage` requires a `Stack.V4V6` TCP/IP stack (@dinosaure, #9)
- Lint opam files (@dinosaure, #11)

### v0.1.0 2020-09-24 Paris (France)

- First release
