(** DKIM signature and verification for emails.

    This module implements the DomainKeys Identified Mail (DKIM) protocol as
    specified by {{:https://datatracker.ietf.org/doc/html/rfc6376} RFC 6376}.
    DKIM allows a sending domain to cryptographically sign outgoing email so
    that receiving mail servers can verify the message has not been altered in
    transit and was authorized by the domain owner.

    The library processes emails in a single streaming pass for both
    verification and signing. Memory consumption stays proportional to the size
    of an input chunk, not the size of the entire message.

    Two signature algorithms are supported: RSA and ED25519. Two hash functions
    are available: SHA1 and SHA256. Both "simple" and "relaxed" canonicalization
    methods are implemented for headers and body. *)

(** {1 Core types} *)

type algorithm = [ `RSA | `ED25519 ]
(** The signature algorithm used to produce or verify a DKIM signature. RSA is
    the most widely deployed algorithm. ED25519 is a newer, smaller-key
    alternative introduced by
    {{:https://datatracker.ietf.org/doc/html/rfc8463} RFC 8463}. *)

type hash = [ `SHA1 | `SHA256 ]
(** The hash function used when computing the digest of the message headers and
    body. SHA256 is recommended. SHA1 is supported for compatibility with older
    signatures but is considered weak. *)

type canonicalization = [ `Simple | `Relaxed ]
(** The canonicalization algorithm applied to headers or body before hashing.
    [`Simple] leaves the content untouched (modulo trailing CRLF rules).
    [`Relaxed] normalizes whitespace and lowercases header field names, which
    makes the signature more tolerant of minor modifications by intermediate
    mail servers. *)

type query = [ `DNS of [ `TXT ] ]
(** The method used to retrieve the public key of the signing domain. The only
    method defined by RFC 6376 is a DNS TXT record query. *)

(** An existentially packed hash algorithm from {!module:Digestif}. *)
type hash_algorithm = Hash_algorithm : 'k Digestif.hash -> hash_algorithm

(** An existentially packed hash value: a pair of a {!module:Digestif} hash
    algorithm and the corresponding digest. *)
type hash_value = Hash_value : 'k Digestif.hash * 'k Digestif.t -> hash_value

type 'a t
(** A DKIM record, parameterized by whether it carries a cryptographic
    signature. A value of type [signed t] was parsed from an existing
    [DKIM-Signature] header field and carries both the original signature bytes
    and the body hash. A value of type [unsigned t] is one that has been
    constructed programmatically and is ready to be signed. *)

and signed = private string * hash_value
(** The payload of a signed DKIM record: the raw signature string together with
    the body hash. The [private] annotation prevents construction outside this
    module while still allowing pattern-matching. *)

and unsigned
(** The phantom type for an unsigned DKIM record. Values of this type are
    created by {!v} and consumed by {!val:Sign.signer}. *)

type key =
  [ `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]
(** A private key used for signing. It must match the {!val:algorithm} declared
    in the DKIM record: an RSA key for [`RSA] and an Ed25519 key for [`ED25519].
*)

(** {1 Constructing a DKIM record} *)

val v :
  ?version:int ->
  ?fields:Mrmime.Field_name.t list ->
  selector:[ `raw ] Domain_name.t ->
  ?algorithm:algorithm ->
  ?hash:hash ->
  ?canonicalization:canonicalization * canonicalization ->
  ?length:int ->
  ?query:query ->
  ?timestamp:int64 ->
  ?expiration:int64 ->
  [ `raw ] Domain_name.t ->
  unsigned t
(** [v ~selector domain] creates an unsigned DKIM record for the given [domain]
    and [selector]. The selector determines which DNS TXT record (published at
    [selector._domainkey.domain]) holds the corresponding public key.

    Optional parameters let you override the defaults:

    - [version] must be [1] (the only version defined by the RFC).
    - [fields] lists the header field names to include in the signature; it
      defaults to [[From]] and [From] is always included even if omitted.
    - [algorithm] defaults to [`RSA].
    - [hash] defaults to [`SHA256]. [canonicalization] is a pair of
      [(header, body)] methods, defaulting to [(`Relaxed, `Relaxed)].
    - [length] restricts the number of body octets covered by the signature.
      (this parameter is {b not} supported)
    - [query] defaults to [`DNS `TXT].
    - [timestamp] and [expiration] are Unix timestamps expressed as [int64]
      values. *)

(** {1 Accessors} *)

val fields : 'a t -> Mrmime.Field_name.t list
(** [fields dkim] returns the list of header field names that are (or will be)
    included in the signature. *)

val timestamp : 'a t -> int64 option
(** [timestamp dkim] returns the signature creation time, if present. The value
    is a Unix timestamp. *)

val expire : 'a t -> int64 option
(** [expire dkim] returns the signature expiration time, if present. A verifier
    should treat the signature as invalid after this time. *)

val body : signed t -> string
(** [body dkim] returns the raw hash of the canonicalized body as recorded in
    the signed DKIM record (the [bh=] tag). *)

val domain : 'a t -> [ `raw ] Domain_name.t
(** [domain dkim] returns the signing domain identity (the [d=] tag). *)

val selector : 'a t -> [ `raw ] Domain_name.t
(** [selector dkim] returns the selector (the [s=] tag) used to locate the
    public key in DNS. *)

val domain_name : 'a t -> ([ `raw ] Domain_name.t, [> `Msg of string ]) result
(** [domain_name dkim] computes the full DNS name used to retrieve the public
    key: [selector._domainkey.domain]. Returns an error if the resulting domain
    name is invalid. *)

val canonicalization : 'a t -> canonicalization * canonicalization
(** [canonicalization dkim] returns the pair [(header_canon, body_canon)] of
    canonicalization algorithms declared in the DKIM record. *)

val hash_algorithm : 'a t -> hash_algorithm
(** [hash_algorithm dkim] returns the hash algorithm used for digesting. *)

val signature_and_hash : 'signed t -> 'signed
(** [signature_and_hash dkim] returns the raw signature-and-hash payload carried
    by the record. For a [signed t], this is the pair of the signature bytes and
    the body hash. *)

val algorithm : 'a t -> algorithm
(** [algorithm dkim] returns the signature algorithm (RSA or ED25519). *)

(** {1 Parsing} *)

val of_string : string -> (signed t, [> `Msg of string ]) result
(** [of_string str] parses a DKIM-Signature header field value from the given
    string. The string should contain the tag-value list without the field name
    itself (that is, everything after ["DKIM-Signature:"]). *)

val of_unstrctrd : Unstrctrd.t -> (signed t, [> `Msg of string ]) result
(** [of_unstrctrd u] parses a DKIM-Signature from an {!Unstrctrd.t} value
    obtained from the [mrmime] header parser. *)

(** {1 Modifiers} *)

val with_canonicalization : 'a t -> canonicalization * canonicalization -> 'a t
(** [with_canonicalization dkim (hdr, body)] returns a copy of [dkim] with the
    canonicalization algorithms replaced. *)

val with_signature_and_hash : _ t -> 'signed -> 'signed t
(** [with_signature_and_hash dkim payload] returns a copy of [dkim] carrying the
    given signature-and-hash [payload]. This is used internally to transition
    between signed and unsigned states. *)

val with_selector : 'a t -> selector:[ `raw ] Domain_name.t -> 'a t
(** [with_selector dkim ~selector] returns a copy of [dkim] with the selector
    replaced. *)

val with_expiration : 'a t -> int64 option -> 'a t
(** [with_expiration dkim exp] returns a copy of [dkim] with the expiration time
    replaced. Pass [None] to remove the expiration. *)

(** {1 Domain keys} *)

type domain_key
(** A domain key is the public-side record published in DNS. It contains the
    public key material and metadata (acceptable hash algorithms, service types,
    flags) that a verifier needs. *)

val domain_key_of_string : string -> (domain_key, [> `Msg of string ]) result
(** [domain_key_of_string str] parses a domain key from the content of a DNS TXT
    record. The string is the raw value returned by the DNS resolver. *)

val domain_key_of_dkim : key:key -> _ t -> domain_key
(** [domain_key_of_dkim ~key dkim] constructs a {!domain_key} from a private key
    and a DKIM value. The resulting value is what you would publish in DNS so
    that verifiers can check signatures produced with [key]. *)

val domain_key_to_string : ?with_version:bool -> domain_key -> string
(** [domain_key_to_string ?with_version dk] serializes a domain key into the
    tag-value format expected in a DNS TXT record. [with_version] writes the
    domain-key version (by default) to [v=DKIM1]. *)

val equal_domain_key : domain_key -> domain_key -> bool
(** [equal_domain_key a b] is [true] if [a] and [b] carry the same public key
    material and metadata. *)

val public_key : domain_key -> string
(** [public_key dk] returns the raw DER-encoded public key bytes. *)

(** {1 Canonicalization}

    The [Canon] module applies the canonicalization algorithm specified in a
    DKIM record to header fields. Canonicalization transforms a header field
    into a deterministic byte sequence so that the same digest is produced by
    both the signer and the verifier, even if intermediate mail servers
    introduced minor formatting changes. *)
module Canon : sig
  val of_fields :
    'a t ->
    Mrmime.Field_name.t ->
    Unstrctrd.t ->
    ('b -> string -> 'b) ->
    'b ->
    'b
  (** [of_fields dkim field_name unstrctrd fn acc] canonicalizes the header
      field [(field_name, unstrctrd)] according to the header canonicalization
      method declared in [dkim], then folds the resulting bytes into [acc] using
      [fn]. *)

  val of_dkim_fields :
    'a t ->
    Mrmime.Field_name.t ->
    Unstrctrd.t ->
    ('b -> string -> 'b) ->
    'b ->
    'b
  (** [of_dkim_fields dkim field_name unstrctrd f acc] does the same as
      {!of_fields} but also strips the [b=] signature value from the header
      before canonicalizing. This is the special treatment that the
      DKIM-Signature header itself receives during verification: the signature
      tag must be empty when computing the digest that the signature covers. *)
end

(** {1 Digest computation}

    The [Digest] module computes the cryptographic digests that underlie a DKIM
    signature. A signature covers two digests: one over a selection of header
    fields (including the DKIM-Signature header with the [b=] tag emptied), and
    one over the canonicalized message body. *)
module Digest : sig
  type 'a dkim = 'a t
  (** Alias for the outer DKIM record type, re-exported inside [Digest] to avoid
      shadowing by the local [t]. *)

  (** An in-progress hash computation, existentially quantified over the hash
      algorithm. *)
  type 'k t = Digest : { m : ('k, 'ctx) impl; ctx : 'ctx } -> 'k t

  and ('k, 'ctx) impl = (module Digestif.S with type t = 'k and type ctx = 'ctx)
  (** A first-class module type pairing a {!module:Digestif} implementation with
      its key and context types. *)

  and ('signed, 'k) value = 'signed dkim * 'k t
  (** A pair of a DKIM record and its corresponding in-progress digest. The
      ['signed] parameter tracks whether the record is signed or unsigned. *)

  (** An existentially packed [(signed, 'k) value], hiding the hash type. *)
  and pack = Value : (signed, 'k) value -> pack

  val digest_fields :
    (Mrmime.Field_name.t * Unstrctrd.t) list ->
    Mrmime.Field_name.t * Unstrctrd.t * signed dkim * domain_key ->
    string * pack
  (** [digest_fields others (field_name, unstrctrd, dkim, domain_key)] computes
      the header digest. [others] is the list of all header fields (excluding
      DKIM-Signature) collected from the email. The function selects the fields
      listed in [dkim.h], canonicalizes them, appends the canonicalized
      DKIM-Signature header (with the [b=] tag removed), and returns the raw
      digest bytes together with an initialized body digest ready to receive
      body data. *)

  val digest_wsp :
    [< `CRLF | `Spaces of string ] list ->
    ('signed, 'k) value ->
    ('signed, 'k) value
  (** [digest_wsp payloads value] feeds whitespace and CRLF tokens into the body
      digest. Under relaxed canonicalization, runs of whitespace are collapsed
      to a single space. *)

  val digest_str : string -> ('signed, 'k) value -> ('signed, 'k) value
  (** [digest_str data value] feeds a chunk of body data (not whitespace) into
      the body digest. *)

  val verify :
    fields:string ->
    domain_key:domain_key ->
    (signed, 'k) value ->
    string * bool
  (** [verify ~fields ~domain_key value] finalizes the body digest and verifies
      the DKIM signature. [fields] is the raw header digest obtained from
      {!digest_fields}. Returns a pair [(body_hash, fields_valid)] where
      [body_hash] is the raw hash of the canonicalized body and [fields_valid]
      is [true] if the cryptographic signature over the headers is valid. *)
end

(** {1 Streaming verification}

    The [Verify] module implements a streaming state machine for verifying all
    DKIM signatures present in an email. You create a decoder, feed it data in
    chunks, and drive the state machine by repeatedly calling
    {!val:Verify.decode}. The state machine will ask you to provide more data
    ([`Await]), to resolve a DNS query for a public key ([`Query]), and
    eventually produces the list of verification results ([`Signatures]). *)
module Verify : sig
  type decoder
  (** The state of the verification decoder. *)

  type response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]
  (** The type of responses you provide to the decoder when it issues a
      [`Query]. [`Domain_key dk] supplies the public key retrieved from DNS.
      [`Expired] indicates the signature has expired. [`DNS_error msg] reports a
      DNS resolution failure. *)

  val domain_key : 'a t -> ([ `raw ] Domain_name.t, [> `Msg of string ]) result
  (** [domain_key dkim] computes the DNS name to query for the public key of the
      given DKIM record: [selector._domainkey.domain]. *)

  val response : decoder -> dkim:signed t -> response:response -> decoder
  (** [response decoder ~dkim ~response] provides the result of a DNS query back
      to the decoder. This must be called exactly once for each [`Query]
      returned by {!val:decode}, passing the same [dkim] value that was received
      in the query. *)

  val decoder : unit -> decoder
  (** [decoder ()] creates a fresh verification decoder. The decoder starts in
      the header extraction phase, waiting for data via {!src}. *)

  val src : decoder -> string -> int -> int -> decoder
  (** [src decoder buf off len] provides input data to the decoder. The
      substring [buf.[off] .. buf.[off+len-1]] is consumed. Passing [len = 0]
      signals end of input. *)

  (** The outcome of verifying a single DKIM signature. The [fields] flag is
      [true] when the cryptographic signature over the header fields is valid.
      The [body] string is the raw hash of the canonicalized body. *)
  type result =
    | Signature : {
        dkim : signed t;
        domain_key : domain_key;
        fields : bool;
        body : string;
      }
        -> result

  type decode =
    [ `Await of decoder
    | `Query of decoder * signed t
    | `Signatures of result list
    | `Malformed of string ]
  (** The type returned by {!val:decode} at each step.

      - [`Await decoder] means the decoder needs more input; call {!val:src}
        then {!val:decode} again.
      - [`Query (decoder, dkim)] means the decoder needs the public key for
        [dkim]; call {!val:domain_key} to get the DNS name, resolve it, then
        call {!val:response}.
      - [`Signatures results] means verification is complete.
      - [`Malformed msg] means the email could not be parsed. *)

  val decode : decoder -> decode
  (** [decode decoder] advances the state machine by one step. *)
end

(** {1 Encoding}

    The [Encoder] module provides {!Prettym} formatters for the individual
    components of a DKIM-Signature header field. The main entry point is
    {!val:Encoder.as_field}, which emits a complete [DKIM-Signature: ...] header
    line with proper folding for long values. *)
module Encoder : sig
  val algorithm : (algorithm * hash_algorithm) Prettym.t
  (** Formats the algorithm and hash (e.g. ["rsa-sha256"]). *)

  val domain : [ `raw ] Domain_name.t Prettym.t
  (** Formats a domain name for the [d=] tag. *)

  val selector : [ `raw ] Domain_name.t Prettym.t
  (** Formats a selector for the [s=] tag. *)

  val timestamp : int64 Prettym.t
  (** Formats a Unix timestamp for the [t=] tag. *)

  val expiration : int64 Prettym.t
  (** Formats an expiration time for the [x=] tag. *)

  val length : int Prettym.t
  (** Formats a body length for the [l=] tag. *)

  val signature : string Prettym.t
  (** Formats a base64-encoded signature for the [b=] tag. *)

  val dkim_signature : ?with_version:bool -> (string * hash_value) t Prettym.t
  (** Formats the tag-value list of a signed DKIM record (everything after the
      colon in a DKIM-Signature field). *)

  val as_field : ?with_version:bool -> (string * hash_value) t Prettym.t
  (** Formats a complete DKIM-Signature header field, including the field name,
      colon, properly folded tag-value list, and trailing newline. *)
end

(** {1 Streaming signing}

    The [Sign] module implements a streaming state machine for producing a DKIM
    signature. You create a signer from a private key and an unsigned DKIM
    record, feed it the raw email in chunks, and drive the state machine by
    calling {!val:Sign.sign}. When the entire email has been consumed, the state
    machine produces a [signed t] that can be rendered with {!Encoder.as_field}
    and prepended to the original email. *)
module Sign : sig
  type signer
  (** The state of the signing engine. *)

  type action =
    [ `Await of signer | `Malformed of string | `Signature of signed t ]
  (** The type returned by {!sign} at each step.

      [`Await signer] means the signer needs more input; call {!fill} then
      {!sign} again. [`Signature dkim] means signing is complete and [dkim]
      carries the computed signature. [`Malformed msg] means the email headers
      could not be parsed. *)

  val fill : signer -> string -> int -> int -> signer
  (** [fill signer buf off len] provides input data to the signer. Passing
      [len = 0] signals end of input. *)

  val sign : signer -> action
  (** [sign signer] advances the signing state machine by one step. *)

  val signer : key:key -> unsigned t -> signer
  (** [signer ~key dkim] creates a new signing engine. The [key] must match the
      algorithm declared in [dkim] (RSA key for [`RSA], Ed25519 key for
      [`ED25519]). *)
end

module Body = Body
module Decoder = Decoder

(** {1 Low-level utilities}

    The following values are exposed for advanced use cases such as building
    custom DKIM processing pipelines or integrating with other email
    authentication mechanisms (SPF, DMARC, ARC). *)

type map
(** An heterogeneous map holding the parsed tag-value pairs of a DKIM-Signature
    header field. *)

val field_dkim_signature : Mrmime.Field_name.t
(** The [DKIM-Signature] field name as a {!Mrmime.Field_name.t} value. *)

val remove_signature_of_dkim : Unstrctrd.t -> Unstrctrd.t
(** [remove_signature_of_dkim u] strips the [b=...] tag value from the
    unstructured representation [u] of a DKIM-Signature header. The [b=] tag key
    and its trailing semicolon are preserved; only the signature data between
    them is removed. This is the transformation required by the RFC before
    hashing the DKIM-Signature header itself. *)

val uniq : Unstrctrd.t -> Unstrctrd.t
(** [uniq u] collapses runs of consecutive whitespace in [u] into a single
    whitespace element, preserving the first one. *)

val trim : Unstrctrd.t -> Unstrctrd.t
(** [trim u] strips leading and trailing whitespace from [u] and collapses
    internal whitespace to a single space. *)

val of_unstrctrd_to_map : Unstrctrd.t -> (map, [> `Msg of string ]) result
(** [of_unstrctrd_to_map u] parses the unstructured content of a DKIM-Signature
    header into a heterogeneous {!map} of tag-value pairs. *)

val map_to_t : map -> (signed t, [> `Msg of string ]) result
(** [map_to_t map] converts a parsed tag-value {!map} into a typed [signed t]
    record. Returns an error if required tags are missing or values are
    malformed. *)

val get_key : string -> map -> string option
(** [get_key name map] looks up a tag by its single-character [name] in the
    heterogeneous [map]. Returns [None] if the tag is absent. This is useful for
    accessing non-standard or extension tags that are not represented by
    dedicated accessors. *)
