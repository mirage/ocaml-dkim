type 'a t
and signed
and unsigned

type algorithm = [ `RSA | `Ed25519 ]
type hash = [ `SHA1 | `SHA256 ]
type canonicalization = [ `Simple | `Relaxed ]
type query = [ `DNS of [ `TXT ] ]

type key =
  [ `Rsa of Mirage_crypto_pk.Rsa.priv
  | `Ed25519 of Mirage_crypto_ec.Ed25519.priv ]

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

val fields : 'a t -> Mrmime.Field_name.t list
val expire : 'a t -> int64 option
val body : signed t -> string
val domain : 'a t -> [ `raw ] Domain_name.t
val selector : 'a t -> [ `raw ] Domain_name.t
val domain_name : 'a t -> ([ `raw ] Domain_name.t, [> `Msg of string ]) result

type domain_key

val domain_key_of_string : string -> (domain_key, [> `Msg of string ]) result
val domain_key_of_dkim : key:key -> _ t -> domain_key
val domain_key_to_string : domain_key -> string
val equal_domain_key : domain_key -> domain_key -> bool

module Verify : sig
  type decoder
  type response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]

  val domain_key :
    signed t -> ([ `raw ] Domain_name.t, [> `Msg of string ]) result

  val response : decoder -> dkim:signed t -> response:response -> decoder
  val decoder : unit -> decoder
  val src : decoder -> string -> int -> int -> decoder

  type ('k, 'ctx) impl =
    (module Digestif.S with type t = 'k and type ctx = 'ctx)

  type result =
    | Signature : {
        dkim : signed t;
        domain_key : domain_key;
        fields : bool;
        body : 'k;
        hash : ('k, _) impl;
      }
        -> result

  type decode =
    [ `Await of decoder
    | `Query of decoder * signed t
    | `Signatures of result list
    | `Malformed of string ]

  val decode : decoder -> decode
end

module Encoder : sig
  val dkim_signature : signed t Prettym.t
  val as_field : signed t Prettym.t
end

module Sign : sig
  type signer

  type action =
    [ `Await of signer | `Malformed of string | `Signature of signed t ]

  val fill : signer -> string -> int -> int -> signer
  val sign : signer -> action
  val signer : key:key -> unsigned t -> signer
end

module Body = Body

(**/*)

type map

val remove_signature_of_dkim : Unstrctrd.t -> Unstrctrd.t
val parse_dkim_field_value : Unstrctrd.t -> (map, [> `Msg of string ]) result
