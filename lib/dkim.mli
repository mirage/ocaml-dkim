type algorithm = [ `RSA | `ED25519 ]
type hash = [ `SHA1 | `SHA256 ]
type canonicalization = [ `Simple | `Relaxed ]
type query = [ `DNS of [ `TXT ] ]
type hash_algorithm = Hash_algorithm : 'k Digestif.hash -> hash_algorithm
type hash_value = Hash_value : 'k Digestif.hash * 'k Digestif.t -> hash_value

type 'a t
and signed = private string * hash_value
and unsigned

type key =
  [ `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]

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
val canonicalization : 'a t -> canonicalization * canonicalization
val hash_algorithm : 'a t -> hash_algorithm
val signature_and_hash : 'signed t -> 'signed
val algorithm : 'a t -> algorithm
val of_string : string -> (signed t, [> `Msg of string ]) result
val of_unstrctrd : Unstrctrd.t -> (signed t, [> `Msg of string ]) result
val with_canonicalization : 'a t -> canonicalization * canonicalization -> 'a t
val with_signature_and_hash : _ t -> 'signed -> 'signed t

type domain_key

val domain_key_of_string : string -> (domain_key, [> `Msg of string ]) result
val domain_key_of_dkim : key:key -> _ t -> domain_key
val domain_key_to_string : domain_key -> string
val equal_domain_key : domain_key -> domain_key -> bool
val public_key : domain_key -> string

module Canon : sig
  val of_fields :
    'a t ->
    Mrmime.Field_name.t ->
    Unstrctrd.t ->
    ('b -> string -> 'b) ->
    'b ->
    'b

  val of_dkim_fields :
    'a t ->
    Mrmime.Field_name.t ->
    Unstrctrd.t ->
    ('b -> string -> 'b) ->
    'b ->
    'b
end

module Digest : sig
  type 'a dkim = 'a t

  type 'k t = Digest : { m : ('k, 'ctx) impl; ctx : 'ctx } -> 'k t
  and ('k, 'ctx) impl = (module Digestif.S with type t = 'k and type ctx = 'ctx)
  and ('signed, 'k) value = 'signed dkim * 'k t
  and pack = Value : (signed, 'k) value -> pack

  val digest_fields :
    (Mrmime.Field_name.t * Unstrctrd.t) list ->
    Mrmime.Field_name.t * Unstrctrd.t * signed dkim * domain_key ->
    string * pack

  val digest_wsp :
    [< `CRLF | `Spaces of string ] list ->
    ('signed, 'k) value ->
    ('signed, 'k) value

  val digest_str : string -> ('signed, 'k) value -> ('signed, 'k) value

  val verify :
    fields:string ->
    domain_key:domain_key ->
    (signed, 'k) value ->
    string * bool
end

module Verify : sig
  type decoder
  type response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]

  val domain_key : 'a t -> ([ `raw ] Domain_name.t, [> `Msg of string ]) result
  val response : decoder -> dkim:signed t -> response:response -> decoder
  val decoder : unit -> decoder
  val src : decoder -> string -> int -> int -> decoder

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

  val decode : decoder -> decode
end

module Encoder : sig
  val algorithm : (algorithm * hash_algorithm) Prettym.t
  val domain : [ `raw ] Domain_name.t Prettym.t
  val selector : [ `raw ] Domain_name.t Prettym.t
  val timestamp : int64 Prettym.t
  val expiration : int64 Prettym.t
  val length : int Prettym.t
  val signature : string Prettym.t
  val dkim_signature : (string * hash_value) t Prettym.t
  val as_field : (string * hash_value) t Prettym.t
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
module Decoder = Decoder

(**/*)

type map

val field_dkim_signature : Mrmime.Field_name.t
val remove_signature_of_dkim : Unstrctrd.t -> Unstrctrd.t
val uniq : Unstrctrd.t -> Unstrctrd.t
val trim : Unstrctrd.t -> Unstrctrd.t
val of_unstrctrd_to_map : Unstrctrd.t -> (map, [> `Msg of string ]) result
val map_to_t : map -> (signed t, [> `Msg of string ]) result
val get_key : string -> map -> string option
