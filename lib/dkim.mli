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

type hash_algorithm = Hash_algorithm : 'k Digestif.hash -> hash_algorithm
type hash_value = Hash_value : 'k Digestif.hash * 'k Digestif.t -> hash_value

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
val signature_and_hash : signed t -> string * hash_value
val algorithm : 'a t -> algorithm
val of_string : string -> (signed t, [> `Msg of string ]) result
val of_unstrctrd : Unstrctrd.t -> (signed t, [> `Msg of string ]) result

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
  and 'k value = signed dkim * domain_key * 'k t
  and pack = Value : 'k value -> pack

  val digest_fields :
    (Mrmime.Field_name.t * Unstrctrd.t) list ->
    Mrmime.Field_name.t * Unstrctrd.t * signed dkim * domain_key ->
    string * pack

  val digest_wsp : [< `CRLF | `Spaces of string ] list -> 'a value -> 'a value
  val digest_str : string -> 'a value -> 'a value
  val verify : fields:string -> 'k value -> string * bool
end

module Verify : sig
  type decoder
  type response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]

  val domain_key :
    signed t -> ([ `raw ] Domain_name.t, [> `Msg of string ]) result

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
module Decoder = Decoder

(**/*)

type map

val field_dkim_signature : Mrmime.Field_name.t
val remove_signature_of_dkim : Unstrctrd.t -> Unstrctrd.t
val uniq : Unstrctrd.t -> Unstrctrd.t
val trim : Unstrctrd.t -> Unstrctrd.t
