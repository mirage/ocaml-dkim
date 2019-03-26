module Refl : sig type ('a, 'b) t = Refl : ('a, 'a) t end

type raw = Mrmime.Unstructured.t
type noop = [ `CR of int | `CRLF | `LF of int | `WSP of string ]
type data = [ `Encoded of Mrmime.Encoded_word.t | `Text of string ]

val unfold : [ noop | data ] list -> (string list, [> Rresult.R.msg ]) result

module type FLOW =
  sig type flow val input : flow -> bytes -> int -> int -> int end

module Info : sig type 'a t = { name : string; pp : 'a Fmt.t } end
module Hmap : Hmap.S with type 'a Key.info = 'a Info.t

type newline = CRLF | LF

val extract_dkim :
  ?newline:newline ->
  'a ->
  (module FLOW with type flow = 'a) ->
  (string * (Mrmime.Field.t * string) list * Hmap.t list, Rresult.R.msg)
  Result.result

type dkim
and hash = V : 'k Digestif.hash -> hash
and value = H : 'k Digestif.hash * 'k Digestif.t -> value

val equal_hash : 'a Digestif.hash -> 'b Digestif.hash -> ('a, 'b) Refl.t option
val pp_dkim : dkim Fmt.t
val expected : dkim -> value

module Simple_body : sig
  type decode = [ `Await | `CRLF | `Data of string | `End | `Spaces of string ]

  type decoder

  val src : decoder -> bytes -> int -> int -> unit
  val decode : decoder -> decode
  val decoder : unit -> decoder
end

val post_process_dkim : Hmap.t -> (dkim, [ `Msg of string ]) result

val digest_fields : (Mrmime.Field.t * String.t) list -> dkim -> value

type iter = string Digestif.iter
type body = { relaxed : iter; simple : iter; }

val digest_body :
  ?newline:newline -> 'a ->
  (module FLOW with type flow = 'a) ->
  string -> body

val body_hash_of_dkim : body -> dkim -> value
