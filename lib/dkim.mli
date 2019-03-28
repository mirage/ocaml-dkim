module Refl : sig type ('a, 'b) t = Refl : ('a, 'a) t end
module Body = Body
module Sigs = Sigs
module Map : sig type t end

type raw = Mrmime.Unstructured.t
type noop = [ `CR of int | `CRLF | `LF of int | `WSP of string ]
type data = [ `Encoded of Mrmime.Encoded_word.t | `Text of string ]
type 'a or_err = ('a, Rresult.R.msg) result

val unfold : [ noop | data ] list -> string list or_err

type newline = CRLF | LF

type dkim
type server
type hash = V : 'k Digestif.hash -> hash
type value = H : 'k Digestif.hash * 'k Digestif.t -> value

val expected : dkim -> value
val equal_hash : 'a Digestif.hash -> 'b Digestif.hash -> ('a, 'b) Refl.t option

val pp_dkim : dkim Fmt.t
val pp_server : server Fmt.t

type extracted =
  { dkim_fields : (Mrmime.Field.t * raw * Map.t) list
  ; fields : (Mrmime.Field.t * string) list
  ; prelude : string }

val extract_dkim :
  ?newline:newline ->
  'flow ->
  't Sigs.state ->
  (module Sigs.FLOW with type flow = 'flow and type backend = 't) ->
  (extracted or_err, 't) Sigs.io

val post_process_dkim : Map.t -> dkim or_err

val extract_server :
  't ->
  'backend Sigs.state ->
  (module Sigs.DNS with type t = 't and type backend = 'backend) ->
  dkim ->
  (Map.t or_err, 'backend) Sigs.io

val post_process_server : Map.t -> server or_err

val digest_fields : (Mrmime.Field.t * string) list -> dkim -> value

type body

val digest_body :
  ?newline:newline -> 'flow -> 'backend Sigs.state ->
  (module Sigs.FLOW with type flow = 'flow and type backend = 'backend) ->
  prelude:string -> (body, 'backend) Sigs.io

val body_hash_of_dkim : body -> dkim -> value
val remove_signature_of_raw_dkim : raw -> raw
val verify : (Mrmime.Field.t * string) list -> (Mrmime.Field.t * raw) -> dkim -> server -> body -> bool
