module Refl : sig type ('a, 'b) t = Refl : ('a, 'a) t end
module Body = Body
module Sigs = Sigs

type raw = Mrmime.Unstructured.t
type noop = [ `CR of int | `CRLF | `LF of int | `WSP of string ]
type data = [ `Encoded of Mrmime.Encoded_word.t | `Text of string ]

val unfold : [ noop | data ] list -> (string list, [> Rresult.R.msg ]) result

module Hmap : sig type t end
type newline = CRLF | LF

val extract_dkim :
  ?newline:newline ->
  'flow ->
  't Sigs.state ->
  (module Sigs.FLOW with type flow = 'flow and type backend = 't) ->
  ((string * (Mrmime.Field.t * string) list * Hmap.t list, Rresult.R.msg) result, 't) Sigs.io

type dkim and server
and hash = V : 'k Digestif.hash -> hash
and value = H : 'k Digestif.hash * 'k Digestif.t -> value

val equal_hash : 'a Digestif.hash -> 'b Digestif.hash -> ('a, 'b) Refl.t option
val pp_dkim : dkim Fmt.t
val pp_server : server Fmt.t
val expected : dkim -> value

val extract_server :
  't ->
  'backend Sigs.state ->
  (module Sigs.DNS with type t = 't and type backend = 'backend) ->
  dkim ->
  ((Hmap.t, Rresult.R.msg) result, 'backend) Sigs.io

val post_process_dkim : Hmap.t -> (dkim, [ `Msg of string ]) result
val post_process_server : Hmap.t -> (server, [ `Msg of string ]) result

val digest_fields : (Mrmime.Field.t * String.t) list -> dkim -> value

type iter = string Digestif.iter
type body = { relaxed : iter; simple : iter; }

val digest_body :
  ?newline:newline -> 'flow -> 'backend Sigs.state ->
  (module Sigs.FLOW with type flow = 'flow and type backend = 'backend) ->
  string -> (body, 'backend) Sigs.io

val body_hash_of_dkim : body -> dkim -> value
