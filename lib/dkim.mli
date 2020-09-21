module Refl : sig
  type ('a, 'b) t = Refl : ('a, 'a) t
end

module Sigs = Sigs

type (+'a, 'err) or_err = ('a, ([> Rresult.R.msg ] as 'err)) result

type newline = CRLF | LF

type map

type signed
type unsigned

type 'a dkim

type server

type body

val pp_dkim : 'a dkim Fmt.t

val pp_server : server Fmt.t

type extracted = {
  dkim_fields : (Mrmime.Field_name.t * Unstrctrd.t * map) list;
  fields : (Mrmime.Field_name.t * Unstrctrd.t) list;
  prelude : string;
}

val extract_dkim :
  ?newline:newline ->
  'flow ->
  't Sigs.state ->
  (module Sigs.FLOW with type flow = 'flow and type backend = 't) ->
  ((extracted, _) or_err, 't) Sigs.io
(** [extract_dkim ?newline flow state (module Flow)] reads [flow] with
    Input/Output scheduler represented by [state] and primitives implemented by
    [(module Flow)]. [?newline] specifies kind of contents ([CRLF] from network
    or [LF] from database like {i maildir}).

    It tries to extract [DKIM-Signature] fields with value, others fields and
    give a prelude of the body of the e-mail (given by [flow]). *)

val post_process_dkim : map -> (signed dkim, _) or_err
(** [post_process_dkim map] from an already parsed [DKIM-Signature] represented
    by {!map}, we compute a post process analyze (check required/optional well
    formed values) and return a safe representation of [DKIM-Signature],
    {!dkim}, which can be used by {!verify}. *)

val selector : 'a dkim -> string

val domain : 'a dkim -> [ `host ] Domain_name.t

val extract_server :
  't ->
  'backend Sigs.state ->
  (module Sigs.DNS with type t = 't and type backend = 'backend) ->
  'a dkim ->
  ((map, _) or_err, 'backend) Sigs.io
(** [extract_server dns state (module Dns) dkim] gets public-key noticed by
    [dkim] from authority server over DNS protocol (with Input/Output scheduler
    represented by [state] and primitives implemented by [(module Dns)]). *)

val post_process_server : map -> (server, _) or_err
(** [post_process_server map] from an already parsed TXT record from a DNS
    service represented by {!map}, we compute a post-process analyze (check
    required/optional well formed values) and return a safe representation of
    public-key, {!server}, which can be used by {!verify}. *)

val extract_body :
  ?newline:newline ->
  'flow ->
  'backend Sigs.state ->
  (module Sigs.FLOW with type flow = 'flow and type backend = 'backend) ->
  prelude:string ->
  (body, 'backend) Sigs.io
(** [extract_body ?newline flow state (module Flow) ~prelude] extracts a thin
    representation of the body of the e-mail. Should follow {!extract_dkim} with
    [prelude] and with [flow], [state], [(module Flow)] and [?newline]
    arguments. It returns a {!body} which can be used by {!verify}. *)

val verify :
  (Mrmime.Field_name.t * Unstrctrd.t) list ->
  Mrmime.Field_name.t * Unstrctrd.t ->
  signed dkim ->
  server ->
  body ->
  bool

type algorithm = [ `RSA ]
type hash = [ `SHA1 | `SHA256 ]
type canonicalization = [ `Simple | `Relaxed ]
type query = [ `DNS of [ `TXT ] ]

val v :
  ?version:int ->
  ?fields:Mrmime.Field_name.t list ->
  selector:string ->
  ?algorithm:algorithm ->
  ?hash:hash ->
  ?canonicalization:(canonicalization * canonicalization) ->
  ?length:int ->
  ?query:query ->
  ?timestamp:int64 ->
  ?expiration:int64 ->
  [ `host ] Domain_name.t -> unsigned dkim

module Encoder : sig
  val dkim_signature : signed dkim Prettym.t
  val as_field : signed dkim Prettym.t
end

val sign :
  key:Mirage_crypto_pk.Rsa.priv ->
  ?newline:newline ->
  'flow ->
  't Sigs.state ->
  (module Sigs.FLOW with type flow = 'flow and type backend = 't) ->
  unsigned dkim -> (signed dkim, 't) Sigs.io

(** / *)

val remove_signature_of_raw_dkim : Unstrctrd.t -> Unstrctrd.t

val relaxed_field_canonicalization :
  Mrmime.Field_name.t -> Unstrctrd.t -> (string -> unit) -> unit

module Body = Body
