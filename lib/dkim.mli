module Refl : sig
  type ('a, 'b) t = Refl : ('a, 'a) t
end

module Body = Body
module Sigs = Sigs

module Map : sig
  type t
end

type (+'a, 'err) or_err = ('a, ([> Rresult.R.msg ] as 'err)) result

type newline = CRLF | LF

type dkim

type server

type body

type hash = V : 'k Digestif.hash -> hash

type value = H : 'k Digestif.hash * 'k Digestif.t -> value

val pp_dkim : dkim Fmt.t

val pp_server : server Fmt.t

type extracted = {
  dkim_fields : (Mrmime.Field_name.t * Unstrctrd.t * Map.t) list;
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

val post_process_dkim : Map.t -> (dkim, _) or_err
(** [post_process_dkim map] from an already parsed [DKIM-Signature] represented
    by {!Map.t}, we compute a post process analyze (check required/optional well
    formed values) and return a safe representation of [DKIM-Signature],
    {!dkim}, which can be used by {!verify}. *)

val selector : dkim -> string

val domain : dkim -> [ `host ] Domain_name.t

val extract_server :
  't ->
  'backend Sigs.state ->
  (module Sigs.DNS with type t = 't and type backend = 'backend) ->
  dkim ->
  ((Map.t, _) or_err, 'backend) Sigs.io
(** [extract_server dns state (module Dns) dkim] gets public-key noticed by
    [dkim] from authority server over DNS protocol (with Input/Output scheduler
    represented by [state] and primitives implemented by [(module Dns)]). *)

val post_process_server : Map.t -> (server, _) or_err
(** [post_process_server map] from an already parsed TXT record from a DNS
    service represented by {!Map.t}, we compute a post-process analyze (check
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
  dkim ->
  server ->
  body ->
  bool

(** / *)

val remove_signature_of_raw_dkim : Unstrctrd.t -> Unstrctrd.t

val relaxed_field_canonicalization :
  Mrmime.Field_name.t -> Unstrctrd.t -> (string -> unit) -> unit
