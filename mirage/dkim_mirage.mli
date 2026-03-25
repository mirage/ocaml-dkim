(** DKIM verification and signing for MirageOS.

    This module provides high-level DKIM operations suitable for use inside a
    MirageOS unikernel. It is parameterized over a DNS client implementation
    from {{:https://github.com/mirage/ocaml-dns} ocaml-dns} so that it can
    work with whatever network stack the unikernel provides. DNS queries for
    public keys and expiration checks are handled automatically. *)

(** Functor that produces [verify] and [sign] functions for a given DNS
    client implementation. *)
module Make (D : Dns_client_mirage.S) : sig

  (** [verify ?newline dns stream] reads an email from [stream], extracts
      every DKIM-Signature header, resolves the corresponding public keys
      through [dns], and returns the list of verification results.

      [newline] controls how line endings in the input are interpreted.
      [`LF] (the default) means the stream uses Unix-style ['\n'] line
      endings, which are converted to CRLF internally as required by the
      RFC. [`CRLF] means the stream already uses CRLF and no conversion is
      performed.

      Returns an error if the email headers are malformed. *)
  val verify :
    ?newline:[ `LF | `CRLF ] ->
    D.t ->
    string Lwt_stream.t ->
    (Dkim.Verify.result list, [> `Msg of string ]) result Lwt.t

  (** [sign ?newline ~key dkim stream] reads an email from [stream] and
      computes a DKIM signature using the private [key] and the parameters in
      the unsigned [dkim] record.

      [newline] has the same meaning as in {!verify}.

      On success, returns a [signed Dkim.t] that can be rendered with
      {!Dkim.Encoder.as_field} and prepended to the original email. *)
  val sign :
    ?newline:[ `LF | `CRLF ] ->
    key:Dkim.key ->
    Dkim.unsigned Dkim.t ->
    string Lwt_stream.t ->
    (Dkim.signed Dkim.t, [> `Msg of string ]) result Lwt.t
end
