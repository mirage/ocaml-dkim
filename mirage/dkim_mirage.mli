module Make (P : Mirage_clock.PCLOCK) (D : Dns_client_mirage.S) : sig
  val verify :
    ?newline:[ `LF | `CRLF ] ->
    D.t ->
    string Lwt_stream.t ->
    (Dkim.Verify.result list, [> `Msg of string ]) result Lwt.t

  val sign :
    ?newline:[ `LF | `CRLF ] ->
    key:Dkim.key ->
    Dkim.unsigned Dkim.t ->
    string Lwt_stream.t ->
    (Dkim.signed Dkim.t, [> `Msg of string ]) result Lwt.t
end
