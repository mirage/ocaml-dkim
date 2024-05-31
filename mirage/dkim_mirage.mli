type 'a stream = unit -> 'a option Lwt.t

module Make (P : Mirage_clock.PCLOCK) (D : Dns_client_mirage.S) : sig
  type nameserver =
    [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]

  val server :
    D.t -> 'a Dkim.dkim -> (Dkim.server, [> `Msg of string ]) result Lwt.t

  val verify :
    ?newline:Dkim.newline ->
    (string * int * int) stream ->
    D.t ->
    ( Dkim.signed Dkim.dkim list * Dkim.signed Dkim.dkim list,
      [> `Msg of string ] )
    result
    Lwt.t
end

val sign :
  key:Mirage_crypto_pk.Rsa.priv ->
  ?newline:Dkim.newline ->
  (string * int * int) stream ->
  Dkim.unsigned Dkim.dkim ->
  (Dkim.signed Dkim.dkim * (string * int * int) stream) Lwt.t
