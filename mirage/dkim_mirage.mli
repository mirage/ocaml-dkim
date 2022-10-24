type 'a stream = unit -> 'a option Lwt.t

module Make
    (R : Mirage_random.S)
    (T : Mirage_time.S)
    (C : Mirage_clock.MCLOCK)
    (P : Mirage_clock.PCLOCK)
    (S : Tcpip.Stack.V4V6) : sig
  type nameserver =
    [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]

  val server :
    S.t ->
    ?cache_size:int ->
    ?nameservers:Dns.proto * nameserver list ->
    ?timeout:int64 ->
    'a Dkim.dkim ->
    (Dkim.server, [> `Msg of string ]) result Lwt.t

  val verify :
    ?newline:Dkim.newline ->
    ?cache_size:int ->
    ?nameservers:Dns.proto * nameserver list ->
    ?timeout:int64 ->
    (string * int * int) stream ->
    S.t ->
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
