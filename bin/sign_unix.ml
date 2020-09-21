module UnixIO = Dkim.Sigs.Make (struct
    type +'a t = 'a
  end)

module Caml_flow = struct
  type backend = UnixIO.t

  type flow =
    { ic : in_channel
    ; buf : Buffer.t }

  let input flow buf off len =
    let len = Stdlib.input flow.ic buf off len in
    Buffer.add_string flow.buf (Bytes.sub_string buf off len) ;
    UnixIO.inj len
end

module Dns = struct
  include Dns_client_unix

  type backend = UnixIO.t

  let getaddrinfo t `TXT domain_name =
    match getaddrinfo t Dns.Rr_map.Txt domain_name with
    | Ok (_ttl, txtset) -> UnixIO.inj (Ok (Dns.Rr_map.Txt_set.elements txtset))
    | Error _ as err -> UnixIO.inj err
end

let ( <.> ) f g x = f (g x)

let unix =
  { Dkim.Sigs.bind = (fun x f -> f (UnixIO.prj x)); return = UnixIO.inj }

let reporter ppf =
  let report src level ~over k msgf =
    let k _ =
      over () ;
      k () in
    let with_metadata header _tags k ppf fmt =
      Format.kfprintf k ppf
        ("%a[%a]: " ^^ fmt ^^ "\n%!")
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src) in
    msgf @@ fun ?header ?tags fmt -> with_metadata header tags k ppf fmt in
  { Logs.report }

let () = Fmt_tty.setup_std_outputs ~style_renderer:`Ansi_tty ~utf_8:true ()

let () = Logs.set_reporter (reporter Fmt.stdout)

let () = Logs.set_level ~all:true (Some Logs.Debug)

let seed = Base64.decode_exn "Do8KdmOYnU7yzqDn3A3lJwwXPaa1NRdv6E9R2KgZyXg="

let priv_of_seed seed =
  let g =
    let seed = Cstruct.of_string seed in
    Mirage_crypto_rng.(create ~seed (module Fortuna)) in
  Mirage_crypto_pk.Rsa.generate ~g ~bits:2048 ()

let () =
  let stdin = { Caml_flow.ic= stdin; buf= Buffer.create 0x1000; } in
  let key = priv_of_seed seed in
  let dkim = Dkim.v ~selector:"admin" ((Domain_name.host_exn <.> Domain_name.of_string_exn) "x25519.net") in
  let dkim = UnixIO.prj (Dkim.sign ~key stdin unix (module Caml_flow) dkim) in
  Fmt.pr "%s" (Prettym.to_string ~new_line:"\n" Dkim.Encoder.as_field dkim) ;
  Fmt.pr "%s" (Buffer.contents stdin.Caml_flow.buf)
