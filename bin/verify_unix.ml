let () = Printexc.record_backtrace true

module UnixIO = Dkim.Sigs.Make (struct
  type +'a t = 'a
end)

module Caml_flow = struct
  type backend = UnixIO.t

  type flow = in_channel

  let input flow buf off len = UnixIO.inj (Stdlib.input flow buf off len)
end

let seed = Base64.decode_exn "Do8KdmOYnU7yzqDn3A3lJwwXPaa1NRdv6E9R2KgZyXg="

let pub_of_seed seed =
  let g =
    let seed = Cstruct.of_string seed in
    Mirage_crypto_rng.(create ~seed (module Fortuna)) in
  let key = Mirage_crypto_pk.Rsa.generate ~g ~bits:2048 () in
  let public = Mirage_crypto_pk.Rsa.pub_of_priv key in
  Cstruct.to_string (X509.Public_key.encode_der (`RSA public))

module Dns = struct
  include Dns_client_unix

  type backend = UnixIO.t

  let getaddrinfo t `TXT domain_name =
    match Domain_name.to_string domain_name with
    | "admin._domainkey.x25519.net" ->
      let str = Fmt.strf "k=rsa; p=%s" (Base64.encode_exn ~pad:true (pub_of_seed seed)) in
      UnixIO.inj (Ok [ str ])
    | _ ->
      match getaddrinfo t Dns.Rr_map.Txt domain_name with
      | Ok (_ttl, txtset) -> UnixIO.inj (Ok (Dns.Rr_map.Txt_set.elements txtset))
      | Error _ as err -> UnixIO.inj err
end

let ( <.> ) f g x = f (g x)

let unix =
  { Dkim.Sigs.bind = (fun x f -> f (UnixIO.prj x)); return = UnixIO.inj }

let list_map3 f a b c =
  if List.length a <> List.length b && List.length b <> List.length c
  then Fmt.invalid_arg "list_iter3" ;
  let rec go a b c =
    match (a, b, c) with
    | a :: ra, b :: rb, c :: rc -> f a b c :: go ra rb rc
    | [], [], [] -> []
    | _ -> assert false in
  go a b c

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

let () =
  match Dkim.extract_dkim stdin unix (module Caml_flow) |> UnixIO.prj with
  | Error (`Msg err) -> Fmt.epr "Retrieve an error: %s.\n%!" err
  | Ok extracted ->
      let mvalues =
        List.map
          (fun (_, _, value) ->
            match Dkim.post_process_dkim value with
            | Ok value -> value
            | Error (`Msg err) -> invalid_arg err)
          extracted.Dkim.dkim_fields in

      let body =
        Dkim.extract_body stdin unix
          (module Caml_flow)
          ~prelude:extracted.Dkim.prelude in
      let body = UnixIO.prj body in

      let dns = Dns.create () in

      let svalues =
        List.map
          (UnixIO.prj <.> Dkim.extract_server dns unix (module Dns))
          mvalues in
      let svalues =
        List.map
          (fun value ->
            let open Rresult.R in
            match value >>= Dkim.post_process_server with
            | Ok value -> value
            | Error (`Msg err) -> invalid_arg err)
          svalues in

      let ress =
        list_map3
          (fun (raw_field_dkim, raw_dkim, _) dkim server ->
            Dkim.verify extracted.Dkim.fields (raw_field_dkim, raw_dkim) dkim
              server body)
          extracted.dkim_fields mvalues svalues in

      Fmt.pr "%a.\n%!" Fmt.(Dump.list bool) ress
