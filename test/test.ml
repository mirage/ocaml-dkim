let smtpapi__domainkey_sendgrid_info =
  "k=rsa; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPtW5iwpXVPiH5FzJ7Nrl8USzuY9zqqzjE0D1r04xDN6qwziDnmgcFNNfMewVKN2D1O+2J9N14hRprzByFwfQW76yojh54Xu3uSbQ3JP0A7k8o8GutRF8zbFUA8n0ZH2y0cIEjMliXY4W4LwPA7m4q0ObmvSjhd63O9d8z1XkUBwIDAQAB"

let s20150108__domainkey_github_com =
  "k=rsa; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDF3DepunKacQZV1E0etEESNkTOG1GlIDm03+1gscZ7Tf/Vsyy9OMsTkOHFPNcbe7iBpJUfo3eC0jJGeHw+EKtvT5Ed2yDpGBxpWX8/TSW7lBrIOul2/QXoyWYXv7/EqWld/NZ+tyndBRPW+q6M2gILPrjdl9A/0TBCRZdGiAJDkwIDAQAB"

let pf2014__domainkey_github_com =
  "v=DKIM1; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDaCCQ+CiOqRkMAM/Oi04Xjhnxv3bXkTtA8KXt49RKQExLCmBxRpMp0PMMI73noKL/bZwEXljPO8HIfzG43ntPp1QRBUpn1UEvbp1/rlWPUop3i1j6aUpjxYGHEEzgmT+ncLUBDEPO4n4Zzt36DG3ZcJaLhvKtRkk2off5XD+BMvQIDAQAB"

let google__domainkey_janestreet_com =
  "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZr8DcbuZ/BsBrNh7kyYIM6tO3Z4P3UQKuyKSN9nFmPlCmkYu7A6zm+069O3iwNUvyHwk+n67KyNzA6mC4B4/x/NHZ1gr6rXJoAha4ORxNPPpxUWKfYsCwnaSP9c8HgWOw4HigJReR5G1kiamGL+4BNy/WknWxT04E6I3c+KEOIQIDAQAB"

let mails =
  [ "raw/001.mail"
  ; "raw/002.mail"
  ; "raw/003.mail" ]

module Unix_scheduler = Dkim.Sigs.Make(struct type +'a t = 'a end)
module Caml_flow = struct
  type backend = Unix_scheduler.t
  type flow = in_channel

  let input flow buf off len = Unix_scheduler.inj (Pervasives.input flow buf off len)
end

module Fake_resolver = struct
  type t = unit
  type backend = Unix_scheduler.t
  type error = [ `Not_found ]

  let getaddrinfo () `TXT domain_name = match Domain_name.to_strings domain_name with
    | [ "smtpapi"; "_domainkey"; "sendgrid"; "info" ] ->
      Unix_scheduler.inj (Ok [ smtpapi__domainkey_sendgrid_info ])
    | [ "s20150108"; "_domainkey"; "github"; "com" ] ->
      Unix_scheduler.inj (Ok [ s20150108__domainkey_github_com ])
    | [ "pf2014"; "_domainkey"; "github"; "com" ] ->
      Unix_scheduler.inj (Ok [ pf2014__domainkey_github_com ])
    | [ "google"; "_domainkey"; "janestreet"; "com" ] ->
      Unix_scheduler.inj (Ok [ google__domainkey_janestreet_com ])
    | _ ->
      Unix_scheduler.inj (Rresult.R.error_msgf "domain %a does not exists"
                            Fmt.(Dump.list string)
                            (Domain_name.to_strings domain_name))
end

let unix =
  { Dkim.Sigs.bind= (fun x f -> f (Unix_scheduler.prj x))
  ; return= Unix_scheduler.inj }

let unzip l =
  let rec go (ra, rb) = function
    | [] -> List.rev ra, List.rev rb
    | (a, b) :: r -> go (a :: ra, b :: rb) r in
  go ([], []) l

let verify ic =
  let errors = ref [] in

  match Dkim.extract_dkim ic unix (module Caml_flow) |> Unix_scheduler.prj with
  | Error _ as err -> err
  | Ok extracted ->
    let dkim_fields =
      List.fold_left
        (fun a (field, raw, value) -> match Dkim.post_process_dkim value with
           | Ok value -> (field, raw, value) :: a
           | Error _ -> errors := `Dkim_field raw :: !errors; a)
        [] extracted.Dkim.dkim_fields in
    let body = Dkim.extract_body ic unix (module Caml_flow) ~prelude:extracted.Dkim.prelude in
    let body = Unix_scheduler.prj body in

    let server_keys =
      List.map
        (fun (_, _, value) -> Unix_scheduler.prj (Dkim.extract_server () unix (module Fake_resolver) value))
        dkim_fields in

    let server_keys, dkim_fields =
      List.fold_left2
        (fun a server_key ((_, _, _) as dkim_field) ->
           let open Rresult.R in match server_key >>= Dkim.post_process_server with
           | Ok server_key -> (server_key, dkim_field) :: a
           | Error (`Msg err) -> errors := `Server err :: !errors ; a)
        [] server_keys dkim_fields
      |> unzip in

    let ress =
      List.map2 (fun (raw_field_dkim, raw_dkim, dkim) server_key ->
          Dkim.domain dkim, Dkim.verify extracted.Dkim.fields (raw_field_dkim, raw_dkim) dkim server_key body)
        dkim_fields server_keys in

    match !errors with
    | [] -> Ok ress
    | errors ->
      List.iter
        (function
          | `Dkim_field _ -> Fmt.epr "Invalid DKIM-field.\n%!"
          | `Server err -> Fmt.epr "%s.\n%!" err)
        errors ;
      Error (`Msg "Got errors while computing inputs")

let test filename =
  Alcotest.test_case filename `Quick @@ fun () ->
  let ic = open_in filename in
  let rs = verify ic in
  close_in ic ; match rs with
  | Ok rs ->
    List.iter
      (fun (domain, res) -> Alcotest.(check bool) (Domain_name.to_string domain) res true)
      rs
  | Error (`Msg err) -> Alcotest.fail err

let () =
  Alcotest.run "ocaml-dkim"
    [ "tests", List.map test mails ]
