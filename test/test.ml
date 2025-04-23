let () = Mirage_crypto_rng_unix.use_default ()

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

let smtpapi__domainkey_sendgrid_info =
  "k=rsa; t=s; \
   p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPtW5iwpXVPiH5FzJ7Nrl8USzuY9zqqzjE0D1r04xDN6qwziDnmgcFNNfMewVKN2D1O+2J9N14hRprzByFwfQW76yojh54Xu3uSbQ3JP0A7k8o8GutRF8zbFUA8n0ZH2y0cIEjMliXY4W4LwPA7m4q0ObmvSjhd63O9d8z1XkUBwIDAQAB"

let s20150108__domainkey_github_com =
  "k=rsa; t=s; \
   p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDF3DepunKacQZV1E0etEESNkTOG1GlIDm03+1gscZ7Tf/Vsyy9OMsTkOHFPNcbe7iBpJUfo3eC0jJGeHw+EKtvT5Ed2yDpGBxpWX8/TSW7lBrIOul2/QXoyWYXv7/EqWld/NZ+tyndBRPW+q6M2gILPrjdl9A/0TBCRZdGiAJDkwIDAQAB"

let pf2014__domainkey_github_com =
  "v=DKIM1; k=rsa; t=y; \
   p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDaCCQ+CiOqRkMAM/Oi04Xjhnxv3bXkTtA8KXt49RKQExLCmBxRpMp0PMMI73noKL/bZwEXljPO8HIfzG43ntPp1QRBUpn1UEvbp1/rlWPUop3i1j6aUpjxYGHEEzgmT+ncLUBDEPO4n4Zzt36DG3ZcJaLhvKtRkk2off5XD+BMvQIDAQAB"

let google__domainkey_janestreet_com =
  "v=DKIM1; k=rsa; \
   p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZr8DcbuZ/BsBrNh7kyYIM6tO3Z4P3UQKuyKSN9nFmPlCmkYu7A6zm+069O3iwNUvyHwk+n67KyNzA6mC4B4/x/NHZ1gr6rXJoAha4ORxNPPpxUWKfYsCwnaSP9c8HgWOw4HigJReR5G1kiamGL+4BNy/WknWxT04E6I3c+KEOIQIDAQAB"

let sjc2__domainkey_discoursemail_com =
  [
    "v=DKIM1; k=rsa; \
     p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsTING4yp/RLlN2i+FnLNo1YJ3SQPvs9fAYIS+ykQRX/TZj0OEfrM9WtZLmy+5CwWQWYlJguWY6Fz02wmIdunxBfZ3bgd5NJHQBN76DIaNfiyLUudbYP5vdrcJG5TwymZ03TVtRtfpqocvKU7X/o9GQiTgeTKRRajK6CBirinlINTXnrwJOA6ZQ1A02SDHAAf/";
    "B+rSYQ3mx9vAd8JlXdD7sIFaWK4Sz3YPad6M4d1p+FWrZ94D0Z6RFPzl/Q+AN5QnVAyjCjVqaQ+QQoUW3TYFc7uaKwbDaATpPOadz7lXNqr9C+i4DNWSU+Lff48e9WQ6tt+MZTJWeaZtL8g9OfBdwIDAQAB";
  ]

let selector1__domainkey_arm_com =
  [
    "v=DKIM1; k=rsa; \
     p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxOd2LnopxcFzP7bDnyOvcA8X3CtmBkjG8Mtban/NIWzQh73PZMz4usZ3QNVWoVtomGPk8FBMhYTwIGao5WVFGjDaAr0+6QfeLSHtPGzkgm2Tqy7fb9sdCwxHPZSXF+s/7fyElWPaa8roYR2OgdGZw3vnzE++7jbc0Yf+md/2HuwIDAQAB; \
     n=1024,1450051522,1465862722";
  ]

let seed = Base64.decode_exn "Do8KdmOYnU7yzqDn3A3lJwwXPaa1NRdv6E9R2KgZyXg="

let priv_of_seed =
  let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
  Mirage_crypto_pk.Rsa.generate ~g ~bits:2048 ()

let mails =
  [
    (2, "raw/001.mail");
    (1, "raw/002.mail");
    (1, "raw/003.mail");
    (1, "raw/004.mail");
    (2, "raw/005.mail");
  ]

let expire dkim =
  match Dkim.expire dkim with
  | None -> false
  | Some ts -> Int64.of_float (Unix.gettimeofday ()) > ts

let gettxtrrecord extra domain_name =
  match Domain_name.to_strings domain_name with
  | [ "smtpapi"; "_domainkey"; "sendgrid"; "info" ] ->
      Ok [ smtpapi__domainkey_sendgrid_info ]
  | [ "s20150108"; "_domainkey"; "github"; "com" ] ->
      Ok [ s20150108__domainkey_github_com ]
  | [ "pf2014"; "_domainkey"; "github"; "com" ] ->
      Ok [ pf2014__domainkey_github_com ]
  | [ "google"; "_domainkey"; "janestreet"; "com" ] ->
      Ok [ google__domainkey_janestreet_com ]
  | [ "sjc2"; "_domainkey"; "discoursemail"; "com" ] ->
      Ok sjc2__domainkey_discoursemail_com
  | [ "selector1"; "_domainkey"; "arm"; "com" ] ->
      Ok selector1__domainkey_arm_com
  | _ ->
  match List.assoc_opt domain_name extra with
  | Some domain_key -> Ok domain_key
  | None -> Error (`Not_found domain_name)

let response_of_dns_request errored ~dkim dns =
  match Dkim.Verify.domain_key dkim with
  | Error (`Msg _msg) ->
      errored := `Invalid_domain_name dkim :: !errored ;
      `DNS_error "Invalid domain-name to retrive domain key"
  | Ok domain_name -> begin
      match gettxtrrecord dns domain_name with
      | Ok txts ->
          let txts = String.concat "" txts in
          begin
            match Dkim.domain_key_of_string txts with
            | Ok domain_key -> `Domain_key domain_key
            | Error (`Msg _msg) ->
                errored := `Invalid_domain_key txts :: !errored ;
                `DNS_error "Invalid domain key"
          end
      | Error err ->
          errored := err :: !errored ;
          `DNS_error "DNS error"
    end

let verify dns ic =
  let errored = ref [] in
  let expired = ref [] in
  let buf = Bytes.create 0x7ff in
  let rec go decoder =
    match Dkim.Verify.decode decoder with
    | `Malformed msg -> failwith msg
    | `Signatures sigs -> sigs
    | `Query (decoder, dkim) when not (expire dkim) ->
        let response = response_of_dns_request errored ~dkim dns in
        let decoder = Dkim.Verify.response decoder ~dkim ~response in
        go decoder
    | `Query (decoder, dkim) ->
        expired := dkim :: !expired ;
        let response = `Expired in
        let decoder = Dkim.Verify.response decoder ~dkim ~response in
        go decoder
    | `Await decoder ->
        let len = input ic buf 0 (Bytes.length buf) in
        let str = Bytes.sub_string buf 0 len in
        let str = String.split_on_char '\n' str in
        let str = String.concat "\r\n" str in
        Logs.debug (fun m -> m "+%d byte(s)" (String.length str)) ;
        let decoder = Dkim.Verify.src decoder str 0 (String.length str) in
        go decoder in
  let valided = go (Dkim.Verify.decoder ()) in
  (valided, !expired, !errored)

let test_verify (_trust, filename) =
  Alcotest.test_case filename `Quick @@ fun () ->
  let ic = open_in filename in
  let finally () = close_in ic in
  Fun.protect ~finally @@ fun () ->
  let valided, expired, errored = verify [] ic in
  Alcotest.(check int) "errored" (List.length errored) 0 ;
  Fmt.pr "%d valid dkim signature(s)\n%!" (List.length valided) ;
  Fmt.pr "%d expired dkim signature(s)\n%!" (List.length expired)

let copy oc ic =
  let buf = Bytes.create 0x7ff in
  let rec go () =
    let len = input ic buf 0 (Bytes.length buf) in
    if len > 0
    then begin
      output_string oc (Bytes.sub_string buf 0 len) ;
      go ()
    end in
  go ()

let test_sign (_trust, filename) =
  Alcotest.test_case filename `Quick @@ fun () ->
  let ic = open_in filename in
  let finally () = close_in ic in
  Fun.protect ~finally @@ fun () ->
  let buf = Bytes.create 0x7ff in
  let x25519 = Domain_name.of_string_exn "x25519.net" in
  let selector = Domain_name.of_string_exn "admin" in
  let dkim = Dkim.v ~selector x25519 in
  let rec go signer =
    match Dkim.Sign.sign signer with
    | `Malformed err -> failwith err
    | `Signature dkim -> dkim
    | `Await signer ->
        let len = input ic buf 0 (Bytes.length buf) in
        let str = Bytes.sub_string buf 0 len in
        let str = String.split_on_char '\n' str in
        let str = String.concat "\r\n" str in
        let signer = Dkim.Sign.fill signer str 0 (String.length str) in
        go signer in
  let key = `RSA priv_of_seed in
  let dkim = go (Dkim.Sign.signer ~key dkim) in
  Logs.debug (fun m -> m "email signed!") ;
  let oc = open_out (filename ^ ".signed") in
  let bbh = (Dkim.signature_and_hash dkim :> string * Dkim.hash_value) in
  let dkim = Dkim.with_signature_and_hash dkim bbh in
  output_string oc (Prettym.to_string ~new_line:"\n" Dkim.Encoder.as_field dkim) ;
  seek_in ic 0 ;
  copy oc ic ;
  close_out oc ;
  let domain_key = Dkim.domain_key_of_dkim ~key dkim in
  let domain_key = [ Dkim.domain_key_to_string domain_key ] in
  let domain_name = Result.get_ok (Dkim.domain_name dkim) in
  let ic = open_in (filename ^ ".signed") in
  let finally () = close_in ic in
  Fun.protect ~finally @@ fun () ->
  Logs.debug (fun m -> m "verify signed email.") ;
  let valided, expired, errored = verify [ (domain_name, domain_key) ] ic in
  Alcotest.(check bool) "valided" (List.length valided >= 1) true ;
  Alcotest.(check int) "errored" (List.length errored) 0 ;
  Fmt.pr "%d valid dkim signature(s)\n%!" (List.length valided) ;
  Fmt.pr "%d expired dkim signature(s)\n%!" (List.length expired)

let () =
  Alcotest.run "ocaml-dkim"
    [
      ("verify", List.map test_verify mails); ("sign", List.map test_sign mails);
    ]
