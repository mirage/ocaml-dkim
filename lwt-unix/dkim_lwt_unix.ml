let src = Logs.Src.create "dkim-lwt-unix"

module Log = (val Logs.src_log src : Logs.LOG)
open Lwt.Infix

let ( % ) f g = fun x -> f (g x)

let response_of_dns_request ~dkim dns =
  match Dkim.Verify.domain_key dkim with
  | Error (`Msg msg) -> Lwt.return (`DNS_error msg)
  | Ok domain_name -> (
      Dns_client_lwt.getaddrinfo dns Dns.Rr_map.Txt domain_name >|= function
      | Ok (_ttl, txts) ->
          let txts =
            Dns.Rr_map.Txt_set.fold (fun elt acc -> elt :: acc) txts [] in
          let txts =
            List.map (String.concat "" % String.split_on_char ' ') txts in
          let txts = String.concat "" txts in
          begin
            match Dkim.domain_key_of_string txts with
            | Ok domain_key -> `Domain_key domain_key
            | Error (`Msg msg) -> `DNS_error msg
          end
      | Error (`Msg msg) -> `DNS_error msg)

let now () = Int64.of_float (Unix.gettimeofday ())

let expire dkim =
  match Dkim.expire dkim with None -> false | Some ts -> now () > ts

let verify ?(newline = `LF) dns seq =
  let decoder = Dkim.Verify.decoder () in
  let rec go decoder seq =
    match Dkim.Verify.decode decoder with
    | `Malformed msg -> Lwt.return_error (`Msg msg)
    | `Signatures sigs -> Lwt.return_ok sigs
    | `Query (decoder, dkim) when not (expire dkim) ->
        response_of_dns_request ~dkim dns >>= fun response ->
        let decoder = Dkim.Verify.response decoder ~dkim ~response in
        go decoder seq
    | `Query (decoder, dkim) ->
        let response = `Expired in
        let decoder = Dkim.Verify.response decoder ~dkim ~response in
        go decoder seq
    | `Await decoder -> (
        seq () >>= function
        | Lwt_seq.Nil ->
            let decoder = Dkim.Verify.src decoder String.empty 0 0 in
            go decoder seq
        | Lwt_seq.Cons (str, seq) when newline = `CRLF ->
            let decoder = Dkim.Verify.src decoder str 0 (String.length str) in
            go decoder seq
        | Lwt_seq.Cons (str, seq) ->
            let lines = String.split_on_char '\n' str in
            let str = String.concat "\r\n" lines in
            let decoder = Dkim.Verify.src decoder str 0 (String.length str) in
            go decoder seq) in
  go decoder seq

let sign ?(newline = `LF) ~key dkim seq =
  let signer = Dkim.Sign.signer ~key dkim in
  let rec go signer seq =
    match Dkim.Sign.sign signer with
    | `Malformed msg -> Lwt.return_error (`Msg msg)
    | `Signature dkim -> Lwt.return_ok dkim
    | `Await signer -> begin
        seq () >>= function
        | Lwt_seq.Nil ->
            let signer = Dkim.Sign.fill signer String.empty 0 0 in
            go signer seq
        | Lwt_seq.Cons (str, seq) when newline = `CRLF ->
            let signer = Dkim.Sign.fill signer str 0 (String.length str) in
            go signer seq
        | Lwt_seq.Cons (str, seq) ->
            let lines = String.split_on_char '\n' str in
            let str = String.concat "\r\n" lines in
            let signer = Dkim.Sign.fill signer str 0 (String.length str) in
            go signer seq
      end in
  go signer seq
