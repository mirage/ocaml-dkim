let () = Printexc.record_backtrace true

module LwtIO = Dkim.Sigs.Make(struct type +'a t = 'a Lwt.t end)

module Udns = struct
  include Udns_client_lwt

  type t = Udns_client_lwt.Uflow.t
  type backend = LwtIO.t

  let getaddrinfo t `TXT domain_name =
    let open Lwt.Infix in
    (getaddrinfo t Udns.Rr_map.Txt domain_name >|= function
      | Ok (_ttl, txtset) -> (Ok (Udns.Rr_map.Txt_set.elements txtset))
      | Error _ as err -> err)
    |> LwtIO.inj
end

module Lwt_flow = struct
  type backend = LwtIO.t
  type flow = Lwt_io.input_channel

  let input flow buf off len = LwtIO.inj (Lwt_io.read_into flow buf off len)
end

let ( <.> ) f g = fun x -> f (g x)

let lwt_bind x f =
  let open Lwt.Infix in
  LwtIO.inj (LwtIO.prj x >>= (LwtIO.prj <.> f))

let lwt =
  { Dkim.Sigs.bind= lwt_bind
  ; return= (fun x -> LwtIO.inj (Lwt.return x)) }

let list_map3 f a b c =
  if List.length a <> List.length b && List.length b <> List.length c
  then Fmt.invalid_arg "list_iter3" ;
  let rec go a b c = match a, b, c with
    | a :: ra, b :: rb, c :: rc -> f a b c :: go ra rb rc
    | [], [], [] -> []
    | _ -> assert false in
  go a b c

let main () =
  let open Lwt.Infix in

  Dkim.extract_dkim Lwt_io.stdin lwt (module Lwt_flow) |> LwtIO.prj >>= function
  | Error (`Msg err) -> Fmt.epr "Retrieve an error: %s.\n%!" err ; Lwt.return ()
  | Ok extracted ->
    let mvalues = List.map
        (fun (_, _, value) -> match Dkim.post_process_dkim value with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        extracted.Dkim.dkim_fields in
    Dkim.extract_body Lwt_io.stdin lwt (module Lwt_flow) ~prelude:extracted.Dkim.prelude
    |> LwtIO.prj >>= fun body ->

    let dns = Udns.create () in

    Lwt_list.map_p (LwtIO.prj <.> Dkim.extract_server dns lwt (module Udns)) mvalues
    >>= fun svalues ->

    let svalues = List.map
        (fun value -> let open Rresult.R in match value >>= Dkim.post_process_server with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        svalues in

    let ress =
      list_map3 (fun (raw_field_dkim, raw_dkim, _) dkim server ->
          Dkim.verify extracted.Dkim.fields (raw_field_dkim, raw_dkim) dkim server body)
        extracted.dkim_fields mvalues svalues in

    Fmt.pr "%a.\n%!" Fmt.(Dump.list bool) ress ; Lwt.return ()

let () = Lwt_main.run (main ())
