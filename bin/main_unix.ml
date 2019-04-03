let () = Printexc.record_backtrace true

module UnixIO = Dkim.Sigs.Make(struct type +'a t = 'a end)

module Caml_flow = struct
  type backend = UnixIO.t
  type flow = in_channel

  let input flow buf off len = UnixIO.inj (Pervasives.input flow buf off len)
end

module Udns = struct
  include Udns_client_unix

  type t = Uflow.t
  type backend = UnixIO.t

  let getaddrinfo t `TXT domain_name =
    match getaddrinfo t Udns.Rr_map.Txt domain_name with
    | Ok (_ttl, txtset) -> UnixIO.inj (Ok (Udns.Rr_map.Txt_set.elements txtset))
    | Error _ as err -> UnixIO.inj err
end

let ( <.> ) f g = fun x -> f (g x)

let unix =
  { Dkim.Sigs.bind= (fun x f -> f (UnixIO.prj x))
  ; return= UnixIO.inj }

let list_map3 f a b c =
  if List.length a <> List.length b && List.length b <> List.length c
  then Fmt.invalid_arg "list_iter3" ;
  let rec go a b c = match a, b, c with
    | a :: ra, b :: rb, c :: rc -> f a b c :: go ra rb rc
    | [], [], [] -> []
    | _ -> assert false in
  go a b c

let () =
  match Dkim.extract_dkim stdin unix (module Caml_flow) |> UnixIO.prj with
  | Error (`Msg err) -> Fmt.epr "Retrieve an error: %s.\n%!" err
  | Ok extracted ->
    let mvalues = List.map
        (fun (_, _, value) -> match Dkim.post_process_dkim value with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        extracted.Dkim.dkim_fields in

    let body = Dkim.extract_body stdin unix (module Caml_flow) ~prelude:extracted.Dkim.prelude in
    let body = UnixIO.prj body in

    let dns = Udns.create () in

    let svalues = List.map (UnixIO.prj <.> Dkim.extract_server dns unix (module Udns)) mvalues in
    let svalues = List.map
        (fun value -> let open Rresult.R in match value >>= Dkim.post_process_server with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        svalues in

    let ress =
      list_map3 (fun (raw_field_dkim, raw_dkim, _) dkim server ->
          Dkim.verify extracted.Dkim.fields (raw_field_dkim, raw_dkim) dkim server body)
        extracted.dkim_fields mvalues svalues in

    Fmt.pr "%a.\n%!" Fmt.(Dump.list bool) ress
