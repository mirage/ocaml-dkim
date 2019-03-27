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
    match getaddrinfo t Udns_map.Txt domain_name with
    | Ok (_ttl, txtset) -> UnixIO.inj (Ok (Udns_map.TxtSet.elements txtset))
    | Error _ as err -> UnixIO.inj err
end

let ( <.> ) f g = fun x -> f (g x)

let unix =
  { Dkim.Sigs.bind= (fun x f -> f (UnixIO.prj x))
  ; return= UnixIO.inj }

let () =
  match Dkim.extract_dkim stdin unix (module Caml_flow) |> UnixIO.prj with
  | Error (`Msg err) -> Fmt.epr "Retrieve an error: %s.\n%!" err
  | Ok (prelude, _, values) ->
    let values = List.map
        (fun (value) -> match Dkim.post_process_dkim value with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        values in
    Fmt.pr "%a.\n%!" Fmt.(Dump.list Dkim.pp_dkim) values ;
    let body = Dkim.digest_body stdin unix (module Caml_flow) prelude in
    let body = UnixIO.prj body in
    let produced_hashes = List.map (Dkim.body_hash_of_dkim body) values in
    let expected_hashes = List.map Dkim.expected values in

    List.iter2
      (fun (Dkim.H (k, h)) (Dkim.H (k', h')) -> match Dkim.equal_hash k k' with
         | Some Dkim.Refl.Refl ->
           if Digestif.equal k h h'
           then Fmt.pr "Body is verified.\n%!"
           else Fmt.pr "Body is alterated (expected: %a, provided: %a).\n%!"
          (Digestif.pp k) h'
          (Digestif.pp k) h
         | None -> assert false)
      produced_hashes expected_hashes ;

    let dns = Udns.create () in

    let svalues = List.map (UnixIO.prj <.> Dkim.extract_server dns unix (module Udns)) values in
    let svalues = List.map
        (fun value -> let open Rresult.R in match value >>= Dkim.post_process_server with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        svalues in
    Fmt.pr "%a.\n%!" Fmt.(Dump.list Dkim.pp_server) svalues
