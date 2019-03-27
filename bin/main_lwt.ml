let () = Printexc.record_backtrace true

module LwtIO = Dkim.Sigs.Make(struct type +'a t = 'a Lwt.t end)

module Udns = struct
  include Udns_client_lwt

  type t = Udns_client_lwt.Uflow.t
  type backend = LwtIO.t

  let getaddrinfo t `TXT domain_name =
    let open Lwt.Infix in
    (getaddrinfo t Udns_map.Txt domain_name >|= function
      | Ok (_ttl, txtset) -> (Ok (Udns_map.TxtSet.elements txtset))
      | Error _ as err -> err)
    |> LwtIO.inj
end

module Lwt_flow = struct
  type backend = LwtIO.t
  type flow = Lwt_io.input_channel

  let input flow buf off len = LwtIO.inj (Lwt_io.read_into flow buf off len)
end

let lwt_bind x f =
  let open Lwt.Infix in
  LwtIO.inj (LwtIO.prj x >>= fun x -> LwtIO.prj (f x))

let ( <.> ) f g = fun x -> f (g x)

let lwt =
  { Dkim.Sigs.bind= lwt_bind
  ; return= (fun x -> LwtIO.inj (Lwt.return x)) }

let main () =
  let open Lwt.Infix in
  Dkim.extract_dkim Lwt_io.stdin lwt (module Lwt_flow) |> LwtIO.prj >>= function
  | Error (`Msg err) -> Fmt.epr "Retrieve an error: %s.\n%!" err ; Lwt.return ()
  | Ok (prelude, _, values) ->
    let values = List.map
        (fun (value) -> match Dkim.post_process_dkim value with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        values in
    Fmt.pr "%a.\n%!" Fmt.(Dump.list Dkim.pp_dkim) values ;
    Dkim.digest_body Lwt_io.stdin lwt (module Lwt_flow) prelude |> LwtIO.prj >>= fun body ->
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

    Lwt_list.map_p (LwtIO.prj <.> Dkim.extract_server dns lwt (module Udns)) values >>= fun svalues ->
    let svalues = List.map
        (fun value -> let open Rresult.R in match value >>= Dkim.post_process_server with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        svalues in
    Fmt.pr "%a.\n%!" Fmt.(Dump.list Dkim.pp_server) svalues ; Lwt.return ()

let () = Lwt_main.run (main ())
