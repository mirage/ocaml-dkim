let () = Printexc.record_backtrace true

module UnixIO = Dkim.Sigs.Make(struct type +'a t = 'a end)

module Caml_flow = struct
  type backend = UnixIO.t
  type flow = in_channel

  let input flow buf off len = UnixIO.inj (Pervasives.input flow buf off len)
end

module Unix_flow : Udns_client_flow.S
  with type flow = Unix.file_descr
   and type io_addr = Unix.inet_addr * int
   and type stack = unit
   and type (+'a, +'b) io = ('a, [> `Msg of string ] as 'b) result = struct
  type io_addr = Unix.inet_addr * int
  type ns_addr = [ `TCP | `UDP ] * io_addr
  type stack = unit
  type flow = Unix.file_descr
  type t = { nameserver : ns_addr }
  type (+'a, +'b) io = ('a, 'b) result constraint 'b = [> `Msg of string ]

  let create ?(nameserver = `TCP, (Unix.inet_addr_of_string "91.239.100.100", 53)) () =
    { nameserver }

  let nameserver { nameserver } = nameserver

  let map = Rresult.R.((>>=))
  let resolve = Rresult.R.((>>=))
  let lift v = v

  open Rresult

  let connect ?nameserver:ns t =
    let proto, (server, port) = match ns with Some x -> x | None -> nameserver t in
    ( match proto with
      | `UDP -> Ok Unix.((getprotobyname "udp").p_proto)
      | `TCP -> Ok Unix.((getprotobyname "tcp").p_proto) ) >>= fun proto ->
    let socket = Unix.(socket PF_INET SOCK_STREAM proto) in
    let addr = Unix.ADDR_INET (server, port) in
    Unix.connect socket addr ; Ok socket

  let send (socket : flow) (tx : Cstruct.t) =
    let str = Cstruct.to_string tx in
    let res = Unix.send_substring socket str 0 (String.length str) [] in

    if res <> String.length str
    then Rresult.R.error_msgf "Broken write to upstream NS (%d)" res
    else Ok ()

  let recv (socket : flow) =
    let buffer = Bytes.make 2048 '\000' in
    let x = Unix.recv socket buffer 0 (Bytes.length buffer) [] in
    if x > 0 && x <= Bytes.length buffer
    then Ok (Cstruct.of_bytes buffer ~len:x)
    else Rresult.R.error_msg "Reading from NS socket failed"
end

module Udns = struct
  include Udns_client_flow.Make(Unix_flow)

  type t = Unix_flow.t
  type backend = UnixIO.t

  let getaddrinfo t `TXT domain_name =
    match getaddrinfo t Udns_map.Txt domain_name with
    | Ok (_ttl, txtset) -> UnixIO.inj (Ok (Udns_map.TxtSet.elements txtset))
    | Error _ as err -> UnixIO.inj err
end

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

    let dns = Unix_flow.create () in

    let svalues = List.map (Dkim.extract_server dns unix (module Udns)) values in
    let svalues = List.map
        (fun value -> let open Rresult.R in match UnixIO.prj value >>= Dkim.post_process_server with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        svalues in
    Fmt.pr "%a.\n%!" Fmt.(Dump.list Dkim.pp_server) svalues
