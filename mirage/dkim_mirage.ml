module Lwt_scheduler = Dkim.Sigs.Make (Lwt)

let ( <.> ) f g x = f (g x)

type 'a stream = unit -> 'a option Lwt.t

module Flow = struct
  type backend = Lwt_scheduler.t

  type flow = {
    linger : bytes;
    mutable pos : int;
    stream : (string * int * int) stream;
  }

  let of_stream ?(size = 0x100) stream =
    { linger = Bytes.create size; pos = 0; stream }

  let rec input ({ linger; pos; stream } as flow) tmp off len =
    let open Lwt.Infix in
    if pos > 0
    then (
      let len = min len pos in
      Bytes.blit tmp off linger 0 len ;
      if len < pos then Bytes.unsafe_blit linger len linger 0 (pos - len) ;
      (* compress *)
      flow.pos <- pos - len ;
      Lwt_scheduler.inj (Lwt.return len))
    else
      let fiber =
        stream () >>= function
        | None -> Lwt.return 0 (* end-of-input *)
        | Some (_, _, 0) ->
            Lwt_scheduler.prj (input flow tmp off len) (* redo *)
        | Some (str, str_off, str_len) ->
            let max = min str_len len in
            Bytes.blit_string str str_off tmp off max ;
            if str_len > max
            then (
              Bytes.blit_string str max linger 0 (str_len - max) ;
              flow.pos <- str_len - max) ;
            Lwt.return max in
      Lwt_scheduler.inj fiber
end

let bind x f =
  let open Lwt.Infix in
  Lwt_scheduler.inj (Lwt_scheduler.prj x >>= (Lwt_scheduler.prj <.> f))

let return x = Lwt_scheduler.inj (Lwt.return x)
let ( >>= ) x f = bind x f

let ( >>? ) x f =
  x >>= function
  | Ok x -> f x
  | Error err -> Lwt_scheduler.inj (Lwt.return_error err)

let lwt = { Dkim.Sigs.bind; return }

module Make (P : Mirage_clock.PCLOCK) (D : Dns_client_mirage.S) = struct
  type nameserver =
    [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]

  module DNS :
    Dkim.Sigs.DNS with type t = D.t and type backend = Lwt_scheduler.t = struct
    type t = D.t
    type backend = Lwt_scheduler.t

    let gettxtrrecord dns domain_name =
      let open Lwt.Infix in
      D.getaddrinfo dns Dns.Rr_map.Txt domain_name >>= function
      | Ok (_ttl, txtset) -> Lwt.return_ok (Dns.Rr_map.Txt_set.elements txtset)
      | Error err -> Lwt.return_error err

    let gettxtrrecord dns domain_name =
      Lwt_scheduler.inj (gettxtrrecord dns domain_name)
  end

  let epoch () =
    let d, _ps = P.now_d_ps () in
    Int64.of_int d

  let consumer_of_stream stream () = Lwt_scheduler.inj (Lwt_stream.get stream)

  let is_not_errored = function
    | `Errored -> Lwt.return false
    | _ -> Lwt.return true

  let is_valid = function `Valid _ -> Lwt.return true | _ -> Lwt.return false

  let server (dns : D.t) dkim =
    Lwt_scheduler.prj
    @@ ( Dkim.extract_server dns lwt (module DNS) dkim >>? fun n ->
         Dkim.post_process_server n |> return )

  (* XXX(dinosaure): this version is able to verify multiple DKIM fields
   * with a bounded stream according to the incoming stream. The trick is
   * to clone [simple] and [relaxed] bounded streams to all DKIM fields
   * and consume all of them concurrently with the consumer of the incoming
   * stream. By this way, we are able to verify an email in one pass!
   *
   * As far as I can tell, such pattern for DKIM does not exist. *)

  let verify ?newline stream dns =
    let q = Queue.create () in
    Dkim.extract_dkim ?newline (Flow.of_stream stream) lwt (module Flow)
    >>? fun extracted ->
    let f (dkim_field_name, dkim_field_value, m, s, r) =
      let fiber =
        Dkim.post_process_dkim m |> return >>? fun dkim ->
        Dkim.extract_server dns lwt (module DNS) dkim >>? fun n ->
        Dkim.post_process_server n |> return >>? fun server ->
        return (Ok (dkim, server)) in
      fiber >>= function
      | Error _ -> Lwt_scheduler.inj (Lwt.return `Errored)
      | Ok (dkim, server) -> (
          Dkim.verify lwt ~epoch extracted.fields
            (dkim_field_name, dkim_field_value)
            ~simple:(consumer_of_stream s) ~relaxed:(consumer_of_stream r) dkim
            server
          >>= function
          | true -> return (`Valid dkim)
          | false -> return (`Invalid dkim)) in
    let s_emitter x = Queue.push (`Simple x) q in
    let r_emitter x = Queue.push (`Relaxed x) q in
    let make_streams (dkim_field_name, dkim_field_value, m) =
      let s, s_pusher = Lwt_stream.create_bounded 10 in
      let r, r_pusher = Lwt_stream.create_bounded 10 in
      ((dkim_field_name, dkim_field_value, m, s, r), (s_pusher, r_pusher)) in
    let dkim_fields_with_streams = List.map make_streams extracted.dkim_fields in
    let dkim_fields, pushers = List.split dkim_fields_with_streams in
    let s_pushers, r_pushers = List.split pushers in
    let i_emmitter, i_pusher = Lwt_stream.create_bounded 10 in
    let rec consume () =
      match Queue.pop q with
      | `Await -> (
          stream () |> Lwt_scheduler.inj >>= function
          | Some v -> i_pusher#push v |> Lwt_scheduler.inj >>= consume
          | None ->
              i_pusher#close ;
              consume ())
      | `Simple (Some v) ->
          Lwt_list.iter_p (fun s_pusher -> s_pusher#push v) s_pushers
          |> Lwt_scheduler.inj
          >>= consume
      | `Relaxed (Some v) ->
          Lwt_list.iter_p (fun r_pusher -> r_pusher#push v) r_pushers
          |> Lwt_scheduler.inj
          >>= consume
      | `Simple None ->
          List.iter (fun s_pusher -> s_pusher#close) s_pushers ;
          if List.for_all (fun r_pusher -> r_pusher#closed) r_pushers
          then Lwt_scheduler.inj Lwt.return_unit
          else consume ()
      | `Relaxed None ->
          List.iter (fun r_pusher -> r_pusher#close) r_pushers ;
          if List.for_all (fun s_pusher -> s_pusher#closed) s_pushers
          then Lwt_scheduler.inj Lwt.return_unit
          else consume ()
      | exception Queue.Empty -> Lwt.pause () |> Lwt_scheduler.inj >>= consume
    in
    let (`Consume th) =
      Dkim.extract_body ?newline
        (Flow.of_stream (fun () ->
             Queue.push `Await q ;
             Lwt_stream.get i_emmitter))
        lwt
        (module Flow)
        ~prelude:extracted.Dkim.prelude ~simple:s_emitter ~relaxed:r_emitter
    in
    let fiber =
      let open Lwt.Infix in
      Lwt.both
        (Lwt.join [ Lwt_scheduler.prj th; Lwt_scheduler.prj (consume ()) ])
        (Lwt_list.map_p (Lwt_scheduler.prj <.> f) dkim_fields)
      >>= fun ((), results) ->
      Lwt_list.filter_p is_not_errored results >>= fun results ->
      Lwt_list.partition_p is_valid results in
    Lwt_scheduler.inj fiber >>= fun (valids, invalids) ->
    let valids =
      List.map (function `Valid dkim -> dkim | _ -> assert false) valids in
    let invalids =
      List.map (function `Invalid dkim -> dkim | _ -> assert false) invalids
    in
    return (Ok (valids, invalids))

  let verify ?newline stream dns =
    Lwt_scheduler.prj (verify ?newline stream dns)
end

(* XXX(dinosaure): this is where we save in the same time the incoming email
 * to be able to restransmit then with the DKIM field. However, we must compute
 * the signature (and read the entire incoming email) to be able to transmit
 * the DKIM field. In others words, we must keep in memory the entire email while
 * we compute the signature to be able to retransmit it with the DKIM-field.
 *
 * In the opposite of [verify], such operation is **not** memory safe. A big email
 * can put a big pressure on the memory! *)

module Flow_with_stream = struct
  type backend = Lwt_scheduler.t

  type flow = {
    linger : Bytes.t;
    mutable pos : int;
    pusher : (string * int * int) option -> unit;
    stream : (string * int * int) stream;
  }

  let of_stream ?(size = 0x1000) stream =
    let stream', pusher = Lwt_stream.create () in
    ({ linger = Bytes.create size; pos = 0; pusher; stream }, stream')

  let rec input ({ linger; pos; pusher; stream } as flow) tmp off len =
    let open Lwt.Infix in
    if pos > 0
    then (
      let len = min len pos in
      Bytes.blit tmp off linger 0 len ;
      if len < pos then Bytes.unsafe_blit linger len linger 0 (pos - len) ;
      (* compress *)
      flow.pos <- pos - len ;
      Lwt_scheduler.inj (Lwt.return len))
    else
      let fiber =
        stream () >>= function
        | None ->
            pusher None ;
            Lwt.return 0 (* end-of-input *)
        | Some (_, _, 0) ->
            Lwt_scheduler.prj (input flow tmp off len) (* redo *)
        | Some (str, str_off, str_len) as v ->
            pusher v ;
            let max = min str_len len in
            Bytes.blit_string str str_off tmp off max ;
            if str_len > max
            then (
              Bytes.blit_string str max linger 0 (str_len - max) ;
              flow.pos <- str_len - max) ;
            Lwt.return max in
      Lwt_scheduler.inj fiber
end

module Stream = struct
  type 'a t = 'a Lwt_stream.t
  type backend = Lwt_scheduler.t

  let create () = Lwt_stream.create ()
  let get stream = Lwt_scheduler.inj (Lwt_stream.get stream)
end

let sign ~key ?(newline = Dkim.LF) stream dkim =
  let open Lwt.Infix in
  let flow, mail_stream = Flow_with_stream.of_stream stream in
  let both a b = Lwt_scheduler.(inj (Lwt.both (prj a) (prj b))) in
  Lwt_scheduler.prj
    (Dkim.sign ~key ~newline flow lwt ~both:{ Dkim.Sigs.f = both }
       (module Flow_with_stream)
       (module Stream)
       dkim)
  >>= fun dkim ->
  let new_line = match newline with Dkim.LF -> "\n" | Dkim.CRLF -> "\r\n" in
  let stream = Prettym.to_stream ~new_line Dkim.Encoder.as_field dkim in
  let dkim_stream =
    Lwt_stream.from (fun () ->
        match stream () with
        | Some str -> Lwt.return_some (str, 0, String.length str)
        | None -> Lwt.return_none) in
  let stream = Lwt_stream.append dkim_stream mail_stream in
  Lwt.return (dkim, fun () -> Lwt_stream.get stream)
