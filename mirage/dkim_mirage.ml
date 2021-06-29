module Lwt_scheduler = Dkim.Sigs.Make (Lwt)

let ( <.> ) f g x = f (g x)

type 'a stream = unit -> 'a option Lwt.t

module Flow = struct
  type backend = Lwt_scheduler.t

  type flow = {
    linger : Bytes.t;
    mutable pos : int;
    stream : (string * int * int) stream;
  }

  let chunk = 0x1000 (* XXX(dinosaure): see [extract_dkim]. *)

  let of_stream stream = { linger = Bytes.create chunk; pos = 0; stream }

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

module Make
    (R : Mirage_random.S)
    (T : Mirage_time.S)
    (C : Mirage_clock.MCLOCK)
    (P : Mirage_clock.PCLOCK)
    (S : Mirage_stack.V4V6) =
struct
  module DNS = struct
    include Dns_client_mirage.Make (R) (T) (C) (S)

    type backend = Lwt_scheduler.t

    let getaddrinfo dns `TXT domain_name =
      let open Lwt.Infix in
      getaddrinfo dns Dns.Rr_map.Txt domain_name >>= function
      | Ok (_ttl, txtset) -> Lwt.return_ok (Dns.Rr_map.Txt_set.elements txtset)
      | Error err -> Lwt.return_error err

    let getaddrinfo dns `TXT domain_name =
      Lwt_scheduler.inj (getaddrinfo dns `TXT domain_name)
  end

  let epoch () =
    let d, _ps = P.now_d_ps () in
    Int64.of_int d

  let consumer_of_stream stream () = Lwt_scheduler.inj (Lwt_stream.get stream)

  let rec drain stream =
    let open Lwt.Infix in
    Lwt_stream.get stream >>= function
    | Some _ -> drain stream
    | None -> Lwt.return_unit

  let is_not_errored = function
    | `Errored -> Lwt.return false
    | _ -> Lwt.return true

  let is_valid = function `Valid _ -> Lwt.return true | _ -> Lwt.return false

  (* XXX(dinosaure): this version is able to verify multiple DKIM fields
   * with a bounded stream according to the incoming stream. The trick is
   * to clone [simple] and [relaxed] bounded streams to all DKIM fields
   * and consume all of them concurrently with the consumer of the incoming
   * stream. By this way, we are able to verify an email in one pass!
   *
   * As far as I can tell, such pattern for DKIM does not exist. *)

  let verify ?newline ?size ?nameserver ?timeout stream stack =
    let flow = Flow.of_stream stream in
    let dns = DNS.create ?size ?nameserver ?timeout stack in
    let q = Queue.create () in
    Dkim.extract_dkim ?newline flow lwt (module Flow) >>? fun extracted ->
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
    let s, s_bounded = Lwt_stream.create_bounded 10 in
    let r, r_bounded = Lwt_stream.create_bounded 10 in
    let clone (dkim_field_name, dkim_field_value, m) =
      ( dkim_field_name,
        dkim_field_value,
        m,
        Lwt_stream.clone s,
        Lwt_stream.clone r ) in
    let dkim_fields = List.map clone extracted.dkim_fields in
    let (`Consume th) =
      Dkim.extract_body ?newline flow lwt
        (module Flow)
        ~prelude:extracted.Dkim.prelude ~simple:s_emitter ~relaxed:r_emitter
    in
    let rec consume () =
      match Queue.pop q with
      | `Simple (Some s) -> s_bounded#push s |> Lwt_scheduler.inj >>= consume
      | `Relaxed (Some s) -> r_bounded#push s |> Lwt_scheduler.inj >>= consume
      | `Simple None ->
          s_bounded#close ;
          if s_bounded#closed && r_bounded#closed
          then Lwt_scheduler.inj Lwt.return_unit
          else consume ()
      | `Relaxed None ->
          r_bounded#close ;
          if s_bounded#closed && r_bounded#closed
          then Lwt_scheduler.inj Lwt.return_unit
          else consume ()
      | exception Queue.Empty -> consume () in
    let fiber =
      let open Lwt.Infix in
      Lwt.both
        (Lwt.join
           [
             Lwt_scheduler.prj th;
             Lwt_scheduler.prj (consume ());
             drain s;
             drain r;
           ])
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

  let verify ?newline ?size ?nameserver ?timeout stream stack =
    Lwt_scheduler.prj (verify ?newline ?size ?nameserver ?timeout stream stack)
end

module Flow_with_stream = struct
  type backend = Lwt_scheduler.t

  type flow = {
    linger : Bytes.t;
    mutable pos : int;
    pusher : (string * int * int) option -> unit;
    stream : (string * int * int) stream;
  }

  let chunk = 0x1000 (* XXX(dinosaure): see [extract_dkim]. *)

  let of_stream stream =
    let stream', pusher = Lwt_stream.create () in
    ({ linger = Bytes.create chunk; pos = 0; pusher; stream }, stream')

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
