[@@@warning "-32-34-37"]

let () = Printexc.record_backtrace true

module Body = Body
module Option = Option
module Sigs = Sigs
module Map = Map
open Sigs

module Refl = struct type ('a, 'b) t = Refl : ('a, 'a) t end

type raw = Mrmime.Unstructured.t
type noop = [ `WSP of string | `CR of int | `LF of int | `CRLF ]
type data = [ `Text of string | `Encoded of Mrmime.Encoded_word.t ]
type +'a or_err = ('a, Rresult.R.msg) result

let (<.>) f g = fun x -> f (g x)

let pp_hex ppf x = String.iter (fun x -> Fmt.pf ppf "%02x" (Char.code x)) x

let unfold =
  (* TODO: not sure if it's necessary to dispatch on semicolon where it can
     appear in a middle of a [`Text]/[`Encoded _]. Why I did this code? *)
  let empty_rest = List.for_all (function #noop -> true | #data -> false) in
  let has_semicolon = function
    | `Text x -> x.[String.length x - 1] = ';'
    | `Encoded { Mrmime.Encoded_word.data= Ok data; _ } -> data.[String.length data - 1] = ';'
    | `Encoded { Mrmime.Encoded_word.data= Error err; _ } ->
      Fmt.invalid_arg "Cannot extract DKIM-Signature: %a" Rresult.R.pp_msg err in
  let rec go tag acc rest = match rest, tag with
    | [], [] -> List.rev acc
    | [], tag -> List.rev (List.rev tag :: acc)
    | (#data as x) :: r, [] ->
      if has_semicolon x || empty_rest r
      then go [] ([ x ] :: acc) r
      else go [ x ] acc r
    | (#data as x) :: r, tag ->
      if has_semicolon x || empty_rest r
      then go [] (List.rev (x :: tag) :: acc) r
      else go (x :: tag) acc r
    | #noop :: r, tag -> go tag acc r in
  go [] []

let unfold unstructured =
  let concat = List.map
      (String.concat "" <.> List.map (function
           | `Text x -> x
           | `Encoded { Mrmime.Encoded_word.data= Ok data; _ } -> data
           (* XXX(dinosaure): [unfold] raises an [Invalid_argument] if it
              retrieves a malformed encoded-word. *)
           | `Encoded _ -> assert false)) in
  try Ok (concat (unfold unstructured))
  with Invalid_argument err -> Rresult.R.error_msg err

let parse_dkim_field_value x =
  match Angstrom.parse_string Parser.mail_tag_list x with
  | Ok v -> Ok v
  | Error _ -> Rresult.R.error_msgf "Invalid DKIM Signature: %S" x

let parse_dkim_server_value x =
  let open Rresult.R in
  let p = Mrmime.Rfc5322.unstructured in
  let x = x ^ "\r\n\r\n" in
  (reword_error (fun _ -> `Msg "Invalid DKIM value (as unstructured value)") (Angstrom.parse_string p x))
  >>= unfold >>| String.concat ""
  >>= (reword_error (fun _ -> `Msg "Invalid DKIM value") <.> Angstrom.parse_string Parser.server_tag_list)

type newline =
  | CRLF | LF

let sub_string_and_replace_newline chunk len =
  let count = ref 0 in
  String.iter (function '\n' -> incr count | _ -> ()) (Bytes.sub_string chunk 0 len) ;
  let plus = !count in
  let pos = ref 0 in
  let res = Bytes.create (len + plus) in
  for i = 0 to len - 1
  do match Bytes.unsafe_get chunk i with
    | '\n' ->
      Bytes.unsafe_set res !pos '\r' ;
      Bytes.unsafe_set res (!pos + 1) '\n' ;
      pos := !pos + 2
    | chr ->
      Bytes.unsafe_set res !pos chr ;
      incr pos
  done ; Bytes.unsafe_to_string res

let sanitize_input newline chunk len = match newline with
  | CRLF -> Bytes.sub_string chunk 0 len
  | LF -> sub_string_and_replace_newline chunk len

let src = Logs.Src.create "dkim" ~doc:"logs dkim's event"
module Log = (val Logs.src_log src : Logs.LOG)

let field_dkim_signature = Mrmime.Field.of_string_exn "DKIM-Signature"

type extracted =
  { dkim_fields : (Mrmime.Field.t * raw * Map.t) list
  ; fields : (Mrmime.Field.t * string) list
  ; prelude : string }

let extract_dkim
  : type flow backend.
    ?newline:newline -> flow -> backend state ->
    (module FLOW with type flow = flow and type backend = backend) ->
    (extracted or_err, backend) io
  = fun (type flow backend) ?(newline = LF) (flow:flow) (state:backend state)
        (module Flow : FLOW with type flow = flow and type backend = backend) ->
    let open Mrmime in

    let (>>=) = state.bind in
    let return = state.return in

    let chunk = 0x1000 in
    let raw = Bytes.create chunk in
    let buffer = Bigstringaf.create (2 * chunk) in
    let decoder = St_header.decoder ~field:field_dkim_signature St_header.Value.Unstructured buffer in
    let rec go others acc = match St_header.decode decoder with
      | `Field (raw_dkim_field, raw_dkim_value) ->
        let acc = match unfold raw_dkim_value with
          | Error (`Msg err) ->
            Log.warn (fun f -> f "Got an error when we unfold DKIM-Signature: %s" err) ;
            acc
          | Ok lst -> match parse_dkim_field_value (String.concat "" lst) with
            | Ok dkim_value -> (raw_dkim_field, raw_dkim_value, dkim_value) :: acc
            | Error (`Msg err) ->
              Log.warn (fun f -> f "Got an error when we parse DKIM-Signature: %s" err) ;
              acc in
        go others acc
      | `Other (field, raw) -> go ((field, raw) :: others) acc
      | `Lines _ -> go others acc
      | `Malformed err -> return (Rresult.R.error_msg err)
      | `End rest -> return (Rresult.R.ok { prelude= rest; fields= List.rev others; dkim_fields= List.rev acc; })
      | `Await ->
        Flow.input flow raw 0 (Bytes.length raw) >>= fun len ->
        let raw = sanitize_input newline raw len in
        match St_header.src decoder raw 0 (String.length raw) with
        | Ok () -> go others acc
        | Error _ as err -> return err in
    go [] []

type dkim =
  { v : int
  ; a : Value.algorithm * hash
  ; b : string
  ; bh : value
  ; c : Value.canonicalization * Value.canonicalization
  ; d : Domain_name.t
  ; h : Mrmime.Field.t list
  ; i : Value.auid option
  ; l : int option
  ; q : Value.query list
  ; s : string
  ; t : int64 option
  ; x : int64 option
  ; z : (Mrmime.Field.t * string) list }
and hash = V : 'k Digestif.hash -> hash
and value = H : 'k Digestif.hash * 'k Digestif.t -> value

type server =
  { v : Value.server_version
  ; h : hash list
  ; k : Value.algorithm
  ; n : string option
  ; p : string
  ; s : Value.service list
  ; t : Value.name list }

let pp_hash ppf (V hash) = let open Digestif in match hash with
  | MD5 -> Fmt.string ppf "MD5"
  | SHA1 -> Fmt.string ppf "SHA1"
  | RMD160 -> Fmt.string ppf "RMD160"
  | SHA224 -> Fmt.string ppf "SHA224"
  | SHA256 -> Fmt.string ppf "SHA256"
  | SHA384 -> Fmt.string ppf "SHA384"
  | SHA512 -> Fmt.string ppf "SHA512"
  | WHIRLPOOL -> Fmt.string ppf "WHIRLPOOL"
  | BLAKE2B _ -> Fmt.string ppf "BLAKE2B"
  | BLAKE2S _ -> Fmt.string ppf "BLAKE2S"

let equal_hash
  : type a b. a Digestif.hash -> b Digestif.hash -> (a, b) Refl.t option
  = fun a b -> let open Digestif in match a, b with
    | MD5, MD5 -> Some Refl.Refl
    | SHA1, SHA1 -> Some Refl.Refl
    | RMD160, RMD160 -> Some Refl.Refl
    | SHA224, SHA224 -> Some Refl.Refl
    | SHA256, SHA256 -> Some Refl.Refl
    | SHA384, SHA384 -> Some Refl.Refl
    | SHA512, SHA512 -> Some Refl.Refl
    | WHIRLPOOL, WHIRLPOOL -> Some Refl.Refl
    | BLAKE2B x, BLAKE2B y -> if x = y then Some Refl.Refl else None
    | BLAKE2S x, BLAKE2S y -> if x = y then Some Refl.Refl else None
    | _, _ -> None

let pp_signature (V hash) ppf (H (hash', value)) = match equal_hash hash hash' with
  | Some Refl.Refl ->
    Digestif.pp hash ppf value
  | None -> assert false (* XXX(dinosaure): should never occur. *)

let pp_dkim ppf (t:dkim) =
  Fmt.pf ppf "{ @[<hov>v = %d;@ a = %a;@ b = %a;@ bh = %a; c = %a;@ d = %a;@ h = @[<hov>%a@];@ \
                       i = @[<hov>%a@];@ l = %a;@ q = @[<hov>%a@];@ s = %s;@ t = %a;@ x = %a;@ \
                       z = @[<hov>%a@];@] }"
    t.v Fmt.(Dump.pair Value.pp_algorithm pp_hash) t.a
    pp_hex t.b (pp_signature (snd t.a)) t.bh Fmt.(Dump.pair Value.pp_canonicalization Value.pp_canonicalization) t.c
    Domain_name.pp t.d Fmt.(Dump.list Mrmime.Field.pp) t.h Fmt.(Dump.option Value.pp_auid) t.i Fmt.(Dump.option int) t.l
    Fmt.(Dump.list Value.pp_query) t.q t.s Fmt.(Dump.option int64) t.t Fmt.(Dump.option int64) t.x
    Fmt.(Dump.list Value.pp_copy) t.z

let pp_server ppf (t:server) =
  Fmt.pf ppf "{ @[<hov>v = %s;@ h = @[<hov>%a@];@ k = %a;@ n = %a; p = %a;@ s = @[<hov>%a@];@ t = @[<hov>%a@];@] }"
    t.v Fmt.(Dump.list pp_hash) t.h
    Value.pp_algorithm t.k
    Fmt.(Dump.option string) t.n
    pp_hex t.p
    Fmt.(Dump.list Value.pp_service) t.s
    Fmt.(Dump.list Value.pp_name) t.t

let expected { bh; _ } = bh

let hash = function
  | Value.SHA1 -> V Digestif.SHA1
  | Value.SHA256 -> V Digestif.SHA256
  | Value.Hash_ext x -> match String.lowercase_ascii x with
    | "sha512" -> V Digestif.SHA512
    | x -> Fmt.invalid_arg "Invalid kind of hash <%s>" x

let string_of_quoted_printable x =
  let decoder = Pecu.Inline.decoder (`String x) in
  let res = Buffer.create 0x800 in
  let rec go () = match Pecu.Inline.decode decoder with
    | `Await -> assert false
    | `Char chr -> Buffer.add_char res chr ; go ()
    | `End -> Rresult.R.ok (Buffer.contents res)
    | `Malformed err -> Rresult.R.error_msg err in
  go ()

module SSet = Set.Make(Mrmime.Field)

let uniqify l =
  let r, _ =
    List.fold_left (fun (r, s) x ->
        if SSet.exists (Mrmime.Field.equal x) s
        then r, s
        else x :: r, SSet.add x s)
      ([], SSet.empty) l in
  List.rev r

let post_process_dkim hmap =
  let v = match Map.find Map.K.v hmap with
    | Some v -> v
    | None -> Fmt.invalid_arg "Version is required" in
  let a = match Map.find Map.K.a hmap with
    | Some (alg, x) -> (alg, hash x)
    | None -> Fmt.invalid_arg "Algorithm is required" in
  let b = match Option.map Base64.decode (Map.find Map.K.b hmap) with
    | Some (Ok v) -> v
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Signature data is required" in
  let bh = match Option.map Base64.decode (Map.find Map.K.bh hmap) with
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Hash of canonicalized body part is required"
    | Some (Ok v) -> let (_, V k) = a in match Digestif.of_raw_string_opt k v with
      | Some v -> H (k, v)
      | None -> Fmt.invalid_arg "Invalid hash" in
  let c = match Map.find Map.K.c hmap with
    | Some v -> v
    | None -> Value.Simple, Value.Simple in
  let d = match Option.map (Domain_name.of_string <.> String.concat ".") (Map.find Map.K.d hmap) with
    | Some (Ok v) -> v
    | Some (Error (`Msg err)) ->
      Fmt.invalid_arg "Retrieve an error with %a: %s"
        Fmt.(Dump.option (Dump.list string)) (Map.find Map.K.d hmap)
        err
    | None -> Fmt.invalid_arg "SDID is required" in
  let h = match Map.find Map.K.h hmap with
    | Some v -> uniqify v
    (* XXX(dinosaure):
       - [Parser.field_name] checks values. So, no post-process is required.
       - uniqify [h],however, I'm clearly not sure about that but [From] can
       appear multiple times and need to be digest only one time. RFC 6376 does
       not explain this behavior (tips from dkimpy). *)
    | None -> Fmt.invalid_arg "Signed header fields required" in
  let i = Map.find Map.K.i hmap in
  let l = Map.find Map.K.l hmap in
  let q =
    List.map (fun (q, x) -> match Option.map string_of_quoted_printable x with
        | None -> (q, None)
        | Some (Ok x) -> (q, Some x)
        | Some (Error (`Msg err)) -> invalid_arg err)
    (Option.value ~default:[] (Map.find Map.K.q hmap)) in
  let s = match Option.map (String.concat ".") (Map.find Map.K.s hmap) with
    | Some v -> v
    | None -> Fmt.invalid_arg "Selector is required" in
  let t = Map.find Map.K.t hmap in
  let x = Map.find Map.K.x hmap in
  let z =
    List.map
      (fun (f, x) -> match string_of_quoted_printable x with
         | Ok x -> (f, x)
         | Error (`Msg err) -> invalid_arg err)
    (Option.(value ~default:[] (Map.find Map.K.z hmap))) in
  { v; a; b; bh; c; d; h; i; l; q; s; t; x; z }

let post_process_dkim hmap =
  try Rresult.R.ok (post_process_dkim hmap)
  with Invalid_argument err -> Rresult.R.error_msg err

let post_process_server hmap =
  let v = Option.value ~default:"DKIM1" (Map.find Map.K.sv hmap) in
  let h = Option.value ~default:[ V Digestif.SHA1; V Digestif.SHA256 ]
      (Option.map (List.map hash) (Map.find Map.K.sh hmap)) in
  let k = Option.value ~default:Value.RSA (Map.find Map.K.k hmap) in
  let n = Map.find Map.K.n hmap in
  let p = match Option.map Base64.decode (Map.find Map.K.p hmap) with
    | Some (Ok p) -> p
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Public-key is required" in
  let s = Option.value ~default:[ Value.All ] (Map.find Map.K.ss hmap) in
  let t = Option.value ~default:[] (Map.find Map.K.st hmap) in
  { v; h; k; n; p; s; t; }

let post_process_server hmap =
  try Rresult.R.ok (post_process_server hmap)
  with Invalid_argument err -> Rresult.R.error_msg err

let digesti_of_hash (V hash) = fun f -> let v = Digestif.digesti_string hash f in H (hash, v)

exception Find

let list_assoc ~equal x l =
  let res = ref None in
  try List.iter (fun (y, v) -> if equal x y then ( res := Some (y, v) ; raise Find )) l
    ; raise Not_found
  with Find -> match !res with
    | Some v -> v | None -> assert false

let list_remove_assoc ~equal x l =
  let already_done = ref false in
  List.fold_left
    (fun a (y, v) ->
       if equal x y && not !already_done
       then ( already_done := true ; a)
       else (y, v) :: a)
    [] l |> List.rev

let list_first predicate vs =
  let res = ref None in
  try List.iter (fun x -> if predicate x then ( res := Some x ; raise Find )) vs
    ; None
  with Find -> !res

let string_contains ?(off= 0) str chr =
  let res = ref None in
  let len = String.length str - off in
  try String.iteri (fun i x -> if x = chr then ( res := Some i ; raise Find )) (String.sub str off len) ; None
  with Find -> match !res with Some pos -> Some (off + pos) | None -> None

let simple_field_canonicalization raw_field_and_value f =
  (* TODO: delete trailing CRLF. *)
  f raw_field_and_value

let simple_dkim_field_canonicalization (dkim_field:Mrmime.Field.t) raw f =
  let raw =
    let remove_crlf =
      let discard = ref true in
      List.fold_left (fun a -> function `CRLF when !discard -> a | x -> discard := false ; x :: a) [] in
    remove_crlf (List.rev raw) in

  f (dkim_field :> string) ;
  f ":" ;

  List.iter
    (function
      | `CRLF -> f "\r\n"
      | `CR n -> f (String.make n '\r')
      | `LF n -> f (String.make n '\n')
      | `Text x -> f x
      | `Encoded t -> f (Mrmime.Encoded_word.reconstruct t)
      | `WSP x -> f x)
    raw

let unstructured_to_string l =
  let res = Buffer.create 16 in
  List.iter (function
      | `CRLF -> ()
      | `CR n -> Buffer.add_string res (String.make n '\r')
      | `LF n -> Buffer.add_string res (String.make n '\n')
      | `Text x -> Buffer.add_string res x
      | `Encoded t -> Buffer.add_string res (Mrmime.Encoded_word.reconstruct t)
      | `WSP _ -> Buffer.add_string res " ")
    l ;
  Buffer.contents res

let relaxed_field_canonicalization raw_field_and_value f =
  let parser =
    let open Angstrom in
    let open Mrmime.Rfc5322 in
    field_name
    <* many (satisfy (function '\x09' .. '\x20' -> true | _ -> false))
    <* char ':'
    >>= fun field_name -> unstructured
    >>= fun value -> return (String.lowercase_ascii field_name, value) in
  (* See RFC 6376:
     Convert all header field names (not the header field values) to lowercase. *)
  match Angstrom.parse_string parser raw_field_and_value with
  | Ok (field, unstructured) ->
    let trim =
      (* Delete all WSP characters at the end of each unfolded header field
         value.

         Delete any WSP characters remaining before and after the colon
         separating the header field name form the header field value. The colon
         separator MUST be retained. *)
      let remove_wsp =
        let discard = ref true in
        List.fold_left (fun a -> function `WSP _ when !discard -> a | x -> discard := false ; x :: a) [] in
      remove_wsp <.> remove_wsp in
    f field ; f ":" ;
    let unfold =
      (* Order it seems important. *)
      trim
      <.> (List.fold_left
             (fun a x -> match a, x with
                | `WSP _ :: _, `WSP _ -> a
                (* Convert all sequences of one or more WSP characters to a
                   single SP character. WSP characters here include those before
                   and after a line folding boundary. *)
                | a, x -> x :: a)
             [])
      <.> (List.fold_left (fun a -> function `CRLF -> a | x -> x :: a) []) in
    let unstructured = unfold unstructured in
    List.iter
      (function
        | `CRLF -> ()
        | `CR n -> f (String.make n '\r')
        | `LF n -> f (String.make n '\n')
        | `Text x -> f x
        | `Encoded t -> f (Mrmime.Encoded_word.reconstruct t)
        | `WSP _ -> f " ")
      unstructured ;
    f "\r\n" (* Implementations MUST NOT remove the CRLF at the end of the
                header field value. *)
  | Error _ -> assert false
    (* [Mrmime] already extracted [field] with, at least, [unstructured] parser.
       In other side, we rely on that RFC said [unstructured] __is__ a super-set of
       any other special values (like date). *)

let relaxed_dkim_field_canonicalization (dkim_field:Mrmime.Field.t) raw f =
  (* XXX(dinosaure): duplicate with [relaxed_field_canonicalization] without
     ["DKIM-Signature"] and trailing [CRLF]. TODO! *)
  let trim =
    let remove_wsp =
      let discard = ref true in
      List.fold_left (fun a -> function `WSP _ when !discard -> a | x -> discard := false ; x :: a) [] in
    let remove_crlf =
      let discard = ref true in
      List.fold_left (fun a -> function `CRLF when !discard -> a | x -> discard := false ; x :: a) [] in
    (remove_crlf <.> List.rev) <.> (remove_wsp <.> remove_wsp) in
  let unfold =
    trim <.> List.rev <.> List.fold_left
      (fun a x -> match a, x with
         | `WSP _ :: _, `WSP _ -> a
         | a, x -> x :: a)
      [] in
  (* XXX(dinosaure): should be [f "dkim-signature:"]. *)
  f (String.lowercase_ascii (dkim_field :> string)) ; f ":" ;
  List.iter
    (function
      | `CRLF -> ()
      | `CR n -> f (String.make n '\r')
      | `LF n -> f (String.make n '\n')
      | `Text x -> f x
      | `WSP _ -> f " "
      | `Encoded t -> f (Mrmime.Encoded_word.reconstruct t))
    (unfold raw)

let crlf digest n =
  let rec go = function
    | 0 -> ()
    | n -> digest "\r\n" ; go (pred n) in
  if n < 0 then Fmt.invalid_arg "Expect at least 0 <crlf>"
  else go n

type iter = string Digestif.iter
type body = { relaxed : iter
            ; simple : iter }

let digest_body
  : type flow backend.
    ?newline:newline ->
    flow -> backend state ->
    (module FLOW with type flow = flow and type backend = backend) ->
    prelude:string -> (body, backend) io
  = fun ?(newline = LF) (type flow backend)
    (flow : flow) (state : backend state)
    (module Flow : FLOW with type flow = flow and type backend = backend)
    ~prelude ->

    let (>>=) = state.bind in
    let return = state.return in

    let decoder = Body.decoder () in
    let chunk = 0x1000 in
    let raw = Bytes.create chunk in
    let qr = Queue.create () in
    let qs = Queue.create () in
    let fr = fun x -> Queue.push x qr in
    let fs = fun x -> Queue.push x qs in

    Bytes.blit_string prelude 0 raw 0 (String.length prelude) ;
    (* XXX(dinosaure): [prelude] comes from [extract_dkim] and should be [<= 0x1000]. *)

    let digest_stack ?(relaxed= false) f l =
      let rec go = function
        | [] -> ()
        | [ `Spaces x ] -> f (if relaxed then " " else x)
        | `CRLF :: r -> f "\r\n" ; go r
        | `Spaces x :: r -> if not relaxed then f x ; go r in
      go (List.rev l) in
    let rec go stack = match Body.decode decoder with
      | `Await ->
        Flow.input flow raw 0 (Bytes.length raw) >>= fun len ->
        let raw = sanitize_input newline raw len in
        Body.src decoder (Bytes.of_string raw) 0 (String.length raw) ;
        go stack
      | `End -> crlf fr 1 ; crlf fs 1 ; return ()
      | `Spaces _ as x -> go (x :: stack)
      | `CRLF -> go (`CRLF :: stack)
    | `Data x ->
      digest_stack ~relaxed:true fr stack ; fr x ;
      digest_stack fs stack ; fs x ;
      go [] in
    Body.src decoder raw 0 (String.length prelude) ;
    go [] >>= fun () -> return { relaxed= (fun f -> Queue.iter f qr)
                               ; simple= (fun f -> Queue.iter f qs) }

(* XXX(dinosaure): seriously, going to hell DKIM! TODO: remove [sps]. From [dkimpy]:
   re.compile(br[\s]b'+FWS+br'=) (?:'+FWS+br'[a-zA-Z0-9+/=])*(?:\r?\n\Z)?' this is does NOT MEAN ANYTHING BOY. *)

let remove_signature_of_raw_dkim raw =
  let contains ?off x chr = match x with
    | `Text x -> string_contains ?off x chr
    | `Encoded { Mrmime.Encoded_word.data= Ok data; _ } -> string_contains ?off data chr
    | _ -> None in

  let length = function
    | `Text x -> String.length x
    | `Encoded { Mrmime.Encoded_word.data= Ok x; _ } -> String.length x
    | _ -> 0 in

  let remove_while_semicolon ?(off= 0) x =
    if off = length x then x, true
    else match x with
    | `Text x ->
      let len = String.length x - off in
      ( match string_contains (String.sub x off len) ';' with
        | Some pos ->
          let s = String.sub x 0 off ^ String.sub x (off + pos) (len - pos) in
          `Text s, false
        | None -> `Text (String.sub x 0 off), true )
    | `Encoded ({ Mrmime.Encoded_word.data= Ok x; _ } as encoded) ->
      let len = String.length x - off in
      ( match string_contains (String.sub x off len) ';' with
        | Some pos ->
          let s = String.sub x 0 off ^ String.sub x (off + pos) (len - pos) in
          `Encoded { encoded with Mrmime.Encoded_word.data= Ok s }, false
        | None -> `Encoded { encoded with Mrmime.Encoded_word.data= Ok (String.sub x 0 off) }, true )
    | _ -> `Text "", true in

  let is_consecutive_3 a b c = a = b - 1 && b = c - 1 in
  let is_consecutive_2 a b = a = b - 1 in

  List.fold_left
    (fun (state, acc) x ->
       let rec go state = match state, x with
        | `_0, (#data as x) ->
          ( match Option.(contains x ';'
                          >>= fun a -> contains ~off:a x 'b'
                          >>= fun b -> contains ~off:b x '='
                          >>= fun c -> Some (a, b, c)),
                  Option.(contains x ';'
                          >>= fun a -> contains ~off:a x 'b'
                          >>= fun b -> Some (a, b)),
                  contains x ';' with
            | Some (a, b, c), _, _ ->
              if is_consecutive_3 a b c
              then let x, continue = remove_while_semicolon ~off:(c + 1) x in
                if continue then (`R, x :: acc) else (`S, x :: acc)
              else if is_consecutive_2 a b && b = length x - 1
              then `_2, x :: acc
              else if a = length x - 1
              then `_1, x :: acc
              else `_0, x :: acc
            | _, Some (a, b), _ ->
              if is_consecutive_2 a b && b = length x - 1
              then `_2, x :: acc
              else if a = length x - 1
              then `_1, x :: acc
              else `_0, x :: acc
            | _, _, Some a ->
              if a = length x - 1
              then `_1, x :: acc
              else `_0, x :: acc
            | _, _, _ -> `_0, x :: acc )
        | `_1, (#data as x) ->
          ( match Option.(contains x 'b' >>= fun b -> contains ~off:b x '=' >>= fun c -> Some (b, c)),
                  contains x 'b' with
            | Some (0, 1), _ ->
              let x, continue = remove_while_semicolon ~off:2 x in
              if continue
              then (`R, x :: acc)
              else (`S, x :: acc)
            | _, Some 0 ->
              if length x = 1 then `_2, x :: acc else go `_0
            | _, _ -> go `_0 )
        | `_1, (#noop as x) -> `_1, x :: acc
        | `_2, (#data as x) ->
          ( match contains x '=' with
            | Some 0 ->
              let x, continue = remove_while_semicolon ~off:1 x in
              if continue then (`R, x :: acc) else (`S, x :: acc)
            | _ -> go `_0 )
        | `_2, (#noop as x) -> `_2, x :: acc
        | `R, #noop -> `R, acc
        | `R, (#data as x) ->
          let x, continue = remove_while_semicolon x in
          if continue then (`R, x :: acc) else (`S, x :: acc)
        | ((`_0 | `S) as state), x -> state, x :: acc
       in go state )
    (`_0, []) (`Text ";" :: raw) (* XXX(dinosaure): if [b] starts at the beginning. *)
  |> fun (state, raw) -> match state, List.rev raw with
  | (`S | `R), (`Text ";" :: raw) ->
    let raw = List.fold_left (fun a -> function
        | `Text ""
        | `Encoded { Mrmime.Encoded_word.data= Ok ""; _ } -> a
        | x -> x :: a) [] raw in
    List.rev raw
  | state, `Text ";" :: _ ->
    let pp_state ppf = function
      | `_0 -> Fmt.string ppf "<state:0>"
      | `_1 -> Fmt.string ppf "<state:1>"
      | `_2 -> Fmt.string ppf "<state:2>"
      | `R -> Fmt.string ppf "<remove-state>"
      | `S -> Fmt.string ppf "<stop-state>" in
    Fmt.invalid_arg "Bad raw input (state:%a)"
      pp_state state
  | _, _ -> assert false (* XXX(dinosaure): should never occur! *)

let body_hash_of_dkim body dkim =
  let digesti = digesti_of_hash (snd dkim.a) in
  match snd dkim.c with
  | Value.Simple -> digesti body.simple
  | Value.Relaxed -> digesti body.relaxed
  | Value.Canonicalization_ext x -> Fmt.invalid_arg "%s canonicalisation is not supported" x

let digest_fields
  : (Mrmime.Field.t * String.t) list -> dkim -> value
  = fun others dkim ->
  let digesti = digesti_of_hash (snd dkim.a) in
  let canonicalization = match fst dkim.c with
    | Value.Simple -> simple_field_canonicalization
    | Value.Relaxed -> relaxed_field_canonicalization
    | Value.Canonicalization_ext x -> Fmt.invalid_arg "%s canonicalisation is not supported" x in
  let q = Queue.create () in
  List.iter
    (fun requested ->
       try let field, raw = list_assoc ~equal:Mrmime.Field.equal requested others in
         Queue.push (field :> string) q ;
         Queue.push ":" q ;
         canonicalization raw (fun x -> Queue.push x q)
       with Not_found -> Fmt.invalid_arg "Field %a not found" Mrmime.Field.pp requested)
    dkim.h ;
  digesti (fun f -> Queue.iter f q)

let extract_server
  : type t backend.
    t -> backend state ->
    (module DNS with type t = t and type backend = backend) ->
    dkim -> (Map.t or_err, backend) io
  = fun (type t backend)
    (t:t) (state:backend state)
    (module Dns : DNS with type t = t and type backend = backend)
    (dkim:dkim) ->

    let (>>=) = state.bind in
    let return = state.return in

    let selector = dkim.s in
    let domain_name = dkim.d in
    let domain_name = Domain_name.prepend_exn ~hostname:false domain_name "_domainkey" in
    let domain_name = Domain_name.prepend_exn ~hostname:false domain_name selector in
    Dns.getaddrinfo t `TXT domain_name >>= function
    | Error _ as err -> return err
    | Ok vss ->
      let vs = List.map (String.concat "") vss in
      (* XXX(dinosaure): RFC 6376 said: Strings in a TXT RR MUST be concatenated
         together before use with no intervening whitespace. *)
      let vs = List.map parse_dkim_server_value vs in
      match list_first Rresult.R.is_ok vs with
      | None ->
        return (Rresult.R.error_msgf "%a does not contain any DKIM values" Domain_name.pp domain_name)
      | Some (Ok hmap) -> return (Ok hmap)
      | Some (Error _) -> assert false

let data_hash_of_dkim fields ((field_dkim : Mrmime.Field.t), raw_dkim) dkim =
  (* In hash step 2, the Signer/Verifiers MUST pass the following to the hash
     algorithm in the indicated order. *)
  let digesti = digesti_of_hash (snd dkim.a) in
  let canonicalization = match fst dkim.c with
    | Value.Simple -> simple_field_canonicalization
    | Value.Relaxed -> relaxed_field_canonicalization
    | Value.Canonicalization_ext x -> Fmt.invalid_arg "%s canonicalisation is not supported" x in
  let dkim_field_canonicalization = match fst dkim.c with
    | Value.Simple -> simple_dkim_field_canonicalization
    | Value.Relaxed -> relaxed_dkim_field_canonicalization
    | Value.Canonicalization_ext x -> Fmt.invalid_arg "%s canonicalisation is not supported" x in
  let q = Queue.create () in
  (* The header fields specified by the "h=" tag, in the order specified in that
     tag, and canonicalized using the header canonicalization algorithm
     specified in the "c=" tag. Each field MUST be terminated with a single
     CRLF. *)
  List.iter
    (fun requested ->
       try let _, raw = list_assoc ~equal:Mrmime.Field.equal requested fields in
         canonicalization raw (fun x -> Queue.push x q)
       with Not_found -> Fmt.invalid_arg "Field %a not found" Mrmime.Field.pp requested)
    dkim.h ;
  (* The DKIM-Signature header field that exists (verifying) or will be inserted
     (signing) in the message, with the value of the "b=" tag (including all
     surrounding whitespace) deleted (i.e., treated as the empty string),
     canonicalized using the header canonicalization algorithm specified in the
     "c=" tag, and without a trailing CRLF. *)
  let raw_dkim = remove_signature_of_raw_dkim raw_dkim in
  dkim_field_canonicalization field_dkim raw_dkim (fun x -> Queue.push x q) ;
  digesti (fun f -> Queue.iter f q)

let verify_body dkim body =
  let H (k, v) = body_hash_of_dkim body dkim in
  let H (k', v') = expected dkim in
  match equal_hash k k' with
  | Some Refl.Refl ->
    Digestif.equal k v v'
  | None -> false

let verify fields (dkim_signature:Mrmime.Field.t * raw) dkim server body =
  let _body_hash = body_hash_of_dkim body dkim in
  let H (k, data_hash) = data_hash_of_dkim fields dkim_signature dkim in
  (* DER-encoded X.509 RSAPublicKey. *)
  match X509.Encoding.public_of_cstruct (Cstruct.of_string server.p) with
  | Some (`RSA p) ->
    let hash_predicate a = match a, k with
      | `SHA1, Digestif.SHA1 -> true
      | `SHA224, Digestif.SHA224 -> true
      | `SHA256, Digestif.SHA256 -> true
      | `SHA384, Digestif.SHA384 -> true
      | `SHA512, Digestif.SHA512 -> true
      | `MD5, Digestif.MD5 -> true
      | _, _ -> false in
    let data_hash = `Digest (Cstruct.of_string (Digestif.to_raw_string k data_hash)) in
    let r0 = Nocrypto.Rsa.PKCS1.verify ~hashp:hash_predicate~key:p ~signature:(Cstruct.of_string dkim.b) data_hash in
    let r1 = verify_body dkim body in

    Logs.debug (fun f -> f "state of body: %b, state of header: %b" r1 r0) ;

    r0 && r1
  | Some (`EC_pub _) -> Fmt.invalid_arg "We did not handle EC public-key yet!"
  | None -> false
