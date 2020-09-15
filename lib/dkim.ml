module Refl = struct
  type ('a, 'b) t = Refl : ('a, 'a) t
end

module Body = Body
module Sigs = Sigs
module Map = Map
open Sigs

type (+'a, 'err) or_err = ('a, ([> Rresult.R.msg ] as 'err)) result

let ( <.> ) f g x = f (g x)

let parse_dkim_field_value unstrctrd =
  let str = Unstrctrd.to_utf_8_string unstrctrd in
  match Angstrom.parse_string ~consume:All Parser.mail_tag_list str with
  | Ok v -> Ok v
  | Error _ -> Rresult.R.error_msgf "Invalid DKIM Signature: %S" str

let parse_dkim_server_value str =
  let open Rresult in
  let _, unstrctrd = Unstrctrd.safely_decode str in
  let unstrctrd = Unstrctrd.fold_fws unstrctrd in
  match
    Angstrom.parse_string ~consume:All Parser.server_tag_list
      (Unstrctrd.to_utf_8_string unstrctrd)
  with
  | Ok _ as v -> v
  | Error _ -> Rresult.R.error_msgf "Invalid DKIM value"

type newline = CRLF | LF

let sub_string_and_replace_newline chunk len =
  let count = ref 0 in
  String.iter
    (function '\n' -> incr count | _ -> ())
    (Bytes.sub_string chunk 0 len) ;
  let plus = !count in
  let pos = ref 0 in
  let res = Bytes.create (len + plus) in
  for i = 0 to len - 1 do
    match Bytes.unsafe_get chunk i with
    | '\n' ->
        Bytes.unsafe_set res !pos '\r' ;
        Bytes.unsafe_set res (!pos + 1) '\n' ;
        pos := !pos + 2
    | chr ->
        Bytes.unsafe_set res !pos chr ;
        incr pos
  done ;
  Bytes.unsafe_to_string res

let sanitize_input newline chunk len =
  match newline with
  | CRLF -> Bytes.sub_string chunk 0 len
  | LF -> sub_string_and_replace_newline chunk len

let src = Logs.Src.create "dkim" ~doc:"logs dkim's event"

module Log = (val Logs.src_log src : Logs.LOG)

let field_dkim_signature = Mrmime.Field_name.v "DKIM-Signature"

type extracted = {
  dkim_fields : (Mrmime.Field_name.t * Unstrctrd.t * Map.t) list;
  fields : (Mrmime.Field_name.t * Unstrctrd.t) list;
  prelude : string;
}

let to_unstrctrd unstructured =
  let fold acc = function #Unstrctrd.elt as elt -> elt :: acc | _ -> acc in
  let unstrctrd = List.fold_left fold [] unstructured in
  Rresult.R.get_ok (Unstrctrd.of_list unstrctrd)

let p =
  let open Mrmime in
  let unstructured = Field.(Witness Unstructured) in
  let open Field_name in
  Map.empty
  |> Map.add date unstructured
  |> Map.add from unstructured
  |> Map.add sender unstructured
  |> Map.add reply_to unstructured
  |> Map.add (v "To") unstructured
  |> Map.add cc unstructured
  |> Map.add bcc unstructured
  |> Map.add subject unstructured
  |> Map.add message_id unstructured
  |> Map.add comments unstructured
  |> Map.add content_type unstructured
  |> Map.add content_encoding unstructured

let extract_dkim :
    type flow backend.
    ?newline:newline ->
    flow ->
    backend state ->
    (module FLOW with type flow = flow and type backend = backend) ->
    ((extracted, _) or_err, backend) io =
  fun (type flow backend) ?(newline = LF) (flow : flow) (state : backend state)
      (module Flow : FLOW with type flow = flow and type backend = backend) ->
   let open Mrmime in
   let ( >>= ) = state.bind in
   let return = state.return in

   let chunk = 0x1000 in
   let raw = Bytes.create chunk in
   let buffer = Bigstringaf.create (2 * chunk) in
   let decoder = Hd.decoder ~p buffer in
   let rec go others acc =
     match Hd.decode decoder with
     | `Field field -> (
         let (Field.Field (field_name, w, v)) = Location.prj field in
         match (Field_name.equal field_name field_dkim_signature, w) with
         | true, Field.Unstructured -> (
             let v = to_unstrctrd v in
             match parse_dkim_field_value v with
             | Ok dkim -> go others ((field_name, v, dkim) :: acc)
             | Error (`Msg _) -> go others acc)
         | false, Field.Unstructured ->
             let v = to_unstrctrd v in
             go ((field_name, v) :: others) acc
         (* TODO(dinosaure): [mrmime] tries to parse some specific fields
          * such as [Date:] with their formats. [p] enforces to parse all
          * of these fields with [Unstructured].
          *
          * So, we can not have something else than [Unstructured] - however,
          * from the POV of the API, it's not so good to do that (so an update
          * of [mrmime] should be done). *)
         | _ -> assert false)
     | `Malformed err ->
         Log.err (fun m -> m "The given email is malformed: %s." err) ;
         return (Rresult.R.error_msg err)
     | `End rest ->
         return
           (Rresult.R.ok
              {
                prelude = rest;
                fields = List.rev others;
                dkim_fields = List.rev acc;
              })
     | `Await -> (
         Flow.input flow raw 0 (Bytes.length raw) >>= fun len ->
         let raw = sanitize_input newline raw len in
         match Hd.src decoder raw 0 (String.length raw) with
         | Ok () -> go others acc
         | Error _ as err -> return err) in
   go [] []

type dkim = {
  v : int;
  a : Value.algorithm * hash;
  b : string;
  bh : value;
  c : Value.canonicalization * Value.canonicalization;
  d : [ `host ] Domain_name.t;
  h : Mrmime.Field_name.t list;
  i : Value.auid option;
  l : int option;
  q : Value.query list;
  s : string;
  t : int64 option;
  x : int64 option;
  z : (Mrmime.Field_name.t * string) list;
}

and hash = V : 'k Digestif.hash -> hash

and value = H : 'k Digestif.hash * 'k Digestif.t -> value

let selector { s; _ } = s

let domain { d; _ } = d

type server = {
  v : Value.server_version;
  h : hash list;
  k : Value.algorithm;
  n : string option;
  p : string;
  s : Value.service list;
  t : Value.name list;
}

let pp_hash ppf (V hash) =
  let open Digestif in
  match hash with
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
  | _ -> assert false

let equal_hash :
    type a b. a Digestif.hash -> b Digestif.hash -> (a, b) Refl.t option =
 fun a b ->
  let open Digestif in
  match (a, b) with
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

let pp_signature (V hash) ppf (H (hash', value)) =
  match equal_hash hash hash' with
  | Some Refl.Refl -> Digestif.pp hash ppf value
  | None -> assert false

(* XXX(dinosaure): should never occur. *)

let pp_hex ppf str =
  for i = 0 to String.length str - 1 do
    Fmt.pf ppf "%02x" (Char.code str.[i])
  done

let pp_dkim ppf (t : dkim) =
  Fmt.pf ppf
    "{ @[<hov>v = %d;@ a = %a;@ b = %a;@ bh = %a;@ c = %a;@ d = %a;@ h = \
     @[<hov>%a@];@ i = @[<hov>%a@];@ l = %a;@ q = @[<hov>%a@];@ s = %s;@ t = \
     %a;@ x = %a;@ z = @[<hov>%a@];@] }"
    t.v
    Fmt.(Dump.pair Value.pp_algorithm pp_hash)
    t.a pp_hex t.b
    (pp_signature (snd t.a))
    t.bh
    Fmt.(Dump.pair Value.pp_canonicalization Value.pp_canonicalization)
    t.c Domain_name.pp t.d
    Fmt.(Dump.list Mrmime.Field_name.pp)
    t.h
    Fmt.(Dump.option Value.pp_auid)
    t.i
    Fmt.(Dump.option int)
    t.l
    Fmt.(Dump.list Value.pp_query)
    t.q t.s
    Fmt.(Dump.option int64)
    t.t
    Fmt.(Dump.option int64)
    t.x
    Fmt.(Dump.list Value.pp_copy)
    t.z

let pp_server ppf (t : server) =
  Fmt.pf ppf
    "{ @[<hov>v = %s;@ h = @[<hov>%a@];@ k = %a;@ n = %a;@ p = %a;@ s = \
     @[<hov>%a@];@ t = @[<hov>%a@];@] }"
    t.v
    Fmt.(Dump.list pp_hash)
    t.h Value.pp_algorithm t.k
    Fmt.(Dump.option string)
    t.n pp_hex t.p
    Fmt.(Dump.list Value.pp_service)
    t.s
    Fmt.(Dump.list Value.pp_name)
    t.t

let expected { bh; _ } = bh

let hash = function
  | Value.SHA1 -> V Digestif.SHA1
  | Value.SHA256 -> V Digestif.SHA256
  | Value.Hash_ext x ->
  match String.lowercase_ascii x with
  | "sha512" -> V Digestif.SHA512
  | x -> Fmt.invalid_arg "Invalid kind of hash <%s>" x

let string_of_quoted_printable x =
  let decoder = Pecu.Inline.decoder (`String x) in
  let res = Buffer.create 0x800 in
  let rec go () =
    match Pecu.Inline.decode decoder with
    | `Await -> assert false
    | `Char chr ->
        Buffer.add_char res chr ;
        go ()
    | `End -> Rresult.R.ok (Buffer.contents res)
    | `Malformed err -> Rresult.R.error_msg err in
  go ()

module SSet = Set.Make (Mrmime.Field_name)

let uniq = List.sort_uniq Mrmime.Field_name.compare

let post_process_dkim hmap =
  let v =
    match Map.find Map.K.v hmap with
    | Some v -> v
    | None -> Fmt.invalid_arg "Version is required" in
  let a =
    match Map.find Map.K.a hmap with
    | Some (alg, x) -> (alg, hash x)
    | None -> Fmt.invalid_arg "Algorithm is required" in
  let b =
    match Option.map Base64.decode (Map.find Map.K.b hmap) with
    | Some (Ok v) -> v
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Signature data is required" in
  let bh =
    match Option.map Base64.decode (Map.find Map.K.bh hmap) with
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Hash of canonicalized body part is required"
    | Some (Ok v) -> (
        let _, V k = a in
        match Digestif.of_raw_string_opt k v with
        | Some v -> H (k, v)
        | None -> Fmt.invalid_arg "Invalid hash") in
  let c =
    match Map.find Map.K.c hmap with
    | Some v -> v
    | None -> (Value.Simple, Value.Simple) in
  let d =
    match Map.find Map.K.d hmap with
    | Some v ->
        (Domain_name.host_exn <.> Domain_name.of_string_exn)
          (String.concat "." v)
    | None -> Fmt.invalid_arg "SDID is required" in
  let h =
    match Map.find Map.K.h hmap with
    | Some v -> uniq v
    (* XXX(dinosaure):
       - [Parser.field_name] checks values. So, no post-process is required.
       - uniqify [h],however, I'm clearly not sure about that but [From] can
       appear multiple times and need to be digest only one time. RFC 6376 does
       not explain this behavior (tips from dkimpy). *)
    | None -> Fmt.invalid_arg "Signed header fields required" in
  let i = Map.find Map.K.i hmap in
  let l = Map.find Map.K.l hmap in
  let q =
    List.map
      (fun (q, x) ->
        match Option.map string_of_quoted_printable x with
        | None -> (q, None)
        | Some (Ok x) -> (q, Some x)
        | Some (Error (`Msg err)) -> invalid_arg err)
      (Option.value ~default:[] (Map.find Map.K.q hmap)) in
  let s =
    match Option.map (String.concat ".") (Map.find Map.K.s hmap) with
    | Some v -> v
    | None -> Fmt.invalid_arg "Selector is required" in
  let t = Map.find Map.K.t hmap in
  let x = Map.find Map.K.x hmap in
  let z =
    List.map
      (fun (f, x) ->
        match string_of_quoted_printable x with
        | Ok x -> (f, x)
        | Error (`Msg err) -> invalid_arg err)
      Option.(value ~default:[] (Map.find Map.K.z hmap)) in
  { v; a; b; bh; c; d; h; i; l; q; s; t; x; z }

let post_process_dkim hmap =
  try Rresult.R.ok (post_process_dkim hmap)
  with Invalid_argument err -> Rresult.R.error_msg err

let post_process_server hmap =
  let v = Option.value ~default:"DKIM1" (Map.find Map.K.sv hmap) in
  let h =
    Option.value
      ~default:[ V Digestif.SHA1; V Digestif.SHA256 ]
      (Option.map (List.map hash) (Map.find Map.K.sh hmap)) in
  let k = Option.value ~default:Value.RSA (Map.find Map.K.k hmap) in
  let n = Map.find Map.K.n hmap in
  let p =
    match Option.map Base64.decode (Map.find Map.K.p hmap) with
    | Some (Ok p) -> p
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Public-key is required" in
  let s = Option.value ~default:[ Value.All ] (Map.find Map.K.ss hmap) in
  let t = Option.value ~default:[] (Map.find Map.K.st hmap) in
  { v; h; k; n; p; s; t }

let post_process_server hmap =
  try Rresult.R.ok (post_process_server hmap)
  with Invalid_argument err -> Rresult.R.error_msg err

let digesti_of_hash (V hash) f =
  let v = Digestif.digesti_string hash f in
  H (hash, v)

let simple_field_canonicalization (field_name : Mrmime.Field_name.t) unstrctrd f
    =
  (* TODO: delete trailing CRLF. *)
  f (field_name :> string) ;
  f ":" ;
  f (Unstrctrd.to_utf_8_string unstrctrd)

let simple_dkim_field_canonicalization (dkim_field : Mrmime.Field_name.t) raw f
    =
  f (dkim_field :> string) ;
  f ":" ;
  f Unstrctrd.(to_utf_8_string raw)

let trim unstrctrd =
  let wsp = ref true in
  let fold acc = function
    | `WSP _ when !wsp -> acc
    | elt ->
        wsp := false ;
        elt :: acc in
  Unstrctrd.fold ~f:fold [] unstrctrd |> fun lst ->
  wsp := true ;
  List.fold_left fold [] lst |> Unstrctrd.of_list |> Rresult.R.get_ok

let relaxed_field_canonicalization (field_name : Mrmime.Field_name.t) unstrctrd
    f =
  f (String.lowercase_ascii (field_name :> string)) ;
  f ":" ;
  let unstrctrd = trim unstrctrd in
  let buf = Buffer.create 8 in
  let iter : Unstrctrd.elt -> unit = function
    | `CR -> f "\r"
    | `FWS _wsp -> f " "
    | `Invalid_char chr -> f (String.make 1 (chr :> char))
    | `LF -> f "\n"
    | `OBS_NO_WS_CTL chr -> f (String.make 1 (chr :> char))
    | `Uchar uchar ->
        Uutf.Buffer.add_utf_8 buf uchar ;
        f (Buffer.contents buf) ;
        Buffer.clear buf
    | `WSP _wsp -> f " "
    | `d0 -> f "\000" in
  Unstrctrd.iter ~f:iter unstrctrd

let relaxed_dkim_field_canonicalization (dkim_field : Mrmime.Field_name.t) raw f
    =
  (* XXX(dinosaure): should be [f "dkim-signature:"]. *)
  f (String.lowercase_ascii (dkim_field :> string)) ;
  f ":" ;
  (* XXX(dinosaure): duplicate with [relaxed_field_canonicalization] without
     ["DKIM-Signature"] and trailing [CRLF]. TODO! *)
  f Unstrctrd.(to_utf_8_string (fold_fws raw))

let crlf digest n =
  let rec go = function
    | 0 -> ()
    | n ->
        digest "\r\n" ;
        go (pred n) in
  if n < 0 then Fmt.invalid_arg "Expect at least 0 <crlf>" else go n

type iter = string Digestif.iter

type body = { relaxed : iter; simple : iter }

let extract_body :
    type flow backend.
    ?newline:newline ->
    flow ->
    backend state ->
    (module FLOW with type flow = flow and type backend = backend) ->
    prelude:string ->
    (body, backend) io =
 fun ?(newline = LF) (type flow backend) (flow : flow) (state : backend state)
     (module Flow : FLOW with type flow = flow and type backend = backend)
     ~prelude ->
  let ( >>= ) = state.bind in
  let return = state.return in

  let decoder = Body.decoder () in
  let chunk = 0x1000 in
  let raw = Bytes.create (max chunk (String.length prelude)) in
  let qr = Queue.create () in
  let qs = Queue.create () in
  let fr x = Queue.push x qr in
  let fs x = Queue.push x qs in

  Bytes.blit_string prelude 0 raw 0 (String.length prelude) ;

  (* XXX(dinosaure): [prelude] comes from [extract_dkim] and should be [<= 0x1000].
     Seems to be not true. *)
  let digest_stack ?(relaxed = false) f l =
    let rec go = function
      | [] -> ()
      | [ `Spaces x ] -> f (if relaxed then " " else x)
      | `CRLF :: r ->
          f "\r\n" ;
          go r
      | `Spaces x :: r ->
          if not relaxed then f x ;
          go r in
    go (List.rev l) in
  let rec go stack =
    match Body.decode decoder with
    | `Await ->
        Flow.input flow raw 0 (Bytes.length raw) >>= fun len ->
        let raw = sanitize_input newline raw len in
        Body.src decoder (Bytes.of_string raw) 0 (String.length raw) ;
        go stack
    | `End ->
        crlf fr 1 ;
        crlf fs 1 ;
        return ()
    | `Spaces _ as x -> go (x :: stack)
    | `CRLF -> go (`CRLF :: stack)
    | `Data x ->
        digest_stack ~relaxed:true fr stack ;
        fr x ;
        digest_stack fs stack ;
        fs x ;
        go [] in
  Body.src decoder raw 0 (String.length prelude) ;
  go [] >>= fun () ->
  return
    {
      relaxed = (fun f -> Queue.iter f qr);
      simple = (fun f -> Queue.iter f qs);
    }

(* XXX(dinosaure): seriously, going to hell DKIM! From [dkimpy]:
   re.compile(br[\s]b'+FWS+br'=) (?:'+FWS+br'[a-zA-Z0-9+/=])*(?:\r?\n\Z)?' this is does
   NOT MEAN ANYTHING BOY. *)

(* TODO *)
let remove_signature_of_raw_dkim unstrctrd =
  let fold (acc, state) elt =
    match (elt, state) with
    | `Uchar uchar, _ -> (
        if Uchar.is_char uchar
        then
          match (Uchar.to_char uchar, state) with
          | 'b', `_0 -> (elt :: acc, `_1)
          | '=', `_1 -> (elt :: acc, `_2)
          | ';', `_2 -> (elt :: acc, `_3)
          | _, `_0 -> (elt :: acc, `_0)
          | _, `_1 -> (elt :: acc, `_0)
          | _, `_2 -> (acc, `_2)
          | _, `_3 -> (elt :: acc, `_3)
        else
          match state with
          | `_0 | `_1 -> (elt :: acc, `_0)
          | `_3 -> (elt :: acc, `_3)
          | `_2 -> (acc, `_2))
    | elt, (`_0 | `_1) -> (elt :: acc, `_0)
    | _, `_2 -> (acc, `_2)
    | elt, `_3 -> (elt :: acc, `_3) in
  let res, _ = Unstrctrd.fold ~f:fold ([], `_0) unstrctrd in
  Rresult.R.get_ok (Unstrctrd.of_list (List.rev res))

let body_hash_of_dkim body dkim =
  let digesti = digesti_of_hash (snd dkim.a) in
  match snd dkim.c with
  | Value.Simple -> digesti body.simple
  | Value.Relaxed -> digesti body.relaxed
  | Value.Canonicalization_ext x ->
      Fmt.invalid_arg "%s canonicalisation is not supported" x

let extract_server :
    type t backend.
    t ->
    backend state ->
    (module DNS with type t = t and type backend = backend) ->
    dkim ->
    ((Map.t, _) or_err, backend) io =
  fun (type t backend) (t : t) (state : backend state)
      (module Dns : DNS with type t = t and type backend = backend)
      (dkim : dkim) ->
   let ( >>= ) = state.bind in
   let return = state.return in

   let selector = dkim.s in
   let domain_name = dkim.d in
   let domain_name = Domain_name.prepend_label_exn domain_name "_domainkey" in
   let domain_name = Domain_name.prepend_label_exn domain_name selector in
   Dns.getaddrinfo t `TXT domain_name >>= function
   | Error _ as err -> return err
   | Ok vs -> (
       (* XXX(dinosaure): RFC 6376 said: Strings in a TXT RR MUST be concatenated
          together before use with no intervening whitespace. *)
       let vs = List.map parse_dkim_server_value vs in
       match List.find_opt Rresult.R.is_ok vs with
       | None ->
           return
             (Rresult.R.error_msgf "%a does not contain any DKIM values"
                Domain_name.pp domain_name)
       | Some v -> return v)

let data_hash_of_dkim fields ((field_dkim : Mrmime.Field_name.t), raw_dkim) dkim
    =
  (* In hash step 2, the Signer/Verifiers MUST pass the following to the hash
     algorithm in the indicated order. *)
  let digesti = digesti_of_hash (snd dkim.a) in
  let canonicalization =
    match fst dkim.c with
    | Value.Simple -> simple_field_canonicalization
    | Value.Relaxed -> relaxed_field_canonicalization
    | Value.Canonicalization_ext x ->
        Fmt.invalid_arg "%s canonicalisation is not supported" x in
  let dkim_field_canonicalization =
    match fst dkim.c with
    | Value.Simple -> simple_dkim_field_canonicalization
    | Value.Relaxed -> relaxed_dkim_field_canonicalization
    | Value.Canonicalization_ext x ->
        Fmt.invalid_arg "%s canonicalisation is not supported" x in
  let q = Queue.create () in
  (* The header fields specified by the "h=" tag, in the order specified in that
     tag, and canonicalized using the header canonicalization algorithm
     specified in the "c=" tag. Each field MUST be terminated with a single
     CRLF. *)
  List.iter
    (fun requested ->
      match List.filter (Mrmime.Field_name.equal requested <.> fst) fields with
      | (field_name, unstrctrd) :: _ ->
          canonicalization field_name unstrctrd (fun x -> Queue.push x q)
      | [] ->
          Fmt.invalid_arg "Field %a not found" Mrmime.Field_name.pp requested)
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
  let (H (k, v)) = body_hash_of_dkim body dkim in
  let (H (k', v')) = expected dkim in
  match equal_hash k k' with
  | Some Refl.Refl -> Digestif.equal k v v'
  | None -> false

let verify fields (dkim_signature : Mrmime.Field_name.t * Unstrctrd.t) dkim
    server body =
  let _body_hash = body_hash_of_dkim body dkim in
  let (H (k, data_hash)) = data_hash_of_dkim fields dkim_signature dkim in
  (* DER-encoded X.509 RSAPublicKey. *)
  match X509.Public_key.decode_der (Cstruct.of_string server.p) with
  | Ok (`RSA p) ->
      let hash_predicate a =
        match (a, k) with
        | `SHA1, Digestif.SHA1 -> true
        | `SHA224, Digestif.SHA224 -> true
        | `SHA256, Digestif.SHA256 -> true
        | `SHA384, Digestif.SHA384 -> true
        | `SHA512, Digestif.SHA512 -> true
        | `MD5, Digestif.MD5 -> true
        | _, _ -> false in

      let data_hash =
        `Digest (Cstruct.of_string (Digestif.to_raw_string k data_hash)) in
      let r0 =
        Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp:hash_predicate ~key:p
          ~signature:(Cstruct.of_string dkim.b) data_hash in
      let r1 = verify_body dkim body in

      Logs.debug (fun f -> f "state of body: %b, state of header: %b" r1 r0) ;

      r0 && r1
  | Ok (`EC_pub _) -> Fmt.invalid_arg "We did not handle EC public-key yet!"
  | Error _ -> false
