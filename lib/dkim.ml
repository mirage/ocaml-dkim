let src = Logs.Src.create "dkim"

module Log = (val Logs.src_log src : Logs.LOG)
module Body = Body
module Decoder = Decoder

type hash_algorithm = Hash_algorithm : 'k Digestif.hash -> hash_algorithm
type hash_value = Hash_value : 'k Digestif.hash * 'k Digestif.t -> hash_value

module Hash = struct
  let pp ppf (Hash_algorithm hash) =
    let open Digestif in
    match hash with
    | SHA1 -> Fmt.string ppf "sha1"
    | SHA256 -> Fmt.string ppf "sha256"
    | _ -> assert false
end

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let invalid_argf = Fmt.invalid_arg
let failwith_error_msg = function Ok v -> v | Error (`Msg err) -> failwith err

type map = Map.t

let ( % ) f g x = f (g x)

let trim unstrctrd =
  let fold acc = function
    | `FWS _ | `CR | `LF | `WSP _ -> acc
    | elt -> elt :: acc in
  Unstrctrd.fold ~f:fold [] unstrctrd |> List.rev |> Unstrctrd.of_list
  |> function
  | Ok v -> v
  | Error _ -> assert false

let of_unstrctrd unstrctrd =
  let str = Unstrctrd.(to_utf_8_string (trim unstrctrd)) in
  match Angstrom.parse_string ~consume:All Decoder.mail_tag_list str with
  | Ok v -> Ok v
  | Error err ->
      Log.err (fun m -> m "Got an error while parsing DKIM-Signature: %s" err) ;
      error_msgf "Invalid DKIM Signature: %S" str
  | exception exn ->
      Log.err (fun m ->
          m "Unexpected exception while parsing DKIM-Signature: %s"
            (Printexc.to_string exn)) ;
      error_msgf "Invalid DKIM Signature: %S" str

let field_dkim_signature = Mrmime.Field_name.v "DKIM-Signature"

let to_unstrctrd unstructured =
  let fold acc = function #Unstrctrd.elt as elt -> elt :: acc | _ -> acc in
  let unstrctrd = List.fold_left fold [] unstructured in
  Result.get_ok (Unstrctrd.of_list (List.rev unstrctrd))

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

type 'bbh t = {
  v : int;
  a : Value.algorithm * hash_algorithm;
  c : Value.canonicalization * Value.canonicalization;
  d : [ `raw ] Domain_name.t;
  h : Mrmime.Field_name.t list;
  i : Value.auid option;
  l : int option;
  q : Value.query list;
  s : [ `raw ] Domain_name.t;
  t : int64 option;
  x : int64 option;
  z : (Mrmime.Field_name.t * string) list;
  bbh : 'bbh;
}

and signed = string * hash_value
and unsigned = unit

type domain_key = {
  v : Value.server_version;
  h : hash_algorithm list;
  k : Value.algorithm;
  n : string option;
  p : string;
  s : Value.service list;
  t : Value.name list;
}

type hash = [ `SHA1 | `SHA256 ]
type algorithm = [ `RSA | `ED25519 ]
type canonicalization = [ `Simple | `Relaxed ]
type query = [ `DNS of [ `TXT ] ]

type key =
  [ `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]

let domain_key_of_dkim : key:key -> 'a t -> domain_key =
 fun ~key dkim ->
  let p =
    match (fst dkim.a, key) with
    | Value.RSA, `RSA key ->
        let pub = Mirage_crypto_pk.Rsa.pub_of_priv key in
        X509.Public_key.encode_der (`RSA pub)
    | Value.ED25519, `ED25519 key ->
        let pub = Mirage_crypto_ec.Ed25519.pub_of_priv key in
        X509.Public_key.encode_der (`ED25519 pub)
    | _ -> failwith "Dkim.domain_key_of_dkim: invalid type of key" in
  let k, h = dkim.a in
  { v = "DKIM1"; h = [ h ]; n = None; k; p; s = [ Value.All ]; t = [] }

let domain_key_to_string domain_key =
  let k_to_string = function
    | Value.RSA -> "rsa"
    | Value.ED25519 -> "ed25519"
    | Value.Algorithm_ext v -> v in
  let h_to_string lst =
    let h_to_string = function
      | Hash_algorithm Digestif.SHA1 -> "sha1"
      | Hash_algorithm Digestif.SHA256 -> "sha256"
      | _ -> assert false in
    let buf = Buffer.create 0x7f in
    let rec go = function
      | [] -> Buffer.contents buf
      | [ x ] ->
          Buffer.add_string buf (h_to_string x) ;
          Buffer.contents buf
      | x :: r ->
          Buffer.add_string buf (h_to_string x) ;
          Buffer.add_char buf ':' ;
          go r in
    go lst in
  let lst =
    [
      ("v", domain_key.v);
      ("p", Base64.encode_exn ~pad:true domain_key.p);
      ("k", k_to_string domain_key.k);
    ] in
  let lst =
    match domain_key.h with [] -> lst | h -> ("h", h_to_string h) :: lst in
  let lst =
    Option.fold ~none:lst ~some:(fun n -> ("n", n) :: lst) domain_key.n in
  let buf = Buffer.create 0x7f in
  let ppf = Format.formatter_of_buffer buf in
  let rec go ppf = function
    | [] -> Format.fprintf ppf "%!"
    | [ (k, v) ] -> Format.fprintf ppf "%s=%s;" k v
    | (k, v) :: r ->
        Format.fprintf ppf "%s=%s; " k v ;
        go ppf r in
  go ppf lst ;
  Buffer.contents buf

let pp : type a. a t Fmt.t =
 fun ppf t ->
  Fmt.pf ppf
    "{ @[<hov>v = %d;@ a = %a;@ c = %a;@ d = %a;@ h = @[<hov>%a@];@ i = \
     @[<hov>%a@];@ l = %a;@ q = @[<hov>%a@];@ s = %a;@ t = %a;@ x = %a;@ z = \
     @[<hov>%a@];@] }"
    t.v
    Fmt.(Dump.pair Value.pp_algorithm Hash.pp)
    t.a
    Fmt.(Dump.pair Value.pp_canonicalization Value.pp_canonicalization)
    t.c Domain_name.pp t.d
    Fmt.(Dump.list Mrmime.Field_name.pp)
    t.h
    Fmt.(Dump.option Value.pp_auid)
    t.i
    Fmt.(Dump.option int)
    t.l
    Fmt.(Dump.list Value.pp_query)
    t.q Domain_name.pp t.s
    Fmt.(Dump.option int64)
    t.t
    Fmt.(Dump.option int64)
    t.x
    Fmt.(Dump.list Value.pp_copy)
    t.z

module SSet = Set.Make (Mrmime.Field_name)

let hash = function
  | Value.SHA1 -> Hash_algorithm Digestif.SHA1
  | Value.SHA256 -> Hash_algorithm Digestif.SHA256
  | Value.Hash_ext x ->
  match String.lowercase_ascii x with
  | "sha512" -> Hash_algorithm Digestif.SHA512
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
    | `End -> Ok (Buffer.contents res)
    | `Malformed err -> error_msgf "%s" err in
  go ()

let post_process_dkim hmap =
  let v =
    match Map.find Map.K.v hmap with Some v -> v | None -> 1
    (* XXX(dinosaure): because ARC-{Seal,Message-Signature} does not specify it.
                   But DKIM should fail, the version is required. *)
  in
  let a =
    match Map.find Map.K.a hmap with
    | Some (alg, x) -> (alg, hash x)
    | None -> Fmt.failwith "Algorithm is required" in
  let b =
    match Option.map (Base64.decode ~pad:false) (Map.find Map.K.b hmap) with
    | Some (Ok v) -> v
    | Some (Error (`Msg err)) -> failwith err
    | None -> Fmt.failwith "Signature data is required" in
  let bh =
    match Option.map (Base64.decode ~pad:false) (Map.find Map.K.bh hmap) with
    | Some (Error (`Msg err)) -> failwith err
    | None ->
        let _, Hash_algorithm k = a in
        Hash_value (k, Digestif.digest_string k "")
        (* Fmt.failwith "Hash of canonicalized body part is required" *)
    | Some (Ok v) -> begin
        let _, Hash_algorithm k = a in
        match Digestif.of_raw_string_opt k v with
        | Some v -> Hash_value (k, v)
        | None -> Fmt.failwith "Invalid hash"
      end in
  let c =
    match Map.find Map.K.c hmap with
    | Some v -> v
    | None -> (Value.Simple, Value.Simple) in
  let d =
    match Map.find Map.K.d hmap with
    | Some v -> failwith_error_msg (Domain_name.of_string (String.concat "." v))
    | None -> Fmt.failwith "SDID is required" in
  let h = match Map.find Map.K.h hmap with Some v -> v | None -> [] in
  (* TODO: explain even if, from DKIM perspective, it's required *)
  let i = Map.find Map.K.i hmap in
  let l = Map.find Map.K.l hmap in
  let q =
    List.map
      (fun (q, x) ->
        match Option.map string_of_quoted_printable x with
        | None -> (q, None)
        | Some (Ok x) -> (q, Some x)
        | Some (Error (`Msg err)) -> failwith err)
      (Option.value ~default:[] (Map.find Map.K.q hmap)) in
  let s =
    match Map.find Map.K.s hmap with
    | Some v -> failwith_error_msg (Domain_name.of_string (String.concat "." v))
    | None -> Fmt.failwith "Selector is required" in
  let t = Map.find Map.K.t hmap in
  let x = Map.find Map.K.x hmap in
  let z =
    List.map
      (fun (f, x) ->
        match string_of_quoted_printable x with
        | Ok x -> (f, x)
        | Error (`Msg err) -> failwith err)
      Option.(value ~default:[] (Map.find Map.K.z hmap)) in
  (* TODO(dinosaure): b, bh *)
  { v; a; c; d; h; i; l; q; s; t; x; z; bbh = (b, bh) }

let expire ({ t; _ } : _ t) = t

let canonicalization ({ c; _ } : _ t) =
  let to_c = function
    | Value.Relaxed -> `Relaxed
    | Value.Simple -> `Simple
    | Value.Canonicalization_ext str ->
        Fmt.failwith "Invalid canonicalization: %s" str in
  (to_c (fst c), to_c (snd c))

let with_canonicalization t (a, b) =
  let of_c = function `Relaxed -> Value.Relaxed | `Simple -> Value.Simple in
  { t with c = (of_c a, of_c b) }

let with_signature_and_hash t bbh = { t with bbh }

let body : signed t -> string =
 fun { bbh = _, Hash_value (m, hash); _ } -> Digestif.to_raw_string m hash

let fields ({ h; _ } : _ t) = h
let domain { d; _ } = d
let selector ({ s; _ } : _ t) = s
let hash_algorithm ({ a; _ } : _ t) = snd a
let signature_and_hash { bbh; _ } = bbh

let algorithm ({ a; _ } : _ t) =
  match fst a with
  | Value.RSA -> `RSA
  | Value.ED25519 -> `ED25519
  | Value.Algorithm_ext v -> Fmt.failwith "Unsupported algorithm: %s" v

let domain_name : 'a t -> ([ `raw ] Domain_name.t, [> `Msg of string ]) result =
 fun t ->
  let open Domain_name in
  Result.bind (prepend_label t.d "_domainkey") (append t.s)

let post_process_domain_key hmap =
  let v = Option.value ~default:"DKIM1" (Map.find Map.K.sv hmap) in
  let h =
    Option.value
      ~default:[ Hash_algorithm Digestif.SHA1; Hash_algorithm Digestif.SHA256 ]
      (Option.map (List.map hash) (Map.find Map.K.sh hmap)) in
  let k = Option.value ~default:Value.RSA (Map.find Map.K.k hmap) in
  let n = Map.find Map.K.n hmap in
  let p =
    match Option.map (Base64.decode ~pad:false) (Map.find Map.K.p hmap) with
    | Some (Ok p) -> p
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Public-key is required" in
  let s = Option.value ~default:[ Value.All ] (Map.find Map.K.ss hmap) in
  let t = Option.value ~default:[] (Map.find Map.K.st hmap) in
  { v; h; k; n; p; s; t }

let post_process_domain_key hmap =
  try Ok (post_process_domain_key hmap)
  with Invalid_argument err -> error_msgf "%s" err

let domain_key_of_string str =
  let _, unstrctrd = Unstrctrd.safely_decode str in
  let unstrctrd = trim unstrctrd in
  let str = Unstrctrd.to_utf_8_string unstrctrd in
  let res = Angstrom.parse_string ~consume:All Decoder.server_tag_list str in
  let res = Result.map_error (fun msg -> `Msg msg) res in
  match Result.bind res post_process_domain_key with
  | Ok _ as v -> v
  | Error _ | (exception _) -> error_msgf "Invalid domain-key value"

let public_key ({ p; _ } : domain_key) = p

let trim unstrctrd =
  let space = Unstrctrd.wsp ~len:1 in
  let fold (acc, state) elt =
    match elt with
    | (`WSP _ | `FWS _) when state -> (acc, true)
    | `WSP _ | `FWS _ -> (space :: acc, state)
    | elt -> (elt :: acc, false) in
  Unstrctrd.fold ~f:fold ([], true) unstrctrd |> fun (lst, _) ->
  List.fold_left fold ([], true) lst |> fun (lst, _) ->
  Unstrctrd.of_list lst |> function Ok v -> v | Error _ -> assert false

let uniq unstrctrd =
  let fold (acc, state) elt =
    match elt with
    | (`FWS _ | `WSP _) when state -> (acc, true)
    | `FWS _ | `WSP _ -> (elt :: acc, true)
    | elt -> (elt :: acc, false) in
  Unstrctrd.fold ~f:fold ([], false) unstrctrd |> fun (lst, _) ->
  Unstrctrd.of_list (List.rev lst) |> Result.get_ok

let remove_signature_of_dkim unstrctrd =
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
  Unstrctrd.of_list (List.rev res) |> Result.get_ok

let assoc field_name fields =
  let res = ref None in
  List.iter
    (fun ((field_name', _) as v) ->
      if Mrmime.Field_name.equal field_name field_name' && Option.is_none !res
      then res := Some v)
    fields ;
  !res

let remove_assoc field_name fields =
  let fold (res, deleted) ((field_name', _) as v) =
    if Mrmime.Field_name.equal field_name field_name' && not deleted
    then (res, true)
    else (v :: res, deleted) in
  let res, _ = List.fold_left fold ([], false) fields in
  List.rev res

module Canon = struct
  let of_fields dkim =
    match fst dkim.c with
    | Value.Simple ->
        fun (fn : Mrmime.Field_name.t) unstrctrd k ctx ->
          let ctx = k ctx (fn :> string) in
          let ctx = k ctx ":" in
          k ctx (Unstrctrd.to_utf_8_string unstrctrd)
    | Value.Relaxed ->
        fun (fn : Mrmime.Field_name.t) unstrctrd k ctx ->
          let ctx = k ctx (String.lowercase_ascii (fn :> string)) in
          let ctx = k ctx ":" in
          let ctx =
            k ctx ((Unstrctrd.to_utf_8_string % uniq % trim) unstrctrd) in
          k ctx "\r\n"
    | _ -> failwith "Invalid canonicalization"

  let of_dkim_fields dkim =
    match fst dkim.c with
    | Value.Simple ->
        fun (fn : Mrmime.Field_name.t) unstrctrd k ctx ->
          let ctx = k ctx (fn :> string) in
          let ctx = k ctx ":" in
          let unstrctrd = remove_signature_of_dkim unstrctrd in
          k ctx (Unstrctrd.to_utf_8_string unstrctrd)
    | Value.Relaxed ->
        fun (fn : Mrmime.Field_name.t) unstrctrd k ctx ->
          let ctx = k ctx (String.lowercase_ascii (fn :> string)) in
          let ctx = k ctx ":" in
          let unstrctrd = (uniq % trim % remove_signature_of_dkim) unstrctrd in
          k ctx (Unstrctrd.to_utf_8_string unstrctrd)
    | _ -> failwith "Invalid canonicalization"
end

module Digest = struct
  type 'a dkim = 'a t

  type 'k t = Digest : { m : ('k, 'ctx) impl; ctx : 'ctx } -> 'k t
  and ('k, 'ctx) impl = (module Digestif.S with type t = 'k and type ctx = 'ctx)
  and ('signed, 'k) value = 'signed dkim * 'k t
  and pack = Value : (signed, 'k) value -> pack

  let digest_fields others (field_name, raw, dkim, _dk) =
    let (Hash_algorithm a) = snd dkim.a in
    let module Hash = (val Digestif.module_of a) in
    let feed_string ctx str = Hash.feed_string ctx str in
    let canon = Canon.of_fields dkim in
    let fn (ctx, fields) reqs =
      match assoc reqs fields with
      | Some (fn, unstrctrd) ->
          let ctx = canon fn unstrctrd feed_string ctx in
          (ctx, remove_assoc fn fields)
      | None -> (ctx, fields) in
    let ctx, _ = List.fold_left fn (Hash.empty, others) dkim.h in
    let canon = Canon.of_dkim_fields dkim in
    let ctx = canon field_name raw feed_string ctx in
    let fields = Hash.get ctx in
    let fields = Hash.to_raw_string fields in
    let digest = Digest { m = (module Hash); ctx = Hash.empty } in
    (fields, Value (dkim, digest))

  let digest_wsp : type signed k. _ -> (signed, k) value -> (signed, k) value =
   fun payloads (dkim, Digest { m; ctx }) ->
    let module Hash = (val m) in
    let relaxed =
      match snd dkim.c with
      | Value.Simple -> false
      | Value.Relaxed -> true
      | _ -> assert false in
    let rec go ctx = function
      | [] -> ctx
      | [ `Spaces str ] ->
          if relaxed then Hash.feed_string ctx " " else Hash.feed_string ctx str
      | `CRLF :: r -> go (Hash.feed_string ctx "\r\n") r
      | `Spaces x :: r ->
          let ctx = if not relaxed then Hash.feed_string ctx x else ctx in
          go ctx r in
    let ctx = go ctx payloads in
    (dkim, Digest { m; ctx })

  let digest_str : type signed k. _ -> (signed, k) value -> (signed, k) value =
   fun x (dkim, Digest { m; ctx }) ->
    let module Hash = (val m) in
    let ctx = Hash.feed_string ctx x in
    (dkim, Digest { m; ctx })

  let hashp : type a. a Digestif.hash -> Digestif.hash' -> bool =
   fun a b ->
    let a = Digestif.hash_to_hash' a in
    a = b

  let verify : type k.
      fields:string ->
      domain_key:domain_key ->
      (signed, k) value ->
      string * bool =
   fun ~fields ~domain_key:dk (dkim, Digest { m = (module Hash); ctx }) ->
    let signature, _ = dkim.bbh in
    let (Hash_algorithm a) = snd dkim.a in
    let hashp = hashp a in
    let body = Hash.get ctx in
    let body = Hash.to_raw_string body in
    let fields =
      match (X509.Public_key.decode_der dk.p, fst dkim.a) with
      | Ok (`RSA key), Value.RSA ->
          Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature
            (`Digest fields)
      | Ok (`ED25519 key), Value.ED25519 ->
          Mirage_crypto_ec.Ed25519.verify ~key signature ~msg:fields
      | _ -> false in
    (body, fields)
end

module Verify = struct
  type decoder = {
    input : bytes;
    input_pos : int;
    input_len : int;
    state : state;
  }

  and decode =
    [ `Await of decoder
    | `Query of decoder * signed t
    | `Signatures of result list
    | `Malformed of string ]

  and response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]

  and state =
    | Extraction of Mrmime.Hd.decoder * fields * maps
    | Queries of raw * dkim list
    | Body of Body.decoder * [ `CRLF | `Spaces of string ] list * ctx list

  and raw = {
    dkims : (Mrmime.Field_name.t * Unstrctrd.t * Map.t) list;
    fields : fields;
    prelude : string;
  }

  and ctx = Ctx : string * domain_key * (signed, 'k) Digest.value -> ctx
  and fields = (Mrmime.Field_name.t * Unstrctrd.t) list

  and dkim =
    | Dkim : Mrmime.Field_name.t * Unstrctrd.t * signed t * domain_key -> dkim

  and maps = (Mrmime.Field_name.t * Unstrctrd.t * Map.t) list

  and result =
    | Signature : {
        dkim : signed t;
        domain_key : domain_key;
        fields : bool;
        body : string;
      }
        -> result

  let decoder () =
    let input, input_pos, input_len = (Bytes.empty, 1, 0) in
    let dec = Mrmime.Hd.decoder p in
    let state = Extraction (dec, [], []) in
    { input; input_pos; input_len; state }

  let end_of_input decoder =
    { decoder with input = Bytes.empty; input_pos = 0; input_len = min_int }

  let src decoder src idx len =
    if idx < 0 || len < 0 || idx + len > String.length src
    then invalid_argf "Dkim.Verify.src: source out of bounds" ;
    let input = Bytes.unsafe_of_string src in
    let input_pos = idx in
    let input_len = idx + len - 1 in
    let decoder = { decoder with input; input_pos; input_len } in
    match decoder.state with
    | Extraction (v, _, _) ->
        Mrmime.Hd.src v src idx len ;
        if len == 0 then end_of_input decoder else decoder
    | Body (v, _, _) ->
        Body.src v input idx len ;
        if len == 0 then end_of_input decoder else decoder
    | Queries _ -> if len == 0 then end_of_input decoder else decoder

  let src_rem decoder = decoder.input_len - decoder.input_pos + 1

  let response t ~dkim ~response =
    match (t.state, response) with
    | ( Queries (({ dkims = (fn, unstrctrd, _) :: r; _ } as raw), dkims),
        `Domain_key dk ) ->
        let raw = { raw with dkims = r } in
        let dkim = Dkim (fn, unstrctrd, dkim, dk) in
        let dkims = dkim :: dkims in
        let state = Queries (raw, dkims) in
        { t with state }
    | Queries (({ dkims = _ :: r; _ } as raw), dkims), (`Expired | `DNS_error _)
      ->
        let raw = { raw with dkims = r } in
        let state = Queries (raw, dkims) in
        { t with state }
    | _ -> invalid_arg "Dkim.Verify.response"

  let domain_key dkim =
    let ( let* ) = Result.bind in
    let* x = Domain_name.prepend_label dkim.d "_domainkey" in
    Domain_name.append dkim.s x

  let signatures ctxs =
    let fn (Ctx (fields, dk, ((dkim, _) as value))) =
      let body, fields = Digest.verify ~fields ~domain_key:dk value in
      Signature { dkim; domain_key = dk; fields; body } in
    List.map fn ctxs

  let rec extract t decoder fields dkims =
    let open Mrmime in
    let rec go fields dkims =
      match Hd.decode decoder with
      | `Field field -> begin
          let (Field.Field (fn, w, v)) = Location.prj field in
          let is_dkim_signature = Field_name.equal fn field_dkim_signature in
          match (is_dkim_signature, w) with
          | true, Field.Unstructured -> begin
              let v = to_unstrctrd v in
              match of_unstrctrd v with
              | Ok dkim ->
                  let dkims = (fn, v, dkim) :: dkims in
                  go fields dkims
              | Error (`Msg err) ->
                  Log.warn (fun m -> m "Ignore DKIM-Signature: %s." err) ;
                  go fields dkims
            end
          | false, Field.Unstructured ->
              let v = to_unstrctrd v in
              let fields = (fn, v) :: fields in
              go fields dkims
          | _ -> assert false
        end
      | `Malformed _ as err -> err
      | `End prelude ->
          let rem = src_rem t in
          let fields = List.rev fields in
          let dkims = List.rev dkims in
          let ext = { prelude; fields; dkims } in
          let state = Queries (ext, []) in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          decode t
      | `Await ->
          let state = Extraction (decoder, fields, dkims) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          `Await t in
    go fields dkims

  and queries t raw dkims =
    match raw.dkims with
    | [] ->
        let prelude = Bytes.unsafe_of_string raw.prelude in
        let fn (Dkim (fn, unstrctrd, (dkim : signed t), dk)) =
          let fields, Value value =
            Digest.digest_fields raw.fields (fn, unstrctrd, dkim, dk) in
          Ctx (fields, dk, value) in
        let ctxs = List.map fn dkims in
        let decoder = Body.decoder () in
        if Bytes.length prelude > 0
        then Body.src decoder prelude 0 (Bytes.length prelude) ;
        let state = Body (decoder, [], ctxs) in
        decode { t with state }
    | (_, _, map) :: _ ->
    try
      let dkim = post_process_dkim map in
      Log.debug (fun m -> m "DKIM-Signature: %a" pp dkim) ;
      `Query (t, dkim)
    with _ -> `Malformed "Invalid DKIM-Signature"

  and digest t decoder stack ctxs =
    let rec go stack results =
      match Body.decode decoder with
      | (`Spaces _ | `CRLF) as x -> go (x :: stack) results
      | `Data x ->
          let fn (Ctx (fields, dk, value)) =
            Ctx (fields, dk, Digest.digest_wsp (List.rev stack) value) in
          let results = List.map fn results in
          let fn (Ctx (fields, dk, value)) =
            Ctx (fields, dk, Digest.digest_str x value) in
          let results = List.map fn results in
          go [] results
      | `Await ->
          let state = Body (decoder, stack, results) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          `Await { t with state; input_pos }
      | `End ->
          let fn (Ctx (fields, dk, value)) =
            Ctx (fields, dk, Digest.digest_wsp [ `CRLF ] value) in
          let results = List.map fn results in
          let signatures = signatures results in
          `Signatures signatures in
    go stack ctxs

  and decode t =
    match t.state with
    | Extraction (decoder, fields, dkims) -> extract t decoder fields dkims
    | Queries (raw, dkims) -> queries t raw dkims
    | Body (decoder, stack, dkims) -> digest t decoder stack dkims
end

module Encoder = struct
  type 'bbh dkim = 'bbh t

  open Prettym

  let tag pvalue ppf (key, value) =
    eval ppf
      [ box; !!string; cut; char $ '='; !!pvalue; cut; char $ ';'; close ]
      key value

  let version ppf v =
    let int ppf v = eval ppf [ !!string ] (string_of_int v) in
    tag int ppf ("v", v)

  let fields ppf lst =
    let sep = ((fun ppf () -> eval ppf [ cut; char $ ':'; cut ]), ()) in
    let field_name ppf (v : Mrmime.Field_name.t) =
      eval ppf [ !!string ] (String.lowercase_ascii (v :> string)) in
    eval ppf [ !!(tag (list ~sep field_name)) ] ("h", lst)

  let query ppf v =
    (* TODO(dinosaure): optional quoted-printable? *)
    let query ppf = function
      | `DNS `TXT, _ -> eval ppf [ string $ "dns/txt" ]
      | `Query_ext v, _ -> eval ppf [ !!string ] v in
    let sep = ((fun ppf () -> eval ppf [ cut; char $ ':'; cut ]), ()) in
    match v with
    | List.[] -> ppf
    | queries -> eval ppf [ !!(tag (list ~sep query)); fws ] ("q", queries)

  let length ppf v =
    let int ppf v = eval ppf [ !!string ] (string_of_int v) in
    tag int ppf ("l", v)

  let timestamp ppf v =
    let int64 ppf v = eval ppf [ !!string ] (Int64.to_string v) in
    tag int64 ppf ("t", v)

  let expiration ppf v =
    let int64 ppf v = eval ppf [ !!string ] (Int64.to_string v) in
    tag int64 ppf ("x", v)

  let domain ppf v =
    let domain ppf v = eval ppf [ !!string ] (Domain_name.to_string v) in
    tag domain ppf ("d", v)

  let selector ppf v =
    let domain ppf v = eval ppf [ !!string ] (Domain_name.to_string v) in
    tag domain ppf ("s", v)

  let canonicalization ppf v =
    let c ppf = function
      | Value.Relaxed, Value.Relaxed -> string ppf "relaxed/relaxed"
      | Value.Simple, Value.Simple -> string ppf "simple/simple"
      | Value.Relaxed, Value.Simple -> string ppf "relaxed/simple"
      | Value.Simple, Value.Relaxed -> string ppf "simple/relaxed"
      | Value.Simple, Value.Canonicalization_ext v ->
          eval ppf [ string $ "simple"; char $ '/'; !!string ] v
      | Value.Relaxed, Value.Canonicalization_ext v ->
          eval ppf [ string $ "relaxed"; char $ '/'; !!string ] v
      | Value.Canonicalization_ext v, Value.Simple ->
          eval ppf [ !!string; char $ '/'; string $ "simple" ] v
      | Value.Canonicalization_ext v, Value.Relaxed ->
          eval ppf [ !!string; char $ '/'; string $ "relaxed" ] v
      | Value.Canonicalization_ext a, Value.Canonicalization_ext b ->
          eval ppf [ !!string; char $ '/'; !!string ] a b in
    tag c ppf ("c", v)

  let algorithm ppf v =
    let algorithm ppf = function
      | Value.RSA, hash ->
          let hash = Fmt.str "%a" Hash.pp hash in
          eval ppf [ string $ "rsa"; cut; char $ '-'; cut; !!string ] hash
      | Value.ED25519, hash ->
          let hash = Fmt.str "%a" Hash.pp hash in
          eval ppf [ string $ "ed25519"; cut; char $ '-'; cut; !!string ] hash
      | Value.Algorithm_ext v, hash ->
          let hash = Fmt.str "%a" Hash.pp hash in
          eval ppf [ !!string; cut; char $ '-'; cut; !!string ] v hash in
    tag algorithm ppf ("a", v)

  let body_hash ppf v =
    let hash ppf (Hash_value (k, hash)) =
      let str = Base64.encode_exn ~pad:true (Digestif.to_raw_string k hash) in
      let rec go ppf idx =
        if idx = String.length str
        then ppf
        else
          let ppf = eval ppf [ cut; !!char; cut ] str.[idx] in
          go ppf (succ idx) in
      go ppf 0 in
    tag hash ppf ("bh", v)

  let signature ppf v =
    let signature ppf = function
      | "" -> ppf
      | signature ->
          let str = Base64.encode_exn ~pad:true signature in
          let rec go ppf idx =
            if idx = String.length str
            then ppf
            else
              let ppf = eval ppf [ cut; !!char; cut ] str.[idx] in
              go ppf (succ idx) in
          go ppf 0 in
    tag signature ppf ("b", v)

  let option_with_fws fmt ppf = function
    | None -> ppf
    | Some v -> eval ppf [ !!fmt; fws ] v

  let dkim_signature ppf (dkim : signed dkim) =
    let b, bh = dkim.bbh in
    eval ppf
      [
        !!version;
        fws;
        !!algorithm;
        fws;
        !!canonicalization;
        fws;
        !!domain;
        fws;
        !!selector;
        fws;
        !!(option_with_fws timestamp);
        !!(option_with_fws expiration);
        !!query;
        !!(option_with_fws length);
        !!body_hash;
        fws;
        !!fields;
        fws;
        !!signature;
        fws;
      ]
      dkim.v dkim.a dkim.c dkim.d dkim.s dkim.t dkim.x dkim.q dkim.l bh dkim.h b

  let algorithm ppf (alg, hash) =
    match alg with
    | `RSA -> algorithm ppf (Value.RSA, hash)
    | `ED25519 -> algorithm ppf (Value.ED25519, hash)

  let as_field ppf dkim =
    eval ppf
      [
        string $ "DKIM-Signature";
        char $ ':';
        tbox 1;
        spaces 1;
        !!dkim_signature;
        close;
        new_line;
      ]
      dkim
end

let dkim_field_and_value =
  let open Angstrom in
  let open Mrmime in
  let buf = Bytes.create 0x7f in
  let is_wsp = function ' ' | '\t' -> true | _ -> false in
  Field_name.Decoder.field_name >>= fun _ ->
  skip_while is_wsp *> char ':' *> Unstrctrd_parser.unstrctrd buf

module Sign = struct
  type signer = {
    input : bytes;
    input_pos : int;
    input_len : int;
    state : state;
    key : key;
    dkim : unsigned t;
  }

  and state =
    | Fields of Mrmime.Hd.decoder * fields
    | Sign : {
        decoder : Body.decoder;
        fields : 'k digest;
        stack : [ `CRLF | `Spaces of string ] list;
        body : 'k digest;
      }
        -> state

  and 'k digest = (unsigned, 'k) Digest.value
  and fields = (Mrmime.Field_name.t * Unstrctrd.t) list

  and action =
    [ `Await of signer | `Malformed of string | `Signature of signed t ]

  let src_rem decoder = decoder.input_len - decoder.input_pos + 1

  let end_of_input decoder =
    { decoder with input = Bytes.empty; input_pos = 0; input_len = min_int }

  let fill decoder src idx len =
    if idx < 0 || len < 0 || idx + len > String.length src
    then invalid_argf "Dkim.Sign.fill: source out of bounds" ;
    let input = Bytes.unsafe_of_string src in
    let input_pos = idx in
    let input_len = idx + len - 1 in
    let decoder = { decoder with input; input_pos; input_len } in
    match decoder.state with
    | Fields (v, _) ->
        Mrmime.Hd.src v src idx len ;
        if len == 0 then end_of_input decoder else decoder
    | Sign { decoder = v; _ } ->
        Body.src v input idx len ;
        if len == 0 then end_of_input decoder else decoder

  let rec fields t decoder fields =
    let open Mrmime in
    let rec go fields =
      match Hd.decode decoder with
      | `Field field -> begin
          let (Field.Field (field_name, w, v)) = Location.prj field in
          match w with
          | Field.Unstructured ->
              let v = to_unstrctrd v in
              go ((field_name, v) :: fields)
          | _ -> assert false
        end
      | `Malformed err -> `Malformed err
      | `End prelude ->
          let (Hash_algorithm k) = snd t.dkim.a in
          let module Hash = (val Digestif.module_of k) in
          let feed_string ctx str = Hash.feed_string ctx str in
          let canon = Canon.of_fields t.dkim in
          let fn (ctx, fields) requested =
            match assoc requested fields with
            | Some (field_name, unstrctrd) ->
                let ctx = canon field_name unstrctrd feed_string ctx in
                (ctx, remove_assoc field_name fields)
            | None -> (ctx, fields) in
          let ctx, _ =
            List.fold_left fn (Hash.empty, List.rev fields) t.dkim.h in
          let fields = Digest.Digest { m = (module Hash); ctx } in
          let fields = (t.dkim, fields) in
          let body = Digest.Digest { m = (module Hash); ctx = Hash.empty } in
          let body = (t.dkim, body) in
          let decoder = Body.decoder () in
          let prelude = Bytes.unsafe_of_string prelude in
          if Bytes.length prelude > 0
          then Body.src decoder prelude 0 (Bytes.length prelude) ;
          let state = Sign { decoder; fields; stack = []; body } in
          sign { t with state }
      | `Await ->
          let state = Fields (decoder, fields) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          `Await t in
    go fields

  and digest : type k.
      signer ->
      Body.decoder ->
      k digest ->
      [ `CRLF | `Spaces of string ] list ->
      k digest ->
      action =
   fun t decoder fields stack body ->
    let rec go stack body =
      match Body.decode decoder with
      | (`Spaces _ | `CRLF) as x -> go (x :: stack) body
      | `Data x ->
          let body = Digest.digest_wsp (List.rev stack) body in
          let body = Digest.digest_str x body in
          go [] body
      | `Await ->
          (* let body = digest_wsp ~dkim:t.dkim stack body in *)
          let state = Sign { decoder; fields; stack; body } in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          `Await { t with state; input_pos }
      | `End ->
          let body = Digest.digest_wsp [ `CRLF ] body in
          let _, Digest { m = (module Hash); ctx } = body in
          let (Hash_algorithm k) = snd t.dkim.a in
          let bh =
            Hash_value
              (k, Digestif.of_raw_string k Hash.(to_raw_string (get ctx))) in
          let fake = { t.dkim with bbh = ("", bh) } in
          let fake = Prettym.to_string ~new_line:"\r\n" Encoder.as_field fake in
          let unstrctrd =
            Angstrom.parse_string ~consume:All dkim_field_and_value fake in
          let unstrctrd = Result.get_ok unstrctrd in
          let canon = Canon.of_dkim_fields in
          let _, Digest { m = (module Hash); ctx } = fields in
          let feed_string str ctx = Hash.feed_string str ctx in
          let ctx =
            canon t.dkim field_dkim_signature unstrctrd feed_string ctx in
          let b =
            match t.key with
            | `RSA key ->
                let hash = Digestif.hash_to_hash' k in
                let msg = `Digest Hash.(to_raw_string (get ctx)) in
                Mirage_crypto_pk.Rsa.PKCS1.sign ~hash ~key msg
            | `ED25519 key ->
                let msg = Hash.(to_raw_string (get ctx)) in
                Mirage_crypto_ec.Ed25519.sign ~key msg in
          `Signature { t.dkim with bbh = (b, bh) } in
    go stack body

  and sign t =
    match t.state with
    | Fields (decoder, fs) -> fields t decoder fs
    | Sign { decoder; fields; stack; body } ->
        digest t decoder fields stack body

  let signer ~key dkim =
    let () =
      match (key, fst dkim.a) with
      | `RSA _, Value.RSA | `ED25519 _, Value.ED25519 -> ()
      | _ -> failwith "Signer.signer: invalid algorithm" in
    let input, input_pos, input_len = (Bytes.empty, 1, 0) in
    let dec = Mrmime.Hd.decoder p in
    let state = Fields (dec, []) in
    { input; input_pos; input_len; key; dkim; state }
end

let v ?(version = 1) ?(fields = [ Mrmime.Field_name.from ]) ~selector
    ?(algorithm = `RSA) ?(hash = `SHA256)
    ?(canonicalization = (`Relaxed, `Relaxed)) ?length ?(query = `DNS `TXT)
    ?timestamp ?expiration domain =
  if version <> 1 then Fmt.invalid_arg "Invalid version number: %d" version ;
  if List.length fields = 0
  then Fmt.invalid_arg "Require at last one field to sign an email" ;
  let a =
    match (algorithm, hash) with
    | `RSA, `SHA1 -> (Value.RSA, Hash_algorithm Digestif.SHA1)
    | `RSA, `SHA256 -> (Value.RSA, Hash_algorithm Digestif.SHA256)
    | `ED25519, `SHA1 -> (Value.ED25519, Hash_algorithm Digestif.SHA1)
    | `ED25519, `SHA256 -> (Value.ED25519, Hash_algorithm Digestif.SHA256) in
  let c =
    match canonicalization with
    | `Relaxed, `Relaxed -> (Value.Relaxed, Value.Relaxed)
    | `Relaxed, `Simple -> (Value.Relaxed, Value.Simple)
    | `Simple, `Relaxed -> (Value.Simple, Value.Relaxed)
    | `Simple, `Simple -> (Value.Simple, Value.Simple) in
  let q = [ ((query, None) :> Value.query) ] in
  let d = domain in
  let t = timestamp in
  let x = expiration in
  let h =
    if List.exists Mrmime.Field_name.(equal from) fields
    then fields
    else Mrmime.Field_name.from :: fields in
  let l = length in
  let s = selector in
  { v = version; a; c; d; t; x; h; l; s; i = None; z = []; q; bbh = () }

(* XXX(dinosaure): lazy to implement these functions but
 * the structural comparison is enough for us. *)
let sort_whash = List.sort Stdlib.compare
let sort_service = List.sort Stdlib.compare
let sort_name = List.sort Stdlib.compare

let equal_domain_key (a : domain_key) (b : domain_key) =
  try
    a.v = b.v
    && List.for_all2 ( = ) (sort_whash a.h) (sort_whash b.h)
    && a.k = b.k
    && a.p = b.p
    && List.for_all2 ( = ) (sort_service a.s) (sort_service b.s)
    && List.for_all2 ( = ) (sort_name a.t) (sort_name b.t)
  with _ -> false

let get_key name hmap =
  let exception Found of string in
  let fn (Map.B (key, value)) =
    match Map.Key.info key with
    | { Map.name = name'; ty = Map.Unknown; _ } ->
        if name = name' then raise_notrace (Found value)
    | _ -> () in
  match Map.iter fn hmap with exception Found value -> Some value | () -> None

let of_unstrctrd_to_map unstrctrd = of_unstrctrd unstrctrd

let map_to_t map =
  try Ok (post_process_dkim map)
  with exn ->
    Log.err (fun m ->
        m "Unexpected exception while normalizing DKIM-Signature: %s"
          (Printexc.to_string exn)) ;
    error_msgf "Invalid DKIM-Signature"

let of_unstrctrd unstrctrd =
  match of_unstrctrd unstrctrd with
  | Error _ as err -> err
  | Ok m ->
  try Ok (post_process_dkim m)
  with _exn -> error_msgf "Invalid DKIM-Signature"

let of_string str =
  let ( let* ) = Result.bind in
  let* _, unstrctrd = Unstrctrd.of_string (str ^ "\r\n") in
  of_unstrctrd unstrctrd
