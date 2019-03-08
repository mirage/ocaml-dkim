type raw = Mrmime.Unstructured.t

type noop = [ `WSP of string | `CR of int | `LF of int | `CRLF ]
type data = [ `Text of string | `Encoded of Mrmime.Encoded_word.t ]

let unfold =
  let empty_rest = List.for_all (function `WSP _ | `CR _ | `LF _ | `CRLF -> true | `Text _ | `Encoded _ -> false) in
  let has_semicolon = function
    | `Text x -> x.[String.length x - 1] = ';'
    | `Encoded { Mrmime.Encoded_word.data= Ok data; _ } -> data.[String.length data - 1] = ';'
    | `Encoded { Mrmime.Encoded_word.data= Error err; _ } -> Fmt.invalid_arg "Cannot extract DKIM-Signature: %a" Rresult.R.pp_msg err in
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

let (<.>) f g = fun x -> f (g x)

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

module Option = struct
  type 'a t = 'a option

  let some x = Some x
end

type 'a tag = { name : string; pp: 'a Fmt.t; }
module Info = struct type 'a t = 'a tag = { name : string; pp : 'a Fmt.t } end
module Hmap = Hmap.Make(Info)

module Value = struct
  type algorithm = RSA | Algorithm_ext of string
  type hash = SHA1 | SHA256 | Hash_ext of string
  type canonicalization = Simple | Relaxed | Canonicalization_ext of string
  type base64 = string
  type version = int
  type domain_name = string list
  type field_name = string
  type auid = { local : [ `String of string | `Dot_string of string list ] option; domain : domain_name }
  type quoted_printable = string
  type query = [ `DNS_TXT | `Query_ext of string ] * quoted_printable option
  type selector = string list
  type flag = Y | S | Flag_ext of string
  type copies = (field_name * quoted_printable) list

  let pp_algorithm ppf = function
    | RSA -> Fmt.string ppf "rsa"
    | Algorithm_ext x -> Fmt.string ppf x

  let pp_hash ppf = function
    | SHA1 -> Fmt.string ppf "sha1"
    | SHA256 -> Fmt.string ppf "sha256"
    | Hash_ext x -> Fmt.string ppf x

  let pp_canonicalization ppf = function
    | Simple -> Fmt.string ppf "simple"
    | Relaxed -> Fmt.string ppf "relaxed"
    | Canonicalization_ext x -> Fmt.string ppf x

  let pp_domain_name = Fmt.(list ~sep:(const string ".") string)
  let pp_selector = Fmt.(list ~sep:(const string ".") string)
  let pp_field = Fmt.using Mrmime.Field.of_string_exn Mrmime.Field.pp

  let pp_auid ppf t =
    let pp_local ppf = function
      | `String x -> Fmt.(quote string) ppf x
      | `Dot_string l -> Fmt.(list ~sep:(const string ".") string) ppf l in
    Fmt.pf ppf "{ @[<hov>local = %a;@ domain= %a;@] }"
      Fmt.(option pp_local) t.local
      Fmt.(list ~sep:(const string ".") string) t.domain

  let pp_query ppf (query, arg) = match query with
    | `DNS_TXT -> Fmt.pf ppf "dns/txt%a" Fmt.(option (prefix (const string ":") string)) arg
    | `Query_ext x -> Fmt.pf ppf "%s%a" x Fmt.(option (prefix (const string ":") string)) arg

  let pp_copy = Fmt.Dump.pair pp_field Fmt.string
end

module Key = struct
  open Value

  let v : version Hmap.key = Hmap.Key.create { name= "version"; pp= Fmt.int }
  let a : (algorithm * hash) Hmap.key = Hmap.Key.create { name= "algorithm"; pp= Fmt.Dump.pair Value.pp_algorithm Value.pp_hash }
  let b : base64 Hmap.key = Hmap.Key.create { name= "signature"; pp= Fmt.string }
  let bh : base64 Hmap.key = Hmap.Key.create { name= "hash"; pp= Fmt.string }
  let c : (canonicalization * canonicalization) Hmap.key = Hmap.Key.create { name= "canonicalization"; pp= Fmt.Dump.pair Value.pp_canonicalization Value.pp_canonicalization }
  let d : domain_name Hmap.key = Hmap.Key.create { name= "domain"; pp= Value.pp_domain_name }
  let h : field_name list Hmap.key = Hmap.Key.create { name= "field"; pp= Fmt.Dump.list Value.pp_field }
  let i : auid Hmap.key = Hmap.Key.create { name= "auid"; pp= Value.pp_auid }
  let l : int Hmap.key = Hmap.Key.create { name="length"; pp= Fmt.int }
  let q : query Hmap.key = Hmap.Key.create { name= "query"; pp= Value.pp_query }
  let s : selector Hmap.key = Hmap.Key.create { name= "selector"; pp= Value.pp_selector }
  let t : int64 Hmap.key = Hmap.Key.create { name= "timestamp"; pp= Fmt.int64 }
  let x : int64 Hmap.key = Hmap.Key.create { name= "expiration"; pp= Fmt.int64 }
  let z : copies Hmap.key = Hmap.Key.create { name= "copies"; pp= Fmt.Dump.list Value.pp_copy }
end

module Parser = struct
  open Angstrom

  let failf fmt = Fmt.kstrf fail fmt

  let is_digit = function '0' .. '9' -> true | _ -> false
  let is_alpha = function 'a' .. 'z' | 'A' .. 'Z' -> true | _ -> false
  let is_plus = (=) '+'
  let is_slash = (=) '/'
  let is_dash = (=) '-'
  let is_equal = (=) '='
  let ( or ) f g = fun x -> f x || g x
  let is_base64 = is_digit or is_alpha or is_plus or is_slash or is_equal
  (* XXX(dinosaure): [is_equal] is necessary to take padding but a
     post-processing with [Base64] will check if we have a valid Base64 input. *)

  (* XXX(dinosaure): [sub-domain] from [colombe]. *)

  let let_dig = satisfy (is_alpha or is_digit)

  let ldh_str =
    take_while1 (is_alpha or is_digit or is_dash)
    >>= fun res ->
    if String.get res (String.length res - 1) <> '-'
    then return res
    else fail "Invalid ldh-str token"

  let sub_domain =
    let_dig
    >>= fun pre -> option "" ldh_str
    >>| fun lst -> String.concat "" [ String.make 1 pre; lst ]

  let domain_name =
    sub_domain
    >>= fun x -> many (char '.' *> sub_domain)
    >>| fun r -> x :: r

  (* XXX(dinosaure): [field-name] from [mrmime]. *)

  let is_ftext = function
    | '\033' .. '\057' | '\060' .. '\126' -> true
    (* XXX(dinosaure): [is_ftext] should accept ';' but it not the case about
       DKIM-Signature (which use this character as seperator). *)
    | _ -> false

  let field_name = take_while1 is_ftext
  let hdr_name = field_name

  (* XXX(dinosaure): [local-part] from [colombe]. *)

  let is_atext = function
    | 'a' .. 'z'
    |'A' .. 'Z'
    |'0' .. '9'
    |'!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/' | '=' | '?'
    |'^' | '_' | '`' | '{' | '}' | '|' | '~' ->
      true
    | _ -> false

  let is_qtextSMTP = function
    | '\032' | '\033' | '\035' .. '\091' | '\093' .. '\126' -> true
    | _ -> false

  let atom = take_while1 is_atext

  let dot_string = atom >>= fun x -> many (char '.' *> atom) >>| fun r -> `Dot_string (x :: r)

  let quoted_pairSMTP =
    char '\\' *> satisfy (function '\032' .. '\126' -> true | _ -> false) >>| String.make 1

  let qcontentSMTP = quoted_pairSMTP <|> take_while1 is_qtextSMTP

  let quoted_string =
    char '"' *> many qcontentSMTP <* char '"' >>| String.concat "" >>| fun x -> `String x

  let local_part = dot_string <|> quoted_string

  let hyphenated_word = peek_char >>= function
    | None -> failf "Unexpected end of input"
    | Some chr -> match chr with
      | ('a' .. 'z' | 'A' .. 'Z') as chr ->
        take_while (is_alpha or is_digit or is_dash) >>= fun rest ->
        if String.length rest > 0
        then (if rest.[String.length rest - 1] <> '-'
              then return (String.make 1 chr ^ rest)
              else failf "Unexpected character %02x" (Char.code rest.[String.length rest - 1]))
        else return (String.make 1 chr)
      | chr -> failf "Unexpected character %02x" (Char.code chr)

  let rsa = string "rsa" *> return Value.RSA
  let sha1 = string "sha1" *> return Value.SHA1
  let sha256 = string "sha256" *> return Value.SHA256
  let simple = string "simple" *> return Value.Simple
  let relaxed = string "relaxed" *> return Value.Relaxed

  let algorithm_extension : Value.algorithm t =
    take_while1 (is_digit or is_alpha)
    >>= fun k -> if not (is_digit k.[0]) then return (Value.Algorithm_ext k) else failf "Invalid algorithm key: %s" k

  let hash_extension : Value.hash t =
    take_while1 (is_digit or is_alpha)
    >>= fun h -> if not (is_digit h.[0]) then return (Value.Hash_ext h) else failf "Invalid hash: %s" h

  let tag_spec
    : type v. tag_name:v Hmap.key t -> tag_value:v t -> (v Hmap.key * v option) t
    = fun ~tag_name ~tag_value ->
    tag_name <* char '=' >>= fun name -> option None (tag_value >>| Option.some) >>= fun value -> return (name, value)

  let is_alnumpunc = function
    | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' -> true
    | _ -> false

  let is_valchar = function
    | '\x21' .. '\x3a' | '\x3c' .. '\x7e' -> true
    | _ -> false

  let dkim_quoted_printable =
    let is_hex = function '0' .. '9' | 'A' .. 'F' -> true | _ -> false in
    take_while (function '\x21' .. '\x3a' | '\x3c' | '\x3e' .. '\x7e' -> true | chr -> is_hex chr)

  let qp_hdr_value = dkim_quoted_printable

  let selector =
    sub_domain
    >>= fun x -> many (char '.' *> sub_domain)
    >>| fun r -> x :: r

  let tag_name = peek_char >>= function
    | None -> failf "Unexpected end of input"
    | Some chr -> match chr with
      | ('a' .. 'z' | 'A' .. 'Z') as chr ->
        take_while is_alnumpunc >>= fun rest ->
        return (String.make 1 chr ^ rest)
      | chr -> failf "Unexpected character: %02x" (Char.code chr)

  let tag_value = take_while1 is_valchar

  let binding = function
    | (k, Some v) -> Some (Hmap.B (k, v))
    | _ -> None

  let v =
    let tag_name = string "v" >>| fun _ -> Key.v in
    let tag_value = take_while1 is_digit >>| int_of_string in
    tag_spec ~tag_name ~tag_value >>| binding

  let a =
    let tag_name = string "a" >>| fun _ -> Key.a in
    let tag_value =
      (rsa <|> algorithm_extension) <* char '-'
      >>= fun k -> (sha1 <|> sha256 <|> hash_extension)
      >>| fun h -> (k, h) in
    tag_spec ~tag_name ~tag_value >>| binding

  let b =
    (* XXX(dinosaure): base64string = ALPHADIGITPS *([FWS] ALPHADIGITPS) [ [FWS]
       "=" [ [FWS] "=" ] ]. Definition of the hell, a pre-processing is needed in
       this case to concat fragments separated by [FWS]. *)
    let tag_name = string "b" >>| fun _ -> Key.b in
    let tag_value = take_while1 is_base64 in
    tag_spec ~tag_name ~tag_value >>| binding

  let bh =
    let tag_name = string "bh" >>| fun _ -> Key.bh in
    let tag_value = take_while1 is_base64 in
    tag_spec ~tag_name ~tag_value >>| binding

  let c =
    let tag_name = string "c" >>| fun _ -> Key.c in
    let tag_value =
      let sig_c_tag_alg = (simple <|> relaxed <|> (hyphenated_word >>| fun x -> Value.Canonicalization_ext x)) in
      sig_c_tag_alg >>= fun h -> option Value.Simple (char '/' *> sig_c_tag_alg) >>= fun b -> return (h, b) in
    tag_spec ~tag_name ~tag_value >>| binding

  let d =
    let tag_name = string "d" >>| fun _ -> Key.d in
    let tag_value = domain_name in
    tag_spec ~tag_name ~tag_value >>| binding

  let h =
    let tag_name = string "h" >>| fun _ -> Key.h in
    let tag_value = hdr_name >>= fun x -> many (char ':' *> hdr_name) >>= fun r -> return (x :: r) in
    tag_spec ~tag_name ~tag_value >>| binding

  let i =
    let tag_name = string "i" >>| fun _ -> Key.i in
    let tag_value = option None (local_part >>| Option.some) >>= fun local -> char '*' *> domain_name >>= fun domain ->
      return { Value.local; domain } in
    tag_spec ~tag_name ~tag_value >>| binding

  let l =
    let tag_name = string "l" >>| fun _ -> Key.l in
    let tag_value = take_while1 is_digit >>| int_of_string in
    tag_spec ~tag_name ~tag_value >>| binding

  let q =
    let tag_name = string "q" >>| fun _ -> Key.q in
    let tag_value =
      (string "dns/txt" >>| fun _ -> `DNS_TXT)
      <|> (hyphenated_word >>| fun x -> `Query_ext x)
      >>= fun meth -> option None (char '/' *> qp_hdr_value >>| Option.some)
      >>= fun args -> return (meth, args) in
    tag_spec ~tag_name ~tag_value >>| binding

  let s =
    let tag_name = string "s" >>| fun _ -> Key.s in
    let tag_value = selector in
    tag_spec ~tag_name ~tag_value >>| binding

  let t =
    let tag_name = string "t" >>| fun _ -> Key.t in
    let tag_value = take_while1 is_digit >>| Int64.of_string in
    tag_spec ~tag_name ~tag_value >>| binding

  let x =
    let tag_name = string "x" >>| fun _ -> Key.x in
    let tag_value = take_while1 is_digit >>| Int64.of_string in
    tag_spec ~tag_name ~tag_value >>| binding

  let z =
    let tag_name = string "z" >>| fun _ -> Key.z in
    let tag_value =
      let sig_z_tag_copy = hdr_name >>= fun field -> char ':' *> qp_hdr_value >>= fun v -> return (field, v) in
      sig_z_tag_copy >>= fun x -> many (char '|' *> sig_z_tag_copy) >>= fun r -> return (x :: r) in
    tag_spec ~tag_name ~tag_value >>| binding

  let tag_list =
    let tag_spec = bh <|> v <|> a <|> b <|> c <|> d <|> h <|> i <|> l <|> q <|> s <|> t <|> x <|> z in
    tag_spec >>= function
    | Some (Hmap.B (k, v)) ->
      many (char ';' *> tag_spec) >>|
      List.fold_left (fun hmap -> function
          | Some (Hmap.B (k, v)) -> Hmap.add k v hmap
          | None -> hmap)
        (Hmap.singleton k v)
    | None -> failf "Expect at least one tag"
end

(*
type base64 = private string
type hash_value = private string
type canonicalization = Simple | Relaxed | CExtension of string
type query_method =
  | DNS | TXT | QExtension of string

type auid =
  { local : Mrmime.Mailbox.local option
  ; domain : Domain_name.t }

type dkim_field =
  { version : int
  ; algorithm : algorithm * hash
  ; signature : base64
  ; hash_body_part : hash_value
  ; canonicalization : canonicalization * canonicalization
  ; sdid : Domain_name.t
  ; signed_header_fields : Mrmime.Field.t list
  ; auid : auid option
  ; length : int option
  ; query_methods : (query_method * query_method) list
  ; selector : Domain_name.t
  ; timestamp : int64 option
  ; expiration : int64 option
  ; copied_header_fields : (Mrmime.Field.t * Mrmime.Header.Value.t) list }
*)

let parse_dkim x =
  match Angstrom.parse_string Parser.tag_list x with
  | Ok v -> Ok v
  | Error _ -> Rresult.R.error_msgf "Invalid DKIM Signature: %S" x

let pp_dkim ?sep =
  let pp_binding ppf (Hmap.B (k, value)) =
    let { Info.name; pp } = Hmap.Key.info k in
    Fmt.pf ppf "%s => @[<hov>%a@]" name pp value in
  Fmt.iter ?sep Hmap.iter pp_binding

module type FLOW = sig
  type flow

  val input : flow -> bytes -> int -> int -> int
end

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

let extract_dkim ?(newline = LF) (type flow) (flow : flow) (module Flow : FLOW with type flow = flow) =
  let open Mrmime in
  let chunk = 0x1000 in
  let raw = Bytes.create chunk in
  let buffer = Bigstringaf.create (2 * chunk) in
  let decoder = St_header.decoder ~field:(Field.of_string_exn "DKIM-Signature") St_header.Value.Unstructured buffer in
  let rec go () = match St_header.decode decoder with
    | `Field dkim_value ->
      (match unfold dkim_value with
       | Ok lst ->
         let dkim_value = String.concat "" lst |> parse_dkim in
         Fmt.epr "> %a.\n%!" Fmt.(result ~ok:(pp_dkim ~sep:(fun ppf () -> fmt ",@ " ppf)) ~error:Rresult.R.pp_msg) dkim_value
       | Error (`Msg err) ->
         Fmt.epr "Invalid DKIM value: %s.\n%!" err) ;
      go ()
    | `Other _ -> go ()
    | `Malformed err -> Rresult.R.error_msg err
    | `End -> Rresult.R.ok ()
    | `Await ->
      let len = Flow.input flow raw 0 (Bytes.length raw) in
      let raw = sanitize_input newline raw len in
      match St_header.src decoder raw 0 (String.length raw) with
      | Ok () -> go ()
      | Error _ as err -> err in
  go ()
