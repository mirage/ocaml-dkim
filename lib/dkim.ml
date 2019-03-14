[@@@warning "-32-34-37"]

type raw = Mrmime.Unstructured.t

type noop = [ `WSP of string | `CR of int | `LF of int | `CRLF ]
type data = [ `Text of string | `Encoded of Mrmime.Encoded_word.t ]

let unfold =
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

  let map f = function
    | Some x -> Some (f x)
    | None -> None

  let value ~default = function
    | Some x -> x
    | None -> default
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
  let a : (algorithm * hash) Hmap.key = Hmap.Key.create
      { name= "algorithm"; pp= Fmt.Dump.pair Value.pp_algorithm Value.pp_hash }
  let b : base64 Hmap.key = Hmap.Key.create { name= "signature"; pp= Fmt.string }
  let bh : base64 Hmap.key = Hmap.Key.create { name= "hash"; pp= Fmt.string }
  let c : (canonicalization * canonicalization) Hmap.key = Hmap.Key.create
      { name= "canonicalization"; pp= Fmt.Dump.pair Value.pp_canonicalization Value.pp_canonicalization }
  let d : domain_name Hmap.key = Hmap.Key.create { name= "domain"; pp= Value.pp_domain_name }
  let h : field_name list Hmap.key = Hmap.Key.create { name= "field"; pp= Fmt.Dump.list Value.pp_field }
  let i : auid Hmap.key = Hmap.Key.create { name= "auid"; pp= Value.pp_auid }
  let l : int Hmap.key = Hmap.Key.create { name="length"; pp= Fmt.int }
  let q : query list Hmap.key = Hmap.Key.create { name= "query"; pp= Fmt.Dump.list Value.pp_query }
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

  (* XXX(dinosaure): [field-name] from [mrmime]. See RFC 6376:

     The following tokens are imported from [RFC5322]:
     o  "field-name" (name of a header field)
     o  "dot-atom-text" (in the local-part of an email address)
  *)

  let is_ftext = function
    | '\033' .. '\057' | '\060' .. '\126' -> true
    (* XXX(dinosaure): [is_ftext] should accept ';' but it not the case about
       DKIM-Signature (which use this character as seperator). *)
    | _ -> false

  let field_name = take_while1 is_ftext

  (* XXX(dinosaure): [local-part] and [sub-domain] from [colombe]. See RFC 6376:

     The following tokens are imported from [RFC5321]:
     o  "local-part" (implementation warning: this permits quoted strings)
     o  "sub-domain"
  *)

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

  (* See RFC 6376:

     hyphenated-word =  ALPHA [ *(ALPHA / DIGIT / "-") (ALPHA / DIGIT) ]
  *)
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

  (* See RFC 6376:

     hdr-name        =  field-name
  *)
  let hdr_name = field_name

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

  (* See RFC 6376

     dkim-quoted-printable =  *(FWS / hex-octet / dkim-safe-char)
                               ; hex-octet is from RFC2045
     dkim-safe-char        =  %x21-3A / %x3C / %x3E-7E
                               ; '!' - ':', '<', '>' - '~'
  *)
  let dkim_quoted_printable =
    let is_hex = function '0' .. '9' | 'A' .. 'F' -> true | _ -> false in
    take_while (function '\x21' .. '\x3a' | '\x3c' | '\x3e' .. '\x7e' -> true | chr -> is_hex chr)

  let qp_hdr_value = dkim_quoted_printable

  let selector =
    sub_domain
    >>= fun x -> many (char '.' *> sub_domain)
    >>| fun r -> x :: r

  (* See RFC 6376

     tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]
     tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
     tag-name  =  ALPHA *ALNUMPUNC
     tag-value =  [ tval *( 1*(WSP / FWS) tval ) ]
                     ; Prohibits WSP and FWS at beginning and end
     tval      =  1*VALCHAR
     VALCHAR   =  %x21-3A / %x3C-7E
                     ; EXCLAMATION to TILDE except SEMICOLON
     ALNUMPUNC =  ALPHA / DIGIT / "_"
  *)
  let is_valchar = function
    | '\x21' .. '\x3a' | '\x3c' .. '\x7e' -> true
    | _ -> false

  let is_alnumpunc = function
    | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' -> true
    | _ -> false

  let tag_name = peek_char >>= function
    | None -> failf "Unexpected end of input"
    | Some chr -> match chr with
      | ('a' .. 'z' | 'A' .. 'Z') as chr ->
        take_while is_alnumpunc >>= fun rest ->
        return (String.make 1 chr ^ rest)
      | chr -> failf "Unexpected character: %02x" (Char.code chr)

  let tag_value = take_while1 is_valchar

  let tag_spec
    : type v. tag_name:v Hmap.key t -> tag_value:v t -> (v Hmap.key * v option) t
    = fun ~tag_name ~tag_value ->
      tag_name <* char '=' >>= fun name -> option None (tag_value >>| Option.some) >>= fun value -> return (name, value)

  let binding = function
    | (k, Some v) -> Some (Hmap.B (k, v))
    | _ -> None

  (* sig-v-tag       = %x76 [FWS] "=" [FWS] 1*DIGIT *)
  let v =
    let tag_name = string "v" >>| fun _ -> Key.v in
    let tag_value = take_while1 is_digit >>| int_of_string in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-a-tag       = %x61 [FWS] "=" [FWS] sig-a-tag-alg
     sig-a-tag-alg   = sig-a-tag-k "-" sig-a-tag-h
     sig-a-tag-k     = "rsa" / x-sig-a-tag-k
     sig-a-tag-h     = "sha1" / "sha256" / x-sig-a-tag-h
     x-sig-a-tag-k   = ALPHA *(ALPHA / DIGIT)
                     ; for later extension
     x-sig-a-tag-h   = ALPHA *(ALPHA / DIGIT)
                     ; for later extension *)
  let a =
    let tag_name = string "a" >>| fun _ -> Key.a in
    let tag_value =
      (rsa <|> algorithm_extension) <* char '-'
      >>= fun k -> (sha1 <|> sha256 <|> hash_extension)
      >>| fun h -> (k, h) in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-b-tag       = %x62 [FWS] "=" [FWS] sig-b-tag-data
     sig-b-tag-data  = base64string *)
  let b =
    (* XXX(dinosaure): base64string = ALPHADIGITPS *([FWS] ALPHADIGITPS) [ [FWS]
       "=" [ [FWS] "=" ] ]. Definition of the hell, a pre-processing is needed in
       this case to concat fragments separated by [FWS]. *)
    let tag_name = string "b" >>| fun _ -> Key.b in
    let tag_value = take_while1 is_base64 in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-bh-tag      = %x62 %x68 [FWS] "=" [FWS] sig-bh-tag-data
     sig-bh-tag-data = base64string *)
  let bh =
    let tag_name = string "bh" >>| fun _ -> Key.bh in
    let tag_value = take_while1 is_base64 in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-c-tag       = %x63 [FWS] "=" [FWS] sig-c-tag-alg
                  ["/" sig-c-tag-alg]
     sig-c-tag-alg   = "simple" / "relaxed" / x-sig-c-tag-alg
     x-sig-c-tag-alg = hyphenated-word    ; for later extension *)
  let c =
    let tag_name = string "c" >>| fun _ -> Key.c in
    let tag_value =
      let sig_c_tag_alg = (simple <|> relaxed <|> (hyphenated_word >>| fun x -> Value.Canonicalization_ext x)) in
      sig_c_tag_alg >>= fun h -> option Value.Simple (char '/' *> sig_c_tag_alg) >>= fun b -> return (h, b) in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-d-tag       = %x64 [FWS] "=" [FWS] domain-name
     domain-name     = sub-domain 1*("." sub-domain)
                  ; from [RFC5321] Domain,
                  ; excluding address-literal *)
  let d =
    let tag_name = string "d" >>| fun _ -> Key.d in
    let tag_value = domain_name in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-h-tag       = %x68 [FWS] "=" [FWS] hdr-name
                   *( [FWS] ":" [FWS] hdr-name ) *)
  let h =
    let tag_name = string "h" >>| fun _ -> Key.h in
    let tag_value = hdr_name >>= fun x -> many (char ':' *> hdr_name) >>= fun r -> return (x :: r) in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-i-tag       = %x69 [FWS] "=" [FWS] [ Local-part ]
                           "@" domain-name *)
  let i =
    let tag_name = string "i" >>| fun _ -> Key.i in
    let tag_value = option None (local_part >>| Option.some) >>= fun local -> char '*' *> domain_name >>= fun domain ->
      return { Value.local; domain } in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-l-tag    = %x6c [FWS] "=" [FWS]
                1*76DIGIT *)
  let l =
    let tag_name = string "l" >>| fun _ -> Key.l in
    let tag_value = take_while1 is_digit >>| int_of_string in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-q-tag        = %x71 [FWS] "=" [FWS] sig-q-tag-method
                      *([FWS] ":" [FWS] sig-q-tag-method)
      sig-q-tag-method = "dns/txt" / x-sig-q-tag-type
                         ["/" x-sig-q-tag-args]
      x-sig-q-tag-type = hyphenated-word  ; for future extension
      x-sig-q-tag-args = qp-hdr-value *)
  let q =
    let tag_name = string "q" >>| fun _ -> Key.q in
    let tag_value =
      let sig_q_tag_method =
        (string "dns/txt" >>| fun _ -> `DNS_TXT)
        <|> (hyphenated_word >>| fun x -> `Query_ext x)
        >>= fun meth -> option None (char '/' *> qp_hdr_value >>| Option.some)
        >>= fun args -> return (meth, args) in
      sig_q_tag_method >>= fun x -> many (char ':' *> sig_q_tag_method) >>= fun r -> return (x :: r) in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-s-tag    = %x73 [FWS] "=" [FWS] selector *)
  let s =
    let tag_name = string "s" >>| fun _ -> Key.s in
    let tag_value = selector in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-t-tag    = %x74 [FWS] "=" [FWS] 1*12DIGIT *)
  let t =
    let tag_name = string "t" >>| fun _ -> Key.t in
    let tag_value = take_while1 is_digit >>| Int64.of_string in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-x-tag    = %x78 [FWS] "=" [FWS]
                              1*12DIGIT *)
  let x =
    let tag_name = string "x" >>| fun _ -> Key.x in
    let tag_value = take_while1 is_digit >>| Int64.of_string in
    tag_spec ~tag_name ~tag_value >>| binding

  (* sig-z-tag      = %x7A [FWS] "=" [FWS] sig-z-tag-copy
                 *( "|" [FWS] sig-z-tag-copy )
     sig-z-tag-copy = hdr-name [FWS] ":" qp-hdr-value *)
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

let parse_dkim x =
  match Angstrom.parse_string Parser.tag_list x with
  | Ok v -> Ok v
  | Error _ -> Rresult.R.error_msgf "Invalid DKIM Signature: %S" x

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

let src = Logs.Src.create "dkim" ~doc:"logs dkim's event"
module Log = (val Logs.src_log src : Logs.LOG)

let field_dkim_signature = Mrmime.Field.of_string_exn "DKIM-Signature"

let extract_dkim ?(newline = LF) (type flow) (flow : flow) (module Flow : FLOW with type flow = flow) =
  let open Mrmime in
  let chunk = 0x1000 in
  let raw = Bytes.create chunk in
  let buffer = Bigstringaf.create (2 * chunk) in
  let decoder = St_header.decoder ~field:field_dkim_signature St_header.Value.Unstructured buffer in
  let rec go others acc = match St_header.decode decoder with
    | `Field dkim_value ->
      let acc = match unfold dkim_value with
        | Error (`Msg err) ->
          Log.warn (fun f -> f "Got an error when we unfold DKIM-Signature: %s" err) ;
          acc
        | Ok lst -> match parse_dkim (String.concat "" lst) with
          | Ok dkim_value -> dkim_value :: acc
          | Error (`Msg err) ->
            Log.warn (fun f -> f "Got an error when we parse DKIM-Signature: %s" err) ;
            acc in
      go others acc
    | `Other (field, raw) -> go ((field, raw) :: others) acc
    | `Lines _ -> go others acc
    | `Malformed err -> Rresult.R.error_msg err
    | `End rest -> Rresult.R.ok (rest, List.rev others, List.rev acc)
    | `Await ->
      let len = Flow.input flow raw 0 (Bytes.length raw) in
      let raw = sanitize_input newline raw len in
      match St_header.src decoder raw 0 (String.length raw) with
      | Ok () -> go others acc
      | Error _ as err -> err in
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
  ; s : Domain_name.t
  ; t : int64 option
  ; x : int64 option
  ; z : (Mrmime.Field.t * string) list }
and hash = V : 'k Digestif.hash -> hash
and value = H : 'k Digestif.hash * 'k Digestif.t -> value

let expected { bh; _ } = bh

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

let pp_hex ppf x =
  String.iter (fun x -> Fmt.pf ppf "%02x" (Char.code x)) x

module Refl = struct type ('a, 'b) t = Refl : ('a, 'a) t end

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

let pp_dkim ppf t =
  Fmt.pf ppf "{ @[<hov>v = %d;@ a = %a;@ b = %a;@ bh = %a; c = %a;@ d = %a;@ h = @[<hov>%a@];@ \
                       i = @[<hov>%a@];@ l = %a;@ q = @[<hov>%a@];@ s = %a;@ t = %a;@ x = %a;@ \
                       z = @[<hov>%a@];@] }"
    t.v Fmt.(Dump.pair Value.pp_algorithm pp_hash) t.a
    pp_hex t.b (pp_signature (snd t.a)) t.bh Fmt.(Dump.pair Value.pp_canonicalization Value.pp_canonicalization) t.c
    Domain_name.pp t.d Fmt.(Dump.list Mrmime.Field.pp) t.h Fmt.(Dump.option Value.pp_auid) t.i Fmt.(Dump.option int) t.l
    Fmt.(Dump.list Value.pp_query) t.q Domain_name.pp t.s Fmt.(Dump.option int64) t.t Fmt.(Dump.option int64) t.x
    Fmt.(Dump.list Value.pp_copy) t.z

let hash_ext = function
  | hash -> Fmt.invalid_arg "Hash %s not found" hash (* TODO *)

let string_of_quoted_printable x =
  let decoder = Pecu.Inline.decoder (`String x) in
  let res = Buffer.create 0x800 in
  let rec go () = match Pecu.Inline.decode decoder with
    | `Await -> assert false
    | `Char chr -> Buffer.add_char res chr ; go ()
    | `End -> Rresult.R.ok (Buffer.contents res)
    | `Malformed err -> Rresult.R.error_msg err in
  go ()

let post_process_dkim hmap =
  let v = match Hmap.find Key.v hmap with
    | Some v -> v
    | None -> Fmt.invalid_arg "Version is required" in
  let a = match Hmap.find Key.a hmap with
    | Some (alg, Value.SHA1) -> (alg, V Digestif.SHA1)
    | Some (alg, Value.SHA256) -> (alg, V Digestif.SHA256)
    | Some (alg, Value.Hash_ext x) -> (alg, hash_ext x)
    | None -> Fmt.invalid_arg "Algorithm is required" in
  let b = match Option.map Base64.decode (Hmap.find Key.b hmap) with
    | Some (Ok v) -> v
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Signature data is required" in
  let bh = match Option.map Base64.decode (Hmap.find Key.bh hmap) with
    | Some (Error (`Msg err)) -> invalid_arg err
    | None -> Fmt.invalid_arg "Hash of canonicalized body part is required"
    | Some (Ok v) -> let (_, V k) = a in match Digestif.of_raw_string_opt k v with
      | Some v -> H (k, v)
      | None -> Fmt.invalid_arg "Invalid hash" in
  let c = match Hmap.find Key.c hmap with
    | Some v -> v
    | None -> Value.Simple, Value.Simple in
  let d = match Option.map (Domain_name.of_string <.> String.concat ".") (Hmap.find Key.d hmap) with
    | Some (Ok v) -> v
    | Some (Error (`Msg err)) ->
      Fmt.invalid_arg "Retrieve an error with %a: %s"
        Fmt.(Dump.option (Dump.list string)) (Hmap.find Key.d hmap)
        err
    | None -> Fmt.invalid_arg "SDID is required" in
  let h = match Option.map (List.map Mrmime.Field.of_string_exn) (Hmap.find Key.h hmap) with
    | Some v -> v (* XXX(dinosaure): [Parser.field_name] checks values. So, no post-process is required. *)
    | None -> Fmt.invalid_arg "Signed header fields required" in
  let i = Hmap.find Key.i hmap in
  let l = Hmap.find Key.l hmap in
  let q =
    List.map (fun (q, x) -> match Option.map string_of_quoted_printable x with
        | None -> (q, None)
        | Some (Ok x) -> (q, Some x)
        | Some (Error (`Msg err)) -> invalid_arg err)
    (Option.value ~default:[] (Hmap.find Key.q hmap)) in
  let s = match Option.map (Domain_name.of_string ~hostname:false <.> String.concat ".") (Hmap.find Key.s hmap) with
    | Some (Ok v) -> v
    | Some (Error (`Msg err)) ->
      Fmt.invalid_arg "Retrieve an error with %a: %s"
        Fmt.(Dump.option (Dump.list string)) (Hmap.find Key.s hmap)
        err
    | None -> Fmt.invalid_arg "Selector is required" in
  let t = Hmap.find Key.t hmap in
  let x = Hmap.find Key.x hmap in
  let z =
    List.map
      (fun (f, x) -> match string_of_quoted_printable x with
         | Ok x -> (Mrmime.Field.of_string_exn f, x)
         | Error (`Msg err) -> invalid_arg err)
    (Option.(value ~default:[] (Hmap.find Key.z hmap))) in
  { v; a; b; bh; c; d; h; i; l; q; s; t; x; z }

let simple_field_canonicalization field f = f field

let relaxed_field_canonicalization field f =
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
  match Angstrom.parse_string parser field with
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
      trim <.> List.rev <.> List.fold_left
        (fun a x -> match a, x with
           | `WSP _ :: _, `WSP _ -> a
           (* Convert all sequences of one or more WSP characters to a single SP
              character. WSP characters here include those before and after a
              line folding boundary. *)
           | a, x -> x :: a)
        [] in
    List.iter
      (function
        | `CRLF -> ()
        | `CR n -> f (String.make n '\r')
        | `LF n -> f (String.make n '\n')
        | `Text x -> f x
        | `Encoded { Mrmime.Encoded_word.data= Ok x; _ } -> f x
        | `WSP _ -> f " "
        (* Convert all sequences of one or more WSP characters to a single SP character.
           WSP characters here include those before and after a line folding boundary. *)
        | `Encoded { Mrmime.Encoded_word.data= Error (`Msg err); raw; _ } ->
          Fmt.invalid_arg "%s with %S" err raw)
      (unfold unstructured) ;
    f "\r\n" (* Implementations MUST NOT remove the CRLF at the end of the
                header field value. *)
  | Error _ -> assert false
    (* [Mrmime] already extracted [field] with, at least, [unstructured] parser.
       In other side, we rely on that RFC said [unstructured] __is__ a super-set of
       any other special values (like date). *)

module Simple_body = struct
  type decode = [ `Data of string | `Await | `End | `CRLF | `Spaces of string ]

  type decoder =
    { mutable i : bytes
    ; mutable i_pos : int
    ; mutable i_len : int
    ; mutable has_cr : bool
    ; b : Buffer.t (* XXX(dinosaure): we should replace it by something else
                      where it can be an entry point for an attack. *)
    ; mutable k : decoder -> decode }

  let i_rem d = d.i_len - d.i_pos + 1

  let end_of_input d =
    d.i <- Bytes.empty ;
    d.i_pos <- 0 ;
    d.i_len <- min_int

  let src decoder source off len =
    if off < 0 || len < 0 || off + len > Bytes.length source
    then Fmt.invalid_arg "Invalids bounds"
    else if len = 0
    then end_of_input decoder
    else (
      decoder.i <- source ;
      decoder.i_pos <- off ;
      decoder.i_len <- off + len - 1 )

  let ret k v decoder =
    decoder.k <- k ; v

  let rec t_crlf k decoder =
    ret k `CRLF decoder

  and t_end decoder =
    decoder.k <- t_end ; `End

  and t_data s k decoder =
    ret k (`Data s) decoder

  and t_space j decoder =
    let idx = ref j in
    let chr = ref '\000' in

    while decoder.i_len - !idx >= 0
          && ( chr := Bytes.get decoder.i !idx
             ; !chr = ' ' || !chr = '\t' )
    do incr idx done ;

    let i = decoder.i_pos in
    let s = Bytes.sub_string decoder.i i (j - i) in
    let s = if decoder.has_cr then "\r" ^ s else s in
    let n = Bytes.sub_string decoder.i j (!idx - j) in

    Buffer.add_string decoder.b n ;
    decoder.has_cr <- false ;
    decoder.i_pos <- !idx ;

    if String.length s = 0
    then t_decode decoder
    else ret (fun decoder ->
        let s = Buffer.contents decoder.b in
        (* XXX(dinosaure): in [t_spaces], we ensure that [decoder.b] as, at
           least, one space. *)
        Buffer.clear decoder.b ;
        ret t_decode (`Spaces s) decoder)
        (`Data s) decoder

  and t_space_or k v decoder =
    if Buffer.length decoder.b > 0
    then ( let s = Buffer.contents decoder.b in Buffer.clear decoder.b ; ret (ret k v) (`Spaces s) decoder )
    else ret k v decoder

  and t_decode decoder =
    let rem = i_rem decoder in
    if rem <= 0 then
      if rem < 0
      then ( if decoder.has_cr then t_space_or t_end (`Data "\r") decoder else t_space_or t_end `End decoder )
      else `Await
    else match decoder.has_cr with
      | true ->
        if Bytes.get decoder.i decoder.i_pos = '\n'
        then ( decoder.i_pos <- decoder.i_pos + 1 ; decoder.has_cr <- false ; `CRLF )
        else
          ( let idx = ref decoder.i_pos in
            let chr = ref '\000' in

            while decoder.i_len - !idx >= 0
                  && ( chr := Bytes.get decoder.i !idx
                     ; !chr <> '\r' && !chr <> ' ' && !chr <> '\t' )
            do incr idx done ;

            if !chr = '\r'
            then ( let j = decoder.i_pos in
                   decoder.i_pos <- !idx + 1
                 ; let s = Bytes.sub_string decoder.i j (!idx - j) in
                   let s = "\r" ^ s in
                   decoder.has_cr <- true
                 ; t_space_or t_decode (`Data s) decoder )
            else if (!chr = ' ' || !chr = '\t')
            then t_space !idx decoder
            else ( let j = decoder.i_pos in
                   decoder.i_pos <- !idx + 1
                 ; let s = Bytes.sub_string decoder.i j (!idx + 1 - j) in
                   let s = "\r" ^ s in
                   decoder.has_cr <- false
                 ; t_space_or t_decode (`Data s) decoder ) )
      | false ->
        let idx = ref decoder.i_pos in
        let chr = ref '\000' in

        while decoder.i_len - !idx >= 0
              && ( chr := Bytes.get decoder.i !idx
                 ; !chr <> '\r' && !chr <> ' ' && !chr <> '\t' )
        do incr idx done ;

        if !chr = '\r'
        then ( let j = decoder.i_pos in
               decoder.i_pos <- !idx + 1
             ; let s = Bytes.sub_string decoder.i j (!idx - j) in
               decoder.has_cr <- true
             ; if s = "" then t_decode decoder else t_space_or t_decode (`Data s) decoder )
        else if (!chr = ' ' || !chr = '\t')
        then t_space !idx decoder
        else ( let j = decoder.i_pos in
               decoder.i_pos <- !idx
             ; let s = Bytes.sub_string decoder.i j (!idx - j) in
               decoder.has_cr <- false
             ; if s = "" then t_decode decoder else ( Fmt.epr "t_space_or.\n%!" ; t_space_or t_decode (`Data s) decoder ) )

  let decode decoder = decoder.k decoder

  let decoder () =
    { i= Bytes.empty
    ; i_pos= 1
    ; i_len= 0
    ; has_cr= false
    ; b= Buffer.create 16
    ; k= t_decode }
end

let simple_body_canonicalization () =
  (* RFC 6376 said:

     The "simple" body canonicalization algorithm ignores all empty lines at the
     end of the message body. An empty line is a line of zero length after
     removal of the line line terminator. If there is no body or trailing CRLF
     on the message body, a CRLF is added. It makes no other changes to the
     message body. In more formal terms, the "simple" body canonicalization
     algorithm converts "*CRLF" at the end of the body to a single "CRLF".

     Note that a completely empty or missing body is canonicalized as a single
     "CRLF"; that is, the canonicalized length will be 2 octets. *)
  assert false

let post_process_dkim hmap =
  try Rresult.R.ok (post_process_dkim hmap)
  with Invalid_argument err -> Rresult.R.error_msg err

let digesti_of_hash (V hash) = fun f -> let v = Digestif.digesti_string hash f in H (hash, v)

exception Find

let list_assoc ~equal x l =
  let res = ref None in
  try List.iter (fun (y, v) -> if equal x y then ( res := Some v ; raise Find )) l ; raise Not_found
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

let crlf digest n =
  let rec go = function
    | 0 -> ()
    | n -> digest "\r\n" ; go (pred n) in
  if n < 0 then Fmt.invalid_arg "Expect at least 0 <crlf>"
  else go n

let digest_body
  : type flow. ?newline:newline -> flow -> (module FLOW with type flow = flow) -> (string * dkim) -> value
  = fun ?(newline = LF) (type flow) (flow : flow) (module Flow : FLOW with type flow = flow) (prelude, dkim) ->
  let relaxed = match snd dkim.c with
    | Value.Simple -> false
    | Value.Relaxed -> true
    | Value.Canonicalization_ext _ -> assert false (* TODO *) in
  let decoder = Simple_body.decoder () in
  let chunk = 0x1000 in
  let raw = Bytes.create chunk in
  let q = Queue.create () in
  let f = fun x -> Queue.push x q in
  Bytes.blit_string prelude 0 raw 0 (String.length prelude) ;
  (* XXX(dinosaure): [prelude] comes from [extract_dkim] and should be [<= 0x1000]. *)
  let digest_stack f l =
    let rec go = function
      | [] -> ()
      | [ `Spaces x ] -> f (if relaxed then " " else x)
      | `CRLF :: r -> f "\r\n" ; go r
      | `Spaces x :: r -> if not relaxed then f x ; go r in
    go (List.rev l) in
  let rec go stack = match Simple_body.decode decoder with
    | `Await ->
      let len = Flow.input flow raw 0 (Bytes.length raw) in
      let raw = sanitize_input newline raw len in
      Simple_body.src decoder (Bytes.unsafe_of_string raw) 0 (String.length raw) ;
      go stack
    | `End -> crlf f 1 ; () (* TODO: relaxed <> simple at the end.*)
    | `Spaces _ as x -> go (x :: stack)
    | `CRLF -> go (`CRLF :: stack)
    | `Data x ->
      digest_stack f stack ;
      f x ; go [] in
  Simple_body.src decoder raw 0 (String.length prelude) ; go [] ;
  let digesti = digesti_of_hash (snd dkim.a) in
  digesti (fun f -> Queue.iter f q)

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
       try let raw = list_assoc ~equal:Mrmime.Field.equal requested others in
         canonicalization raw (fun x -> Queue.push x q)
       with Not_found -> Fmt.invalid_arg "Field %a not found" Mrmime.Field.pp requested)
    dkim.h ;
  digesti (fun f -> Queue.iter f q)
