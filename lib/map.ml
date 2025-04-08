type 'a ty = Unknown : string ty | Any : 'a ty
type 'a tag = { name : string; pp : 'a Fmt.t; ty : 'a ty }

module Info = struct
  type 'a t = 'a tag = { name : string; pp : 'a Fmt.t; ty : 'a ty }
end

include Hmap.Make (Info)

module K = struct
  open Value

  let v : version key =
    let name = "version" and pp = Fmt.int and ty = Any in
    Key.create { name; pp; ty }

  let a : (algorithm * hash) key =
    let name = "algorithm"
    and pp = Fmt.(Dump.pair Value.pp_algorithm Value.pp_hash)
    and ty = Any in
    Key.create { name; pp; ty }

  let b : base64 key =
    let name = "signature" and pp = Fmt.string and ty = Any in
    Key.create { name; pp; ty }

  let bh : base64 key =
    let name = "hash" and pp = Fmt.string and ty = Any in
    Key.create { name; pp; ty }

  let c : (canonicalization * canonicalization) key =
    let name = "canonicalization"
    and pp = Fmt.(Dump.pair Value.pp_canonicalization Value.pp_canonicalization)
    and ty = Any in
    Key.create { name; pp; ty }

  let d : domain_name key =
    let name = "domain" and pp = Value.pp_domain_name and ty = Any in
    Key.create { name; pp; ty }

  let h : Mrmime.Field_name.t list key =
    let name = "field"
    and pp = Fmt.(Dump.list Mrmime.Field_name.pp)
    and ty = Any in
    Key.create { name; pp; ty }

  let i : auid key =
    let name = "auid" and pp = Value.pp_auid and ty = Any in
    Key.create { name; pp; ty }

  let l : int key =
    let name = "length" and pp = Fmt.int and ty = Any in
    Key.create { name; pp; ty }

  let q : query list key =
    let name = "query" and pp = Fmt.(Dump.list Value.pp_query) and ty = Any in
    Key.create { name; pp; ty }

  let s : selector key =
    let name = "selector" and pp = Value.pp_selector and ty = Any in
    Key.create { name; pp; ty }

  let t : int64 key =
    let name = "timestamp" and pp = Fmt.int64 and ty = Any in
    Key.create { name; pp; ty }

  let x : int64 key =
    let name = "expiration" and pp = Fmt.int64 and ty = Any in
    Key.create { name; pp; ty }

  let z : copies key =
    let name = "copies" and pp = Fmt.(Dump.list Value.pp_copy) and ty = Any in
    Key.create { name; pp; ty }

  let sv : server_version key =
    let name = "server-version" and pp = Fmt.string and ty = Any in
    Key.create { name; pp; ty }

  let sh : hash list key =
    let name = "hashes" and pp = Fmt.(Dump.list Value.pp_hash) and ty = Any in
    Key.create { name; pp; ty }

  let k : algorithm key =
    let name = "algorithm" and pp = Value.pp_algorithm and ty = Any in
    Key.create { name; pp; ty }

  let p : base64 key =
    let name = "public-key" and pp = Fmt.string and ty = Any in
    Key.create { name; pp; ty }

  let n : string key =
    let name = "notes" and pp = Fmt.string and ty = Any in
    Key.create { name; pp; ty }

  let ss : service list key =
    let name = "services"
    and pp = Fmt.(Dump.list Value.pp_service)
    and ty = Any in
    Key.create { name; pp; ty }

  let st : name list key =
    let name = "names" and pp = Fmt.(Dump.list Value.pp_name) and ty = Any in
    Key.create { name; pp; ty }

  let unknown : string -> string key =
   fun name ->
    let pp = Fmt.string and ty = Unknown in
    Key.create { name; pp; ty }
end
