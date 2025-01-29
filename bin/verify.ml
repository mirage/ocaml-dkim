open Lwt.Infix

let show_result ~valid:v_valid ~invalid:v_invalid =
  let valid (Dkim.Verify.Signature { dkim; _ }) =
    Fmt.pr "[%a]: %a\n%!"
      Fmt.(styled `Green string)
      "ok" Domain_name.pp (Dkim.domain dkim) in
  let invalid (Dkim.Verify.Signature { dkim; _ }) =
    Fmt.pr "[%a]: %a (%a)\n%!"
      Fmt.(styled `Red string)
      "er" Domain_name.pp (Dkim.domain dkim) Domain_name.pp (Dkim.selector dkim)
  in
  List.iter valid v_valid ;
  List.iter invalid v_invalid

let exit_success = 0
let exit_failure = 1

let seq_of_in_channel ic =
  let buf = Bytes.create 0x7ff in
  let rec go () =
    Lwt_io.read_into ic buf 0 (Bytes.length buf) >>= fun len ->
    if len == 0
    then Lwt.return Lwt_seq.Nil
    else
      let str = Bytes.sub_string buf 0 len in
      Lwt.return Lwt_seq.(Cons (str, go)) in
  go

let run _quiet src newline nameservers =
  let he = Happy_eyeballs_lwt.create () in
  let dns = Dns_client_lwt.create ~nameservers:(`Tcp, nameservers) he in
  let ( let* ) = Lwt.bind in
  let* seq =
    match src with
    | `Input -> Lwt.return (seq_of_in_channel Lwt_io.stdin)
    | `Path p ->
        Lwt_io.open_file ~mode:Lwt_io.input (Fpath.to_string p)
        >|= seq_of_in_channel in
  let* sigs = Dkim_lwt_unix.verify ~newline dns seq in
  match sigs with
  | Error (`Msg msg) -> failwith msg
  | Ok sigs ->
      let fn
          (Dkim.Verify.Signature
             { dkim; domain_key = _; fields; body; hash = (module Hash) } as
           result) =
        let body = Eqaf.equal (Dkim.body dkim) (Hash.to_raw_string body) in
        if body && fields then Either.Left result else Either.Right result in
      let valid, invalid = List.partition_map fn sigs in
      show_result ~valid ~invalid ;
      Lwt.return_ok 0

let run quiet src newline nameservers =
  match Lwt_main.run (run quiet src newline nameservers) with
  | Ok v -> v
  | Error (`Msg err) ->
      Fmt.epr "%s: @[@%a@]@." Sys.argv.(0) Fmt.string err ;
      exit_failure

open Cmdliner

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let input =
  let parser = function
    | "-" -> Ok `Input
    | v ->
    match Fpath.of_string v with
    | Ok path when Sys.file_exists v && not (Sys.is_directory v) ->
        Ok (`Path path)
    | Ok path -> error_msgf "%a does not exist" Fpath.pp path
    | Error _ as err -> err in
  let pp ppf = function
    | `Input -> Fmt.string ppf "-"
    | `Path path -> Fpath.pp ppf path in
  Arg.conv (parser, pp)

let newline =
  let parser str =
    match String.lowercase_ascii str with
    | "lf" -> Ok `LF
    | "crlf" -> Ok `CRLF
    | _ -> error_msgf "Invalid newline specification: %S" str in
  let pp ppf = function
    | `LF -> Fmt.string ppf "lf"
    | `CRLF -> Fmt.string ppf "crlf" in
  Arg.conv (parser, pp)

let common_options = "COMMON OPTIONS"

let verbosity =
  let env = Cmd.Env.info "VERIFY_LOGS" in
  Logs_cli.level ~env ~docs:common_options ()

let renderer =
  let env = Cmd.Env.info "VERIFY_FMT" in
  Fmt_cli.style_renderer ~docs:common_options ~env ()

let reporter ppf =
  let report src level ~over k msgf =
    let k _ =
      over () ;
      k () in
    let with_metadata header _tags k ppf fmt =
      Format.kfprintf k ppf
        ("%a[%a]: " ^^ fmt ^^ "\n%!")
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src) in
    msgf @@ fun ?header ?tags fmt -> with_metadata header tags k ppf fmt in
  { Logs.report }

let setup_logs style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer () ;
  Logs.set_level level ;
  Logs.set_reporter (reporter Fmt.stderr) ;
  Option.is_none level

(* XXX(dinosaure): if [None], [-q] is used. *)

let setup_logs = Term.(const setup_logs $ renderer $ verbosity)

let inet_addr =
  let parser str =
    try
      match String.split_on_char ':' str with
      | [ ns ] -> Ok (Unix.inet_addr_of_string ns, 53)
      | [ ns; port ] -> Ok (Unix.inet_addr_of_string ns, int_of_string port)
      | _ -> error_msgf "Invalid nameserver IP: %S" str
    with _exn -> error_msgf "Nameserver must be a valid IPv4: %S" str in
  let pp ppf (inet_addr, port) =
    Fmt.pf ppf "%s:%d" (Unix.string_of_inet_addr inet_addr) port in
  Arg.conv (parser, pp)

let nameserver_of_string str =
  let ( let* ) = Result.bind in
  match String.split_on_char ':' str with
  | "tls" :: rest -> (
      let str = String.concat ":" rest in
      match String.split_on_char '!' str with
      | [ nameserver ] ->
          let* ipaddr, port =
            Ipaddr.with_port_of_string ~default:853 nameserver in
          let* authenticator = Ca_certs.authenticator () in
          let* tls = Tls.Config.client ~authenticator () in
          Ok (`Tls (tls, ipaddr, port))
      | nameserver :: authenticator ->
          let* ipaddr, port =
            Ipaddr.with_port_of_string ~default:853 nameserver in
          let authenticator = String.concat "!" authenticator in
          let* authenticator = X509.Authenticator.of_string authenticator in
          let time () = Some (Ptime.v (Ptime_clock.now_d_ps ())) in
          let authenticator = authenticator time in
          let* tls = Tls.Config.client ~authenticator () in
          Ok (`Tls (tls, ipaddr, port))
      | [] -> assert false)
  | "tcp" :: nameserver | nameserver ->
      let str = String.concat ":" nameserver in
      let* ipaddr, port = Ipaddr.with_port_of_string ~default:53 str in
      Ok (`Plaintext (ipaddr, port))

let nameserver =
  let parser = nameserver_of_string in
  let pp ppf = function
    | `Tls (_, ipaddr, 853) ->
        Fmt.pf ppf "tls:%a!<authenticator>" Ipaddr.pp ipaddr
    | `Tls (_, ipaddr, port) ->
        Fmt.pf ppf "tls:%a:%d!<authenticator>" Ipaddr.pp ipaddr port
    | `Plaintext (ipaddr, 53) -> Fmt.pf ppf "%a" Ipaddr.pp ipaddr
    | `Plaintext (ipaddr, port) -> Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port
  in
  Arg.conv (parser, pp) ~docv:"<nameserver>"

let google_com = `Plaintext (Ipaddr.of_string_exn "8.8.8.8", 53)

let nameservers =
  let doc = "Nameservers used to resolve domain-names." in
  let env = Cmd.Env.info "VERIFY_NAMESERVERS" in
  Arg.(
    value
    & opt_all nameserver [ google_com ]
    & info [ "nameserver" ] ~docs:common_options ~doc ~docv:"<nameserver>" ~env)

let src =
  let doc =
    "The email to verify, if it's omitted, we expect something into the \
     standard input." in
  Arg.(value & pos ~rev:true 0 input `Input & info [] ~docv:"<input>" ~doc)

let newline =
  let doc =
    "Depending on the transmission, an email can use the $(i,CRLF) end-of-line \
     (network transmission) or the LF end-of-line (UNIX transmission). By \
     default, we assume an UNIX transmission (LF character)." in
  Arg.(value & opt newline `LF & info [ "newline" ] ~doc ~docv:"<newline>")

let term = Term.(const run $ setup_logs $ src $ newline $ nameservers)

let verify =
  let doc = "Verify DKIM-Signature of the given email." in
  let exits = Cmd.Exit.defaults in
  let man =
    [
      `S Manpage.s_description;
      `P
        "$(b,verify) does the DKIM verification process. It checks signatures \
         and does the DNS request to verify these signatures. Then, it shows \
         which signature is valid which is not.";
    ] in
  Cmd.v (Cmd.info "verify" ~version:"%%VERSION%%" ~doc ~exits ~man) term

let () = exit @@ Cmd.eval' verify
