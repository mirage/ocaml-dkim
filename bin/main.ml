module Caml_flow : Dkim.FLOW with type flow = in_channel = struct
  type flow = in_channel

  let input = Pervasives.input
end

let () =
  match Dkim.extract_dkim stdin (module Caml_flow) with
  | Ok values ->
    let values = List.map
        (fun value -> match Dkim.post_process_dkim value with
           | Ok value -> value
           | Error (`Msg err) -> invalid_arg err)
        values in
    Fmt.pr "%a.\n%!" Fmt.(Dump.list Dkim.pp_dkim) values
  | Error (`Msg err) -> Fmt.epr "Retrieve an error: %s.\n%!" err
