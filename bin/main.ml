module Caml_flow : Dkim.FLOW with type flow = in_channel = struct
  type flow = in_channel

  let input = Pervasives.input
end

let () =
  match Dkim.extract_dkim stdin (module Caml_flow) with
  | Ok () -> ()
  | Error (`Msg err) -> Fmt.epr "Retrieve an error: %s.\n%!" err
