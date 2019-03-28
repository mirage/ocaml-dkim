let computation = Dkim.remove_signature_of_raw_dkim

let unstructured = Alcotest.testable Mrmime.Unstructured.pp Mrmime.Unstructured.equal

let test_0 =
  Alcotest.test_case "b=sig;" `Quick @@
  fun () -> Alcotest.(check unstructured) "[]" (computation [ `Text "b=sig;"]) [ `Text "b=;"]
let test_1 =
  Alcotest.test_case "b|=|sig|;" `Quick @@
  fun () -> Alcotest.(check unstructured) "[]" (computation [ `Text "b"; `Text "="; `Text "sig"; `Text ";" ]) [ `Text "b"; `Text "="; `Text ";" ]
let test_2 =
  Alcotest.test_case "b=|sig;" `Quick @@
  fun () -> Alcotest.(check unstructured) "[]" (computation [ `Text "b="; `Text "sig;"; ]) [ `Text "b="; `Text ";" ]
let test_3 =
  Alcotest.test_case "b=|<wsp>sig<wsp>|;" `Quick @@
  fun () -> Alcotest.(check unstructured) "[]" (computation [ `Text "b="; `WSP " "; `Text "sig"; `WSP " "; `Text ";"; ]) [ `Text "b="; `Text ";" ]
let test_4 =
  Alcotest.test_case "s=1234;|b=sig;" `Quick @@
  fun () -> Alcotest.(check unstructured) "[]" (computation [ `Text "s=1234;"; `Text "b=sig;"]) [ `Text "s=1234;"; `Text "b=;" ]
let test_5 =
  Alcotest.test_case "s=1234;|<wsp>|b=sig;" `Quick @@
  fun () -> Alcotest.(check unstructured) "[]" (computation [ `Text "s=1234;"; `WSP " "; `Text "b=sig;"]) [ `Text "s=1234;"; `WSP " "; `Text "b=;" ]
let test_6 =
  Alcotest.test_case "s|=1234|;|b=|sig|;" `Quick @@
  fun () -> Alcotest.(check unstructured) "[]" (computation [ `Text "s"; `Text "=1234"; `Text ";"; `Text "b="; `Text "sig"; `Text ";" ])
    [ `Text "s"; `Text "=1234"; `Text ";"; `Text "b="; `Text ";" ]
let test_7 =
  Alcotest.test_case "b=|<wsp>|s|<wsp>|ig|<wsp>|;" `Quick @@
  fun () -> Alcotest.(check unstructured) "[]" (computation [ `Text "b="; `WSP " "; `Text "s"; `WSP " "; `Text "ig"; `WSP " "; `Text ";" ])
    [ `Text "b="; `Text ";" ]

let () =
  Alcotest.run "dkim_field"
    [ "signature", [ test_0; test_1; test_2; test_3; test_4; test_5; test_6; test_7 ] ]
