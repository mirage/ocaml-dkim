let computation = Dkim.remove_signature_of_raw_dkim

let v str =
  let _, v = Unstrctrd.safely_decode str in
  v

let rem str =
  let res = Dkim.remove_signature_of_raw_dkim (v str) in
  Unstrctrd.to_utf_8_string res

let test_0 =
  Alcotest.test_case "b=sig;" `Quick @@ fun () ->
  Alcotest.(check string) "" (rem "b=sig;") "b=;"

let test_3 =
  Alcotest.test_case "b=|<wsp>sig<wsp>|;" `Quick @@ fun () ->
  Alcotest.(check string) "" (rem "b= sig ;") "b=;"

let test_4 =
  Alcotest.test_case "s=1234;|b=sig;" `Quick @@ fun () ->
  Alcotest.(check string) "" (rem "s=1234; b=sig;") "s=1234; b=;"

let test_6 =
  Alcotest.test_case "s|=1234|;|b=|sig|;" `Quick @@ fun () ->
  Alcotest.(check string) "" (rem "s=1234;b=sig;") "s=1234;b=;"

let test_7 =
  Alcotest.test_case "b=|<wsp>|s|<wsp>|ig|<wsp>|;" `Quick @@ fun () ->
  Alcotest.(check string) "" (rem "b= s ig ;") "b=;"

let test_8 =
  Alcotest.test_case "errored" `Quick @@ fun () ->
  let field_value =
    "v=1;a=rsa-sha256;c=relaxed/relaxed;s=k1;d=mailchimpapp.net;h=Subject:From:Reply-To:To:Date:Message-ID:List-ID:List-Unsubscribe:Content-Type:MIME-Version;i=marion=3D3Dbimbimgo.com@mailchimpapp.net;bh=4rPKuuElHjwTg+Bu4bqi+wBpN+CnFMJNj3Ku9+nqvc0=;b=U740GmA0kaYm23vArgtjWpDht5KNerlw9N3fNniErALcxhh0239S/RZeG0tjsOK/sUc7vOCuakOyNxBc6X0rNRbKb4A5SvjIA0ogrwYJeJ42GID9KE2GNluIQnLImp5tAcQLGok8OVFAxbwdDjHIG0J7/4WYhhKNMIf2RxmYoBg="
  in
  let field_value = Unstrctrd.of_string (field_value ^ "\r\n") in
  let _, field_value = Result.get_ok field_value in
  match Dkim.parse_dkim_field_value field_value with
  | Ok _ -> ()
  | Error (`Msg err) -> Alcotest.fail err

let () =
  Alcotest.run "dkim_field"
    [
      ("signature", [ test_0; test_3; test_4; test_6; test_7 ]);
      ("field-value", [ test_8 ]);
    ]
