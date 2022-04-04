(*
 * (c) 2004-2011 Anastasia Gornostaeva
 *
 * RFC 2831 Digest SASL Mechanism
 *
 *)

exception Error of string
exception Failure of string

type t =
  | Token of string
  | Separator of char

let separators = ['('; ')'; '<'; '>'; '@';
                  ','; ';'; ':'; '\\'; '"';
                  '/'; '['; ']'; '?'; '=';
                  '{'; '}'; ' '; '\t'
                 ]

let is_ctl ch =
  match ch with
    | '\000'..'\031' -> true
    | '\127' -> true
    | _ -> false

let make_lexer =
  let buf = Buffer.create 100 in
  let rec tokenizer strm =
    match Stream.peek strm with
      | Some ch ->
          if ch = '"' then (
            Stream.junk strm;
            get_string strm
          ) else if ch = ' ' || ch = '\t' || is_ctl ch then (
            Stream.junk strm;
            tokenizer strm
          ) else if List.mem ch separators then (
            Stream.junk strm;
            Some (Separator ch)
          ) else
            get_token strm
      | None -> None
  and get_string strm =
    match Stream.peek strm with
      | Some ch ->
          if ch = '"' then (
            Stream.junk strm;
            let str = Buffer.contents buf in
              Buffer.reset buf;
              Some (Token str)
          ) else if ch = '\\' then (
            Stream.junk strm;
            match Stream.peek strm with
              | Some ch1 ->
                  Stream.junk strm;
                  Buffer.add_char buf ch1;
                  get_string strm
              | None ->
                  failwith "Unterminated string"
          )
          else (
            Stream.junk strm;
            Buffer.add_char buf ch;
            get_string strm
          )
      | None ->
          failwith "Unterminated string"
  and get_token strm =
    match Stream.peek strm with
      | Some ch ->
          if List.mem ch separators || is_ctl ch then
            let str = Buffer.contents buf in
              Buffer.reset buf;
              Some (Token str)
          else (
            Stream.junk strm;
            Buffer.add_char buf ch;
            get_token strm
          )
      | None ->
          let str = Buffer.contents buf in
            Buffer.reset buf;
            Some (Token str)
  in
    fun strm -> Stream.from (fun _ -> tokenizer strm)

let get_pairs str =
  let rec scan acc = parser
  | [< 'Token t1; 'Separator '='; 'Token t2; rest >] ->
      check_comma ((t1, t2) :: acc) rest
and check_comma acc = parser
  | [< 'Separator ','; rest >] ->
      scan acc rest
  | [< >] ->
      List.rev acc
  in
  let strm = make_lexer (Stream.of_string str) in
    try
      scan [] strm
    with _ -> raise (Error "Malformed SASL challenge")

let parse_qop str =
  let rec qop acc = parser
    | [< 'Token t; rest >] ->
        check_comma (t :: acc) rest
    | [< >] ->
        List.rev acc
  and check_comma acc = parser
    | [< 'Separator ','; rest >] ->
        qop acc rest
    | [< >] ->
        List.rev acc
  in
  let strm = make_lexer (Stream.of_string str) in
    try
      qop [] strm
    with _ ->
      raise (Error "Malformed qop in SASL challenge")

let h s =
  let cs = Cstruct.of_string s in
  let res = Mirage_crypto.Hash.digest `MD5 cs in
  Cstruct.to_string res

let hex s =
  let cs = Cstruct.of_string s in
  let rec fill acc = function
    | x when x = Cstruct.length cs -> acc
    | x ->
       let datum = acc ^ Printf.sprintf "%02x" (Cstruct.get_uint8 cs x) in
       fill datum (x + 1)
  in
  fill "" 0

let response_value ~username ~realm ~nonce ~cnonce ~qop ~nc ~digest_uri ~passwd =
  let a1 =
    (h (username ^ ":" ^ realm ^ ":" ^ passwd)) ^ ":" ^ nonce ^ ":" ^ cnonce
  and a2 = "AUTHENTICATE:" ^ digest_uri in
  let t = (hex (h a1)) ^ ":" ^ nonce ^ ":" ^ nc ^ ":" ^ cnonce ^ ":" ^
    qop ^ ":" ^ (hex (h a2)) in
    hex (h t)

let make_cnonce () =
  let random = Mirage_crypto_rng.generate 8 in
  hex (Cstruct.to_string random)

let b64enc data = Base64.encode_string data

let b64dec data =
  match Base64.decode data with
  | Error _ -> assert false
  | Ok x -> x

let parse_digest_md5_challenge str =
  let pairs = get_pairs str in
    try
      let qop = parse_qop (List.assoc "qop" pairs)
      and nonce = List.assoc "nonce" pairs
      and realm = if List.mem_assoc "realm" pairs then
                    List.assoc "realm" pairs
                  else
                    ""
      in
      (realm, qop, nonce)
    with Not_found ->
      raise (Error "Malformed SASL challenge")

let sasl_digest_response chl username domain digest_uri passwd =
  let str = b64dec chl in
  let realm, qop, nonce = parse_digest_md5_challenge str
  and cnonce = make_cnonce ()
  and nc = "00000001"
  in
    if List.mem "auth" qop then
      let qop_method = "auth" in
      let digest_uri =
        if realm = "" then
          digest_uri ^ domain
        else
          digest_uri ^ realm
      in
      let response = response_value ~username ~realm
        ~nonce ~cnonce ~nc ~qop:qop_method ~digest_uri ~passwd in
      let resp = Printf.sprintf
        "charset=utf-8,username=\"%s\",realm=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=%s,qop=\"%s\",digest-uri=\"%s\",response=%s"
        username realm nonce cnonce nc qop_method digest_uri response
      in
      b64enc resp
    else
      raise (Error "No known qop methods")

let sasl_digest_rspauth chl =
  let str = b64dec chl in
  let pairs = get_pairs str in
  let _rspauth = List.assoc "rspauth" pairs in
  ()

let sasl_plain authorization_id authentication_id passwd =
  let str =
    String.concat "\000" [ authorization_id ; authentication_id ; passwd ]
  in
  b64enc str
