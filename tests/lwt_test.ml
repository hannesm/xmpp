open StanzaError

module PlainSocket =
struct
  open Lwt

  type 'a z = 'a Lwt.t

  type fd = Lwt_unix.file_descr

  type socket = fd

  let get_fd fd = fd

  let open_connection sockaddr =
    let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
      Lwt_unix.connect fd sockaddr >>= fun () ->
    return fd

  let read fd buf start len =
    Lwt_unix.read fd buf start len >>=
      (fun size ->
        if size > 0 then
          print_string "IN: "; print_endline (String.sub buf start size);
        return size
      )

  let write fd str =
    print_string "OUT: ";
    print_endline str;
    let len = String.length str in
    let rec aux_send start =
      Lwt_unix.write fd str start (len - start) >>= fun sent ->
    if sent = 0 then
      return ()
    else
      aux_send (start + sent)
    in
      aux_send 0

  let close fd =
    Lwt_unix.close fd

end

module TLSSocket =
struct
  open Lwt

  let read s buf start len =
    let cs = Cstruct.create len in
    Tls_lwt.Unix.read s cs >>= fun size ->
    if size > 0 then
      (String.blit (Cstruct.to_string cs) 0 buf start size ;
       print_string "IN TLS: "; print_endline (String.sub buf start size)
      ) ;
    return size

  let write s str =
    print_string "OUT TLS: ";
    print_endline str;
    Tls_lwt.Unix.write s (Cstruct.of_string str)

  let switch fd host =
    Mirage_crypto_rng.unix.initialize ();
    X509_lwt.authenticator (`Ca_dir "certificates") >>= fun authenticator ->
    let config = Tls.Config.client ~authenticator () in
    Tls_lwt.Unix.client_of_fd config ~host fd

  let close s =
    Tls_lwt.Unix.close s

end

module ID =
struct
  type t = string
  let compare = Pervasives.compare
end
module IDCallback = Map.Make(ID)

module XMPPClient = XMPP.Make (Lwt) (Xmlstream.XmlStream) (IDCallback)

open XMPPClient

module Version = XEP_version.Make (XMPPClient)

type otr = { mutable state : Otr.State.session }

let message_callback otr t stanza =
  let send = match stanza.content.body with
  | None -> print_endline "received nothing :/" ; []
  | Some v ->
    (* let dump ctx = Sexplib.Sexp.to_string_hum (Otr.State.sexp_of_session ctx) in *)
    (* print_endline (dump otr.state) ; *)
    let ctx, out, user_data = Otr.Engine.handle otr.state v in
    otr.state <- ctx ;
    (* print_endline (dump otr.state) ; *)
    List.iter (function
        | `Warning w                       -> print_endline ("warning: " ^ w)
        | `Received_error e                -> print_endline ("error: " ^ e)
        | `Received e                      -> print_endline ("received unencrypted: " ^ e)
        | `Received_encrypted e            -> print_endline ("received encrypted: " ^ e)
        | `Established_encrypted_session _ -> print_endline "established secure session"
        | `SMP_awaiting_secret             -> print_endline "awaiting SMP secret"
        | `SMP_failure                     -> print_endline "SMP failure"
        | `SMP_received_question q         -> print_endline ("SMP question " ^ q)
        | `SMP_success                     -> print_endline "SMP success" )
      user_data ;
    let send msg =
      let ctx, out, warn = Otr.Engine.send_otr otr.state msg in
      otr.state <- ctx ;
      ( match warn with
        | `Warning w        -> print_endline ("warning while sending " ^ w)
        | `Sent s           -> print_endline ("sending unencrypted " ^ s)
        | `Sent_encrypted s -> print_endline ("sending encrypted " ^ s) ) ;
      match out with
      | Some x -> [ x ]
      | None -> []
    in
    match out with
    | None ->
(*      if List.length (List.filter (function `Established_encrypted_session _ -> true | _ -> false) user_data) > 0 then
        let ctx, Some out, _r = Otr.Engine.start_smp otr.state "bla" in
        otr.state <- ctx ; [out]
        else *)
      ( match List.filter (function `Received_encrypted x -> true | _ -> false) user_data with
        | (`Received_encrypted x)::[] when x = "bla" ->
          []
        | (`Received_encrypted x)::[] when x = "bla2" ->
          let msg1 = send "bla" in
          let msg2 = send "bla" in
          msg1 @ msg2
        | (`Received_encrypted x)::[] when x = "fin" ->
          let ctx, out = Otr.Engine.end_otr otr.state in
          otr.state <- ctx ;
          ( match out with
            | Some x -> [ x ]
            | None -> [ "end_otr didn't want me to send anything" ] )
        | (`Received_encrypted x)::[] ->
          (* let rec s acc = function
            | 0 -> List.rev acc
            | n -> s ((send x)@acc) (pred n)
            in
             s [] (succ (Random.int 2)) *)
          send x
        | _ -> send "nothing to send" )
    | Some c -> [ c ]
  in
  Lwt_list.iter_s (fun out ->
      send_message t ?jid_to:stanza.jid_from
        ?id:stanza.id
        ?kind:stanza.content.message_type
        ?lang:stanza.lang
        ?body:(Some out) ()) send

let message_error t ?id ?jid_from ?jid_to ?lang error =
  print_endline ("message error: " ^ error.err_text);
  return ()
    
let presence_callback t stanza =
  (match stanza.content.presence_type with
    | None -> print_endline "available"
    | Some _ -> print_endline "something"
  ); return ()
  
let presence_error t ?id ?jid_from ?jid_to ?lang error =
  print_endline ("presence error: " ^ error.err_text);
  return ()
    

let session starter t =
  print_endline "in session" ;
  let dsa = Mirage_crypto_pk.Dsa.generate `Fips1024 in
  let config = Otr.State.config [`V2] [`REQUIRE_ENCRYPTION] in
  Printf.printf "my fp" ; Cstruct.hexdump (Cstruct.of_string (Otr.Utils.own_fingerprint dsa)) ;
  let otr = { state = (Otr.State.new_session config dsa ()) } in
  register_iq_request_handler t Version.ns_version
    (fun ev _jid_from _jid_to _lang () ->
      match ev with
        | IQGet _el ->
          let el = Version.encode {Version.name = "xmpptest";
                                   Version.version = "2.0";
                                   Version.os = Sys.os_type} in
            return (IQResult (Some el))
        | IQSet _el ->
          fail BadRequest
    );
  register_stanza_handler t (ns_client, "message")
    (parse_message ~callback:(message_callback otr) ~callback_error:message_error);
  register_stanza_handler t (ns_client, "presence")
    (parse_presence ~callback:presence_callback ~callback_error:presence_error);
  print_endline "sending presence" ;
  send_presence t () >>= fun () ->
  ( match starter with
    | None -> return ()
    | Some x ->
      let ctx, out = Otr.Engine.start_otr otr.state in
      otr.state <- ctx ;
      send_message t ~jid_to:(JID.of_string x) ?body:(Some out) () ) >>= fun () ->
  print_endline "returning" ; return ()

let _ =
  let server = Sys.argv.(1)
  and username = Sys.argv.(2)
  and password = Sys.argv.(3)
  and resource = "xmpp3.0"
  in

  let starter = if Array.length Sys.argv > 4 then Some (Sys.argv.(4)) else None in

  let myjid = JID.make_jid username server resource in
  let inet_addr =
    try Unix.inet_addr_of_string server
    with Failure("inet_addr_of_string") ->
      (Unix.gethostbyname server).Unix.h_addr_list.(0) in
  let sockaddr = Unix.ADDR_INET (inet_addr, 5222) in
    Lwt_main.run (
      PlainSocket.open_connection sockaddr >>= fun socket_data ->
      let module Socket_module = struct type t = PlainSocket.socket
                                        let socket = socket_data
                                        include PlainSocket
      end in
      let make_tls () =
        TLSSocket.switch (PlainSocket.get_fd socket_data) server >>= fun socket_data ->
        let module TLS_module = struct type t = Tls_lwt.Unix.t
                                       let socket = socket_data
                                       include TLSSocket
        end in
          return (module TLS_module : XMPPClient.Socket)
      in
      print_endline "setting up" ;
        XMPPClient.setup_session
          ~user_data:()
          ~myjid
          ~plain_socket:(module Socket_module : XMPPClient.Socket)
          ~tls_socket:make_tls
          ~password (session starter) >>=
          (fun session_data -> XMPPClient.parse session_data >>= fun () ->
            let module S = (val session_data.socket : Socket) in
              S.close S.socket
          )
    )
