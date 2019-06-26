(*
 * (c) 2004-2012 Anastasia Gornostaeva
 *)

module Make (X : XMPP.S) =
struct
  open Xml
  open JID
  open X

  let ns_roster = Some "jabber:iq:roster"

  type ask_t =
    | AskSubscribe

  type subscription_t =
    | SubscriptionNone
    | SubscriptionBoth
    | SubscriptionFrom
    | SubscriptionRemove
    | SubscriptionTo

  type item = {
    group : string list;
    approved : bool;
    ask : ask_t option;
    jid : JID.t;
    name : string;
    subscription : subscription_t;
  }

  let decode attrs els =
    let ver =
      try Some (get_attr_value "ver" attrs)
      with Not_found -> None in
    let items =
      List.fold_left (fun acc -> function
          | Xmlelement ((ns_roster, "item"), attrs, els) ->
          let item =
            List.fold_left (fun item -> function
              | ((None, "approved"), value) ->
                if value = "true" then
                  {item with approved = true}
                else
                  item
              | ((None, "ask"), value) ->
                if value = "subscribe" then
                  {item with ask = Some AskSubscribe}
                else
                  item
              | ((None, "jid"), value) ->
                (* TODO validity and verify *)
                let jid = try JID.of_string value with _ -> item.jid in
                { item with jid }
              | ((None, "name"), value) ->
                {item with name = value}
              | ((None, "subscription"), value) ->
                let value =
                  match value with
                    | "none" -> SubscriptionNone
                    | "both" -> SubscriptionBoth
                    | "from" -> SubscriptionFrom
                    | "to" -> SubscriptionTo
                    | "remove" -> SubscriptionRemove
                    | _ -> SubscriptionNone
                in
                  {item with subscription = value}
              | _ -> item
            ) {group = [];
               approved = false;
               ask = None;
               jid = {
                 node = "";
                 lnode = "";
                 domain = "";
                 ldomain = "";
                 resource = "";
                 lresource = ""
               };
               name = "";
               subscription = SubscriptionNone
              } attrs in
          let item =
            List.fold_left (fun item -> function
              | Xmlelement ((ns_roster, "group"), _, _) as el ->
                let group = get_cdata el in
                  {item with group = group :: item.group}
              | _ -> item
            ) item els in
            if item.jid.node = "" || item.jid.domain = "" then
              acc
            else
              item :: acc
          | Xmlelement ((_,x), _ , _) ->
            invalid_arg (Printf.sprintf "Xmlelement expected 'item' got: %S" x)
        | Xmlcdata _ -> acc
        ) [] els in
    (ver, List.rev items)

  let ignore v = ignore v; return ()

  let get xmpp ?jid_from ?jid_to ?lang ?(error_callback=ignore) callback =
    let callback ev jid_from jid_to lang () =
      match ev with
      | IQResult el -> (
          match el with
          | Some (Xmlelement ((ns_roster, "query"), attrs, els)) ->
            let ver, items = decode attrs els in
            callback ?jid_from ?jid_to ?lang ?ver items
          | _ ->
            callback ?jid_from ?jid_to ?lang ?ver:None []
        )
      | IQError err ->
        error_callback err
    in
    make_iq_request xmpp ?jid_from ?jid_to ?lang
      (IQGet (make_element (ns_roster, "query") [] []))
      callback

  let put xmpp jid ?remove ?name ?groups ?jid_from ?jid_to ?lang ?(error_callback=ignore) callback =
    let callback ev jid_from jid_to lang () =
      match ev with
      | IQResult el ->
        callback ?jid_from ?jid_to ?lang el
      | IQError err ->
        error_callback err
    in
    let attr = [make_attr "jid" jid] in
    let attr, groupelem =
      let group gs = List.map (fun e ->
          make_element (no_ns, "group") [] [e])
          gs
      in
      match remove, name, groups with
      | Some _, _, _ -> (make_attr "subscription" "remove" :: attr, [])
      | None, Some x, None -> (make_attr "name" x :: attr, [])
      | None, Some x, Some y -> (make_attr "name" x :: attr, group y)
      | None, None, Some y -> (attr, group y)
      | None, None, None -> assert false
    in
    make_iq_request xmpp ?jid_from ?jid_to ?lang
      (IQSet (make_element (ns_roster, "query") []
                [make_element (no_ns, "item") attr groupelem]))
      callback

end
