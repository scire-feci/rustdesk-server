//! Server side of the client's `secure_tcp` handshake on the rendezvous TCP connection.
//!
//! hbbs opens with a KeyExchange carrying a fresh X25519 public key signed with the server
//! key. A client that wants encryption (one logged in to an API account, or signalling
//! WebRTC) answers with its own public key and a session key sealed to ours; both sides then
//! run `Encrypt::new(key)`. KeyExchange carries no version here, so clients pick version 0.
//! Clients that do not answer keep talking in the clear: they already skip the offer.
use hbb_common::{
    anyhow::anyhow,
    bytes::Bytes,
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox::Key, sign},
    tcp::Encrypt,
    ResultType,
};

/// The opening message, and the ephemeral secret key needed to read the client's answer.
pub(crate) fn offer(server_sk: &sign::SecretKey) -> (RendezvousMessage, box_::SecretKey) {
    let (pk, sk) = box_::gen_keypair();
    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(KeyExchange {
        keys: vec![Bytes::from(sign::sign(&pk.0, server_sk))],
        ..Default::default()
    });
    (msg, sk)
}

/// `None` when `bytes` is not the client's answer; otherwise the session key it carries.
pub(crate) fn accept(bytes: &[u8], our_sk: &box_::SecretKey) -> Option<ResultType<Key>> {
    let msg = RendezvousMessage::parse_from_bytes(bytes).ok()?;
    let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
        return None;
    };
    if ex.keys.len() != 2 {
        return Some(Err(anyhow!("key exchange answer carries {} keys", ex.keys.len())));
    }
    Some(Encrypt::decode(&ex.keys[1], &ex.keys[0], our_sk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::{bytes::BytesMut, protobuf::Message as _, sodiumoxide::crypto::secretbox};

    // The client's half, as rustdesk's `secure_tcp` and `create_symmetric_key_msg` do it.
    fn client_answer(offer: &RendezvousMessage, server_pk: &sign::PublicKey) -> (Vec<u8>, Key) {
        let Some(rendezvous_message::Union::KeyExchange(ex)) = offer.union.clone() else {
            panic!("offer is not a key exchange");
        };
        assert_eq!(ex.keys.len(), 1);
        let their_pk = sign::verify(&ex.keys[0], server_pk).expect("offer signed by server key");
        let their_pk = box_::PublicKey(their_pk.try_into().expect("32-byte public key"));
        let (our_pk, our_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let sealed = box_::seal(&key.0, &nonce, &their_pk, &our_sk);
        let mut msg = RendezvousMessage::new();
        msg.set_key_exchange(KeyExchange {
            keys: vec![Bytes::from(our_pk.0.to_vec()), Bytes::from(sealed)],
            ..Default::default()
        });
        (msg.write_to_bytes().unwrap(), key)
    }

    #[test]
    fn handshake_matches_the_client() {
        let (server_pk, server_sk) = sign::gen_keypair();
        let (offer_msg, our_sk) = offer(&server_sk);
        let (answer, client_key) = client_answer(&offer_msg, &server_pk);
        let key = accept(&answer, &our_sk).expect("answer recognised").expect("key decoded");
        assert_eq!(key.0, client_key.0);

        // Each end runs its own Encrypt::new(key), exactly like the client's version 0.
        let mut client = Encrypt::new(client_key);
        let mut server = Encrypt::new(key);
        for _ in 0..3 {
            let mut wire = BytesMut::from(&client.enc(b"punch hole request")[..]);
            server.dec(&mut wire).unwrap();
            assert_eq!(&wire[..], b"punch hole request");
            let mut wire = BytesMut::from(&server.enc(b"punch hole response")[..]);
            client.dec(&mut wire).unwrap();
            assert_eq!(&wire[..], b"punch hole response");
        }
    }

    #[test]
    fn other_messages_and_bad_answers() {
        let (_, server_sk) = sign::gen_keypair();
        let (_, our_sk) = offer(&server_sk);

        let mut plaintext = RendezvousMessage::new();
        plaintext.set_test_nat_request(TestNatRequest::default());
        assert!(accept(&plaintext.write_to_bytes().unwrap(), &our_sk).is_none());
        assert!(accept(b"\xff\xfe not a rendezvous message", &our_sk).is_none());

        let mut garbage = RendezvousMessage::new();
        garbage.set_key_exchange(KeyExchange {
            keys: vec![Bytes::from(vec![7u8; 32]), Bytes::from(vec![7u8; 48])],
            ..Default::default()
        });
        assert!(accept(&garbage.write_to_bytes().unwrap(), &our_sk).unwrap().is_err());

        let mut one_key = RendezvousMessage::new();
        one_key.set_key_exchange(KeyExchange {
            keys: vec![Bytes::from(vec![7u8; 32])],
            ..Default::default()
        });
        assert!(accept(&one_key.write_to_bytes().unwrap(), &our_sk).unwrap().is_err());
    }
}
