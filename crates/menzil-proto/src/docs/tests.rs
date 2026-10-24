use ciborium::Value;

use super::*;

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn int(n: u64) -> Value {
    Value::Integer(n.into())
}

/// A definite length CBOR map with the entries in the given order, duplicates kept.
fn map(entries: Vec<(&str, Value)>) -> Vec<u8> {
    let value = Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect());
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}

fn fetch_entries() -> Vec<(&'static str, Value)> {
    vec![
        ("t", text("fetch")),
        ("v", int(1)),
        ("roster_seq", int(4)),
        ("policy_seq", Value::Null),
        ("base_seq", Value::Null),
    ]
}

fn all_messages() -> Vec<Message> {
    vec![
        Message::Fetch {
            roster_seq: Some(7),
            policy_seq: None,
            base_seq: Some(3),
        },
        Message::Push,
        Message::Doc {
            kind: DocKind::BaseRoster,
            doc: vec![1, 2, 3],
        },
        Message::Doc {
            kind: DocKind::Policy,
            doc: vec![],
        },
        Message::End {
            roster_seq: None,
            policy_seq: Some(9),
        },
        Message::Result {
            roster: Outcome::Adopted,
            policy: Outcome::Rejected,
            code: Some(ErrorCode::BadDocument),
            roster_seq: Some(5),
            policy_seq: None,
        },
    ]
}

#[test]
fn every_message_round_trips_through_a_frame() {
    for message in all_messages() {
        let frame = encode_frame(&message).unwrap();
        let declared = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, frame.len() - FRAME_HEADER_LEN);
        assert_eq!(decode_message(&frame[4..]).unwrap(), message);
    }
}

#[test]
fn the_wire_form_has_the_spec_keys_and_a_byte_string_doc() {
    let frame = encode_frame(&Message::Doc {
        kind: DocKind::BasePolicy,
        doc: vec![0xAA; 3],
    })
    .unwrap();
    let value: Value = ciborium::from_reader(&frame[4..]).unwrap();
    let Value::Map(entries) = value else {
        panic!("a map")
    };
    let get = |k: &str| {
        entries
            .iter()
            .find(|(key, _)| key == &text(k))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(get("t"), Some(text("doc")));
    assert_eq!(get("kind"), Some(text("base_policy")));
    assert_eq!(get("doc"), Some(Value::Bytes(vec![0xAA; 3])));
    assert_eq!(entries.len(), 3);

    let frame = encode_frame(&Message::Push).unwrap();
    let value: Value = ciborium::from_reader(&frame[4..]).unwrap();
    let Value::Map(entries) = value else {
        panic!("a map")
    };
    assert_eq!(entries.len(), 2);
}

#[test]
fn the_length_bound_is_exact() {
    assert_eq!(check_frame_len(0), Ok(0));
    assert_eq!(check_frame_len(MAX_FRAME_LEN as u32), Ok(MAX_FRAME_LEN));
    for over in [MAX_FRAME_LEN as u32 + 1, u32::MAX] {
        assert_eq!(
            check_frame_len(over),
            Err(DocsError::FrameTooLarge {
                len: over as usize,
                max: MAX_FRAME_LEN
            })
        );
    }
    assert_eq!(MAX_FRAME_LEN, 1_049_600);
}

#[test]
fn the_seventh_message_is_refused_and_six_are_admitted() {
    let mut counter = MessageCounter::new();
    for n in 1..=MAX_MESSAGES {
        counter.admit().unwrap();
        assert_eq!(counter.seen(), n);
    }
    assert_eq!(
        counter.admit(),
        Err(DocsError::TooManyMessages { max: MAX_MESSAGES })
    );
    assert_eq!(counter.seen(), MAX_MESSAGES);
    assert_eq!(MAX_MESSAGES, 6);
}

#[test]
fn an_outgoing_frame_over_the_limit_is_refused() {
    // The frame body is the document plus a few bytes of map around it.
    let fits = Message::Doc {
        kind: DocKind::Roster,
        doc: vec![0; crate::MAX_DOC_BYTES],
    };
    assert!(encode_frame(&fits).unwrap().len() <= FRAME_HEADER_LEN + MAX_FRAME_LEN);
    let too_big = Message::Doc {
        kind: DocKind::Roster,
        doc: vec![0; MAX_FRAME_LEN],
    };
    assert!(matches!(
        encode_frame(&too_big),
        Err(DocsError::FrameTooLarge { .. })
    ));
}

#[test]
fn the_deadline_is_thirty_seconds() {
    assert_eq!(STREAM_DEADLINE, Duration::from_secs(30));
}

#[test]
fn a_well_formed_hand_built_fetch_decodes() {
    assert_eq!(
        decode_message(&map(fetch_entries())).unwrap(),
        Message::Fetch {
            roster_seq: Some(4),
            policy_seq: None,
            base_seq: None
        }
    );
}

#[test]
fn an_unknown_key_is_refused_in_every_message() {
    let extra = ("x", int(1));
    let cases: Vec<Vec<(&str, Value)>> = vec![
        fetch_entries(),
        vec![("t", text("push")), ("v", int(1))],
        vec![
            ("t", text("doc")),
            ("kind", text("roster")),
            ("doc", Value::Bytes(vec![1])),
        ],
        vec![
            ("t", text("end")),
            ("roster_seq", Value::Null),
            ("policy_seq", Value::Null),
        ],
        vec![
            ("t", text("result")),
            ("roster", int(0)),
            ("policy", int(0)),
            ("code", Value::Null),
            ("roster_seq", Value::Null),
            ("policy_seq", Value::Null),
        ],
    ];
    for entries in cases {
        // The message without the extra key decodes; with it, it does not.
        decode_message(&map(entries.clone())).unwrap();
        let mut with_extra = entries;
        with_extra.push((extra.0, extra.1.clone()));
        assert!(
            matches!(decode_message(&map(with_extra)), Err(DocsError::Decode(_))),
            "an unknown key must be refused"
        );
    }
}

#[test]
fn a_duplicate_key_is_refused() {
    for key in ["t", "v", "roster_seq", "base_seq"] {
        let mut entries = fetch_entries();
        let original = entries.iter().find(|(k, _)| *k == key).unwrap().clone();
        entries.push(original);
        assert!(
            matches!(decode_message(&map(entries)), Err(DocsError::Decode(_))),
            "duplicate {key} must be refused"
        );
    }
    // A duplicate of the tag with a different value is no way to smuggle another message in.
    let mut entries = fetch_entries();
    entries.push(("t", text("push")));
    assert!(decode_message(&map(entries)).is_err());
}

#[test]
fn a_missing_key_is_refused_even_for_a_nullable_one() {
    for missing in ["v", "roster_seq", "policy_seq", "base_seq", "t"] {
        let entries: Vec<_> = fetch_entries()
            .into_iter()
            .filter(|(k, _)| *k != missing)
            .collect();
        assert!(
            matches!(decode_message(&map(entries)), Err(DocsError::Decode(_))),
            "a fetch without {missing} must be refused"
        );
    }
    // Same for `code` in a result.
    let entries = vec![
        ("t", text("result")),
        ("roster", int(0)),
        ("policy", int(3)),
        ("roster_seq", Value::Null),
        ("policy_seq", Value::Null),
    ];
    assert!(decode_message(&map(entries)).is_err());
}

#[test]
fn a_wrong_version_an_unknown_tag_kind_or_outcome_is_refused() {
    let mut entries = fetch_entries();
    entries[1] = ("v", int(2));
    assert_eq!(decode_message(&map(entries)), Err(DocsError::Version(2)));

    let mut entries = fetch_entries();
    entries[0] = ("t", text("shout"));
    assert!(decode_message(&map(entries)).is_err());

    let entries = vec![
        ("t", text("doc")),
        ("kind", text("steward")),
        ("doc", Value::Bytes(vec![])),
    ];
    assert!(decode_message(&map(entries)).is_err());

    let entries = vec![
        ("t", text("result")),
        ("roster", int(4)),
        ("policy", int(0)),
        ("code", Value::Null),
        ("roster_seq", Value::Null),
        ("policy_seq", Value::Null),
    ];
    assert!(decode_message(&map(entries)).is_err());
}

#[test]
fn a_doc_that_is_not_a_byte_string_is_refused() {
    let entries = vec![
        ("t", text("doc")),
        ("kind", text("roster")),
        ("doc", Value::Array(vec![int(1), int(2)])),
    ];
    assert!(decode_message(&map(entries)).is_err());
    let entries = vec![
        ("t", text("doc")),
        ("kind", text("roster")),
        ("doc", text("abc")),
    ];
    assert!(decode_message(&map(entries)).is_err());
}

#[test]
fn indefinite_lengths_and_trailing_bytes_are_refused() {
    // {_ "t": "push", "v": 1}: an indefinite length map.
    let mut indefinite = vec![0xbf];
    indefinite.extend_from_slice(&[0x61, b't', 0x64, b'p', b'u', b's', b'h']);
    indefinite.extend_from_slice(&[0x61, b'v', 0x01, 0xff]);
    assert!(matches!(
        decode_message(&indefinite),
        Err(DocsError::Decode(_))
    ));
    let definite = map(vec![("t", text("push")), ("v", int(1))]);
    assert_eq!(decode_message(&definite).unwrap(), Message::Push);
    let mut trailing = definite;
    trailing.push(0x00);
    assert!(matches!(
        decode_message(&trailing),
        Err(DocsError::Decode(_))
    ));
}

#[test]
fn outcomes_keep_their_numbers() {
    for (n, outcome) in [
        (0, Outcome::Adopted),
        (1, Outcome::Held),
        (2, Outcome::Rejected),
        (3, Outcome::NotSent),
    ] {
        assert_eq!(outcome.as_u8(), n);
        assert_eq!(Outcome::from_u8(n), Some(outcome));
    }
    assert_eq!(Outcome::from_u8(4), None);
}

#[test]
fn kinds_are_ordered_bases_first() {
    assert!(DocKind::BaseRoster < DocKind::BasePolicy);
    assert!(DocKind::BasePolicy < DocKind::Roster);
    assert!(DocKind::Roster < DocKind::Policy);
}
