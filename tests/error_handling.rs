use sflow_parser::*;

#[test]
fn test_truncated_header() {
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&[0, 0, 0]);
    assert!(result.error.is_some());
    assert!(matches!(
        result.error.unwrap(),
        SflowError::Incomplete { .. }
    ));
}

#[test]
fn test_wrong_version() {
    let mut data = Vec::new();
    data.extend_from_slice(&4u32.to_be_bytes()); // version 4
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&[10, 0, 0, 1]);
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&100u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());

    let parser = SflowParser::default();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_some());
    match result.error.unwrap() {
        SflowError::UnsupportedVersion { version } => {
            assert_eq!(version, 4)
        }
        other => panic!("Expected UnsupportedVersion, got {:?}", other),
    }
}

#[test]
fn test_max_samples_exceeded() {
    // Datagram claiming 100 samples
    let mut data = Vec::new();
    data.extend_from_slice(&5u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&[10, 0, 0, 1]);
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&100u32.to_be_bytes());
    data.extend_from_slice(&100u32.to_be_bytes()); // 100 samples

    // Provide 100 minimal flow samples (each: 8 header + 32 body)
    for _ in 0..100 {
        let df = (0u32 << 12) | 1;
        data.extend_from_slice(&df.to_be_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // seq
        body.extend_from_slice(&0u32.to_be_bytes()); // source_id
        body.extend_from_slice(&1u32.to_be_bytes()); // rate
        body.extend_from_slice(&0u32.to_be_bytes()); // pool
        body.extend_from_slice(&0u32.to_be_bytes()); // drops
        body.extend_from_slice(&0u32.to_be_bytes()); // input
        body.extend_from_slice(&0u32.to_be_bytes()); // output
        body.extend_from_slice(&0u32.to_be_bytes()); // num_records
        data.extend_from_slice(&(body.len() as u32).to_be_bytes());
        data.extend_from_slice(&body);
    }

    let parser = SflowParser::builder().with_max_samples(10).build();
    let result = parser.parse_bytes(&data);
    assert!(result.error.is_some());
    match result.error.unwrap() {
        SflowError::TooManySamples { count, max } => {
            assert_eq!(count, 100);
            assert_eq!(max, 10);
        }
        other => panic!("Expected TooManySamples, got {:?}", other),
    }
}

#[test]
fn test_error_display_messages() {
    let err = SflowError::UnsupportedVersion { version: 3 };
    let msg = format!("{}", err);
    assert!(msg.contains("3"));
    assert!(msg.contains("5"));

    let err = SflowError::Incomplete {
        available: 2,
        context: "header".to_string(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("2"));

    let err = SflowError::TooManySamples { count: 50, max: 10 };
    let msg = format!("{}", err);
    assert!(msg.contains("50"));
    assert!(msg.contains("10"));
}

#[test]
fn test_empty_input() {
    let parser = SflowParser::default();
    let result = parser.parse_bytes(&[]);
    assert!(result.error.is_none());
    assert!(result.datagrams.is_empty());
}
