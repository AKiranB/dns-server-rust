use crate::{DnsAnswer, DnsName};

#[test]
fn test_dns_answer_from_bytes() {
    let buf: [u8; 27] = [
        // NAME: "example.com."
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x01, // TTL: 300
        0x00, 0x00, 0x01, 0x2C, // RDLENGTH: 4
        0x00, 0x04, // RDATA: 127.0.0.1
        0x7F, 0x00, 0x00, 0x01,
    ];
    let (answer, offset) = DnsAnswer::from_bytes(&buf, 0);
    match answer.name {
        DnsName::Label(ref labels) => {
            assert_eq!(labels, &vec!["example".to_string(), "com".to_string()]);
        }
        _ => panic!("expected label name"),
    }
    assert_eq!(answer.r_type, 1);
    assert_eq!(answer.class, 1);
    assert_eq!(answer.time_to_live, 300);
    assert_eq!(answer.length, 4);
    assert_eq!(answer.data, u32::from_be_bytes([127, 0, 0, 1]));
    assert_eq!(offset, 27);
}
