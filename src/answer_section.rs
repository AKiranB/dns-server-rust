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

#[test]
fn test_dns_answer_parse_upstream() {
    let buf: [u8; 61] = [
        // ---------- Header (12 bytes) ----------
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1, NOERROR
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x02, // ANCOUNT = 2   <-- two answers
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // ---------- Question (example.com A IN) ----------
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
        0x03, b'c', b'o', b'm', // "com"
        0x00, // end of name
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
        // ---------- Answer #1 ----------
        // Startig byte is 29 here
        0xC0, 0x0C, // NAME = pointer to offset 12 (example.com)
        0x00, 0x01, // TYPE = A
        0x00, 0x01, // CLASS = IN
        0x00, 0x00, 0x01, 0x2C, // TTL = 300
        0x00, 0x04, // RDLENGTH = 4
        0x7F, 0x00, 0x00, 0x01, // RDATA = 127.0.0.1
        // ---------- Answer #2 ----------
        0xC0, 0x0C, // NAME = pointer to example.com again
        0x00, 0x01, // TYPE = A
        0x00, 0x01, // CLASS = IN
        0x00, 0x00, 0x01, 0x2C, // TTL = 300
        0x00, 0x04, // RDLENGTH = 4
        0x5D, 0xB8, 0xD8, 0x22, // RDATA = 93.184.216.34
    ];

    let answers = DnsAnswer::parse_upstream(&buf);

    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0].r_type, 1);
    assert_eq!(answers[0].class, 1);
    assert_eq!(answers[0].time_to_live, 300);
    assert_eq!(answers[0].length, 4);
    assert_eq!(answers[0].data, u32::from_be_bytes([127, 0, 0, 1]));
    assert_eq!(answers[1].data, u32::from_be_bytes([93, 184, 216, 34]));
}
