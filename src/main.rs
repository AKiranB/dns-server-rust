use anyhow::Error;
use std::{env, net::UdpSocket};
mod answer_section;
mod utils;
pub struct DnsHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: bool,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

pub struct DnsQuestion {
    qname: DnsName,
    qtype: u16,
    qclass: u16,
}

pub struct DnsAnswer {
    name: DnsName,
    r_type: u16,
    class: u16,
    time_to_live: u32,
    length: u16,
    data: u32,
}
#[derive(Clone, Debug)]
enum DnsName {
    Ptr(u16),
    Label(Vec<String>),
}

pub fn write_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.push((v >> 8) as u8);
    buf.push(v as u8);
}

pub fn write_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.push((v >> 24) as u8);
    buf.push((v >> 16) as u8);
    buf.push((v >> 8) as u8);
    buf.push((v) as u8);
}

fn encode_qname(labels: &[String], buf: &mut Vec<u8>) {
    for label in labels {
        let length = label.len();
        assert!(length <= 63, "label is too long");

        buf.push(length as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn write_name(name: &DnsName, buf: &mut Vec<u8>) {
    match name {
        DnsName::Label(labels) => encode_qname(&labels, buf),
        DnsName::Ptr(off) => {
            let hi = 0xC0 | (((off >> 8) & 0x3F) as u8);
            let lo = (off & 0xFF) as u8;
            buf.push(hi);
            buf.push(lo);
        }
    }
}

fn read_name(buf: &[u8], start: usize) -> (Vec<String>, usize) {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut end_after_pointer = 0usize;
    let mut has_jumped = false;

    loop {
        let len = buf[offset];
        if len & 0xC0 == 0xC0 {
            let byte_two = buf[offset + 1];
            let ptr = (((len as u16 & 0x3F) << 8) | byte_two as u16) as usize;
            if !has_jumped {
                end_after_pointer = offset + 2;
                has_jumped = true;
            }
            offset = ptr;
            continue;
        }

        if len == 0 {
            // This denotes he end of QNAME
            offset += 1;
            break;
        }

        offset += 1;
        let label_bytes = &buf[offset..offset + len as usize];
        let label = String::from_utf8_lossy(label_bytes).to_string();
        labels.push(label);
        offset += len as usize;
    }

    let total_bytes_consumed = if has_jumped {
        end_after_pointer
    } else {
        offset
    };
    return (labels, total_bytes_consumed);
}

impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        write_name(&self.qname, &mut buf);

        write_u16_be(&mut buf, self.qtype);
        write_u16_be(&mut buf, self.qclass);

        buf
    }

    pub fn from_bytes(buf: &[u8], start: usize) -> (Self, usize) {
        let (labels, total_bytes_consumed) = read_name(buf, start);
        let mut offset = total_bytes_consumed;
        let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);

        offset += 2;

        let qclass = u16::from_be_bytes([buf[offset], buf[offset + 1]]);

        offset += 2;

        let question = DnsQuestion {
            qname: DnsName::Label(labels),
            qtype: qtype,
            qclass: qclass,
        };

        return (question, offset);
    }
}

impl DnsHeader {
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];

        out[0..2].copy_from_slice(&self.id.to_be_bytes());

        let flags: u16 = ((self.qr as u16) << 15)
            | ((self.opcode as u16) << 11)
            | ((self.aa as u16) << 10)
            | ((self.tc as u16) << 9)
            | ((self.rd as u16) << 8)
            | ((self.ra as u16) << 7)
            | (((self.z as u16) & 0x7) << 4)
            | ((self.rcode as u16) & 0xF);

        out[2..4].copy_from_slice(&flags.to_be_bytes());

        out[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        out[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        out[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        out[10..12].copy_from_slice(&self.arcount.to_be_bytes());

        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(u16, bool, u8, bool, u8, u16, u16), Error> {
        assert!(
            bytes.len() >= 12,
            "DNS header must be at least 12 bytes long"
        );

        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);

        print!("Flags: {:016b}\n", flags);

        let qr = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let rd = (flags & 0x0100) != 0;
        let rcode = if opcode == 0 { 0 } else { 4 };

        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);

        return Ok((id, qr, opcode, rd, rcode, qdcount, ancount));
    }
}

impl DnsAnswer {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        write_name(&self.name, &mut buf);

        write_u16_be(&mut buf, self.r_type);
        write_u16_be(&mut buf, self.class);

        write_u32_be(&mut buf, self.time_to_live);
        write_u16_be(&mut buf, self.length);

        write_u32_be(&mut buf, self.data);

        buf
    }

    pub fn from_bytes(buf: &[u8], start: usize) -> (Self, usize) {
        let (name, total_bytes_consumed) = read_name(buf, start);
        let mut consumed = total_bytes_consumed;
        let r_type = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]);
        consumed += 2;
        let class = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]);
        consumed += 2;
        let time_to_live = u32::from_be_bytes([
            buf[consumed],
            buf[consumed + 1],
            buf[consumed + 2],
            buf[consumed + 3],
        ]);
        consumed += 4;
        let length = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]);
        consumed += 2;

        let data = u32::from_be_bytes([
            buf[consumed],
            buf[consumed + 1],
            buf[consumed + 2],
            buf[consumed + 3],
        ]);

        consumed += 4;

        let answer = DnsAnswer {
            name: DnsName::Label(name),
            r_type: r_type,
            class: class,
            time_to_live,
            length,
            data,
        };

        return (answer, consumed);
    }

    pub fn parse_upstream(buf: &[u8]) -> Vec<DnsAnswer> {
        let read_values_from_forward_server_header = DnsHeader::from_bytes(&buf).unwrap();
        let ancount = read_values_from_forward_server_header.6;
        let qdcount = read_values_from_forward_server_header.5;
        let (_, offsets) = read_questions(qdcount, &buf);
        let mut upstream_answers = vec![];
        let mut offset;

        if let Some(last) = offsets.last() {
            offset = *last;
        } else {
            offset = 0
        }
        for _ in 0..ancount as usize {
            let (answer, consumed) = DnsAnswer::from_bytes(&buf, offset);
            upstream_answers.push(answer);
            offset = consumed;
        }
        return upstream_answers;
    }
}

fn read_questions(qdcount: u16, buf: &[u8]) -> (Vec<DnsQuestion>, Vec<usize>) {
    let mut q: Vec<DnsQuestion> = vec![];
    let mut start_byte: usize = 12;
    let mut offsets: Vec<usize> = vec![];

    for _ in 0..qdcount as usize {
        let (question, offset) = DnsQuestion::from_bytes(&buf, start_byte);
        q.push(question);
        offsets.push(offset);
        start_byte = offset;
    }

    (q, offsets)
}

fn build_answers(
    questions: &Vec<DnsQuestion>,
    offsets: Vec<usize>,
    is_resolver: bool,
    forwarding_address: &String,
    id: u16,
    opcode: u8,
    rd: bool,
) -> Vec<DnsAnswer> {
    let mut answers = vec![];
    for (i, question) in questions.iter().enumerate() {
        if is_resolver {
            let connection = UdpSocket::bind("0.0.0.0:0").unwrap();
            let mut buf: [u8; 512] = [0; 512];

            // let (amt, src) = connection.recv_from(&mut buf);
        } else {
            let answer = DnsAnswer {
                name: DnsName::Ptr(offsets[i] as u16),
                r_type: question.qtype,
                class: question.qclass,
                time_to_live: 60,
                length: 4,
                data: 8888,
            };
            answers.push(answer);
        }
    }
    answers
}

fn write_answers(answers: Vec<DnsAnswer>) -> Vec<u8> {
    let mut answer_buf = vec![];
    for answer in answers {
        let answer_bytes = DnsAnswer::to_bytes(&answer);
        answer_buf.extend_from_slice(&answer_bytes);
    }
    answer_buf
}

fn write_questions(questions: Vec<DnsQuestion>) -> Vec<u8> {
    let mut question_buf = vec![];
    for question in questions {
        let question_bytes = DnsQuestion::to_bytes(&question);
        question_buf.extend_from_slice(&question_bytes);
    }
    question_buf
}

fn main() {
    let addr: &'static str = "127.0.0.1:2053";
    let udp_socket: UdpSocket = UdpSocket::bind(addr).expect("Failed to bind to address");
    let mut buf: [u8; 512] = [0; 512];

    let args: Vec<String> = env::args().collect();

    let mut resolver = None;
    let mut address = None;
    if args[1] == "--resolver" {
        resolver = Some(&args[1]);
        address = Some(&args[2]);
    }

    let is_it_a_resolver = resolver.is_some();
    print!("{}", is_it_a_resolver);
    }

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((number_of_bytes, source_address)) => {
                println!("Received {} bytes from {}", number_of_bytes, source_address);

                let mut response: Vec<u8> = vec![];
                let read_values_from_header = DnsHeader::from_bytes(&buf).unwrap();
                let qdcount = read_values_from_header.5;

                let (questions, offsets) = read_questions(qdcount, &buf);
                let answers = build_answers(&questions, offsets, resolver.is_some());

                let header = DnsHeader {
                    id: read_values_from_header.0,
                    qr: true,
                    opcode: read_values_from_header.2,
                    aa: false,
                    tc: false,
                    rd: read_values_from_header.3,
                    ra: false,
                    z: false,
                    rcode: read_values_from_header.4,
                    qdcount,
                    ancount: answers.len() as u16,
                    nscount: 0,
                    arcount: 0,
                };

                let header = DnsHeader::to_bytes(&header);

                response.extend_from_slice(&header);
                response.extend_from_slice(&write_questions(questions));
                response.extend_from_slice(&write_answers(answers));
                udp_socket
                    .send_to(&response, source_address)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
