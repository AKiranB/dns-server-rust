use anyhow::Error;
use std::net::UdpSocket;
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
                end_after_pointer = ptr + 1;
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
}

fn read_questions(qdcount: u16, buf: &[u8]) -> (Vec<DnsQuestion>, Vec<usize>) {
    let mut q: Vec<DnsQuestion> = vec![];
    let mut start_byte: usize = 12;
    let mut offsets: Vec<usize> = vec![];

    for _ in 0..qdcount as usize {
        let (question, offset) = DnsQuestion::from_bytes(&buf, start_byte);
        let question = DnsQuestion {
            qname: question.qname,
            qclass: question.qclass,
            qtype: question.qtype,
        };

        q.push(question);
        offsets.push(start_byte);
        start_byte = offset;
    }

    (q, offsets)
}

fn build_answers(questions: &Vec<DnsQuestion>, offsets: Vec<usize>) -> Vec<DnsAnswer> {
    let mut a = vec![];
    for (i, question) in questions.iter().enumerate() {
        let answer = DnsAnswer {
            name: DnsName::Ptr(offsets[i] as u16),
            r_type: question.qtype,
            class: question.qclass,
            time_to_live: 60,
            length: 4,
            data: 8888,
        };
        a.push(answer);
    }
    a
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

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((number_of_bytes, source_address)) => {
                println!("Received {} bytes from {}", number_of_bytes, source_address);

                let read_values_from_header = DnsHeader::from_bytes(&buf).unwrap();

                println!("values from header {:?}", read_values_from_header);

                let read_values_from_question_section_one: (DnsQuestion, usize) =
                    DnsQuestion::from_bytes(&buf, 12);
                let mut read_values_from_question_section_two: Option<DnsQuestion> = None;

                let (questions, offsets) = read_questions(qdcount, &buf);
                let answers = build_answers(&questions, offsets);

                let header = DnsHeader {
                    id: read_values_from_header.0,
                    // we can always assume we are responding
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

                let name = read_values_from_question_section_one.0.qname;

                let question = DnsQuestion {
                    qname: name,
                    qclass: read_values_from_question_section_one.0.qclass,
                    qtype: read_values_from_question_section_one.0.qtype,
                };

                let answer = DnsAnswer {
                    // This is a pointer back to the byte where name is
                    name: DnsName::Ptr(12),
                    r_type: 1,
                    class: 1,
                    time_to_live: 60,
                    length: 4,
                    data: 8888,
                };

                let header = DnsHeader::to_bytes(&header);
                let question = DnsQuestion::to_bytes(&question);

                let mut response: Vec<u8> = vec![];

                response.extend_from_slice(&header);
                response.extend_from_slice(&question);

                let answer = DnsAnswer::to_bytes(&answer);
                let mut answer2: Option<Vec<u8>> = None;

                if let Some(ref q2) = read_values_from_question_section_two {
                    let question_2 = DnsQuestion {
                        qname: q2.qname.clone(),
                        qclass: q2.qclass,
                        qtype: q2.qtype,
                    };
                    let question_2_bytes = DnsQuestion::to_bytes(&question_2);
                    response.extend_from_slice(&question_2_bytes);

                    let answer_2 = DnsAnswer {
                        // And this is a pointer back to where
                        name: DnsName::Ptr(current_byte_offset as u16),
                        r_type: 1,
                        class: 1,
                        time_to_live: 60,
                        length: 4,
                        data: 8888,
                    };
                    answer2 = Some(DnsAnswer::to_bytes(&answer_2));
                }

                response.extend_from_slice(&answer);
                if let Some(answer_2_vec) = answer2 {
                    response.extend_from_slice(&answer_2_vec);
                }

                println!("{:?}", response);

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
