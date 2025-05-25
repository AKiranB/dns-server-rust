use std::net::UdpSocket;
pub struct DnsHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    rcode: u8,
    question_no: u16,
    answer_no: u16,
    authority_no: u16,
    additionals_no: u16,
}

pub struct DnsQuestion {
    qname: Vec<String>,
    qtype: u16,
    qclass: u16,
}

pub struct DnsAnswer {
    name: Vec<String>,
    r_type: u16,
    class: u16,
    time_to_live: u32,
    length: u16,
    data: u32,
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

impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        encode_qname(&self.qname, &mut buf);

        write_u16_be(&mut buf, self.qtype);
        write_u16_be(&mut buf, self.qclass);

        buf
    }
}

impl DnsHeader {
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut result: [u8; 12] = [0; 12];
        result[0] = (self.id >> 8) as u8;
        result[1] = self.id as u8;

        result[2] = (self.qr as u8) << 7
            | self.opcode << 3
            | (self.aa as u8) << 2
            | (self.tc as u8) << 1
            | self.rd as u8;

        result[3] = (self.ra as u8) << 7 | self.rcode;

        result[4] = (self.question_no >> 8) as u8;
        result[5] = self.question_no as u8;

        result[6] = (self.answer_no >> 8) as u8;
        result[7] = self.answer_no as u8;

        result[8] = (self.authority_no >> 8) as u8;
        result[9] = self.authority_no as u8;

        result[10] = (self.additionals_no >> 8) as u8;
        result[11] = self.additionals_no as u8;

        result
    }
}

impl DnsAnswer {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        encode_qname(&self.name, &mut buf);

        write_u16_be(&mut buf, self.class);
        write_u16_be(&mut buf, self.r_type);

        write_u32_be(&mut buf, self.time_to_live);
        write_u16_be(&mut buf, self.length);

        write_u32_be(&mut buf, self.data);

        buf
    }
}

fn main() {
    println!("Logs from your program will appear here!");

    let addr: &'static str = "127.0.0.1:2053";

    let udp_socket: UdpSocket = UdpSocket::bind(addr).expect("Failed to bind to address");
    let mut buf: [u8; 512] = [0; 512];

    let header = DnsHeader {
        id: 1234,
        qr: true,
        opcode: 0,
        aa: false,
        tc: false,
        rd: false,
        ra: false,
        rcode: 0,
        question_no: 1,
        answer_no: 1,
        authority_no: 0,
        additionals_no: 0,
    };

    let question = DnsQuestion {
        qname: vec!["codecrafters".into(), "io".into()],
        qtype: 1,
        qclass: 1,
    };

    let answer = DnsAnswer {
        name: vec!["codecrafters".into(), "io".into()],
        r_type: 1,
        class: 1,
        time_to_live: 60,
        length: 4,
        data: 8888,
    };

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((number_of_bytes, source_address)) => {
                println!("Received {} bytes from {}", number_of_bytes, source_address);

                let header = DnsHeader::to_bytes(&header);
                let question = DnsQuestion::to_bytes(&question);
                let answer = DnsAnswer::to_bytes(&answer);
                let mut response: Vec<u8> = vec![];

                response.extend_from_slice(&header);
                response.extend_from_slice(&question);
                response.extend_from_slice(&answer);

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
