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

pub fn write_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.push((v >> 8) as u8);
    buf.push(v as u8);
}

fn encode_qname(labels: &[String], out: &mut Vec<u8>) {
    for label in labels {
        let length = label.len();
        assert!(length <= 63, "label is too long");
        out.push(length as u8);
        out.extend_from_slice(label.as_bytes());
    }
}

impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = [].to_vec();
        let out = Vec::new();

        encode_qname(&self.qname, &result);

        write_u16_be(out, &self.qtype);

        result
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

fn main() {
    println!("Logs from your program will appear here!");

    let addr: &'static str = "127.0.0.1:2053";

    let udp_socket: UdpSocket = UdpSocket::bind(addr).expect("Failed to bind to address");
    let mut buf: [u8; 512] = [0; 512];

    let header: DnsHeader = DnsHeader {
        id: 1234,
        qr: true,
        opcode: 0,
        aa: false,
        tc: false,
        rd: false,
        ra: false,
        rcode: 0,
        question_no: 0,
        answer_no: 0,
        authority_no: 0,
        additionals_no: 0,
    };

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((number_of_bytes, source_address)) => {
                println!("Received {} bytes from {}", number_of_bytes, source_address);
                let response: [u8; 12] = DnsHeader::to_bytes(&header);
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
