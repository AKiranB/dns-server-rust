use std::net::UdpSocket;

use anyhow::Error;
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

        result[4] = (self.z as u8) << 7 | (self.qdcount >> 8) as u8;
        result[5] = self.qdcount as u8;

        result[6] = (self.ancount >> 8) as u8;
        result[7] = self.ancount as u8;

        result[8] = (self.nscount >> 8) as u8;
        result[9] = self.nscount as u8;

        result[10] = (self.arcount >> 8) as u8;
        result[11] = self.arcount as u8;

        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DnsHeader, Error> {
        assert!(
            bytes.len() >= 12,
            "DNS header must be at least 12 bytes long"
        );

        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);

        let qr = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let aa = (flags & 0x0400) != 0;
        let tc = (flags & 0x0200) != 0;
        let rd = (flags & 0x0100) != 0;
        let z = (flags & 0x0040) != 0;
        let ra = (flags & 0x0080) != 0;
        let rcode = (flags & 0x000F) as u8;

        return Ok(Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            z,
            ra,
            ancount,
            rcode,
            arcount,
            nscount,
            qdcount,
        });
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
        z: false,
        rcode: 0,
        qdcount: 1,
        ancount: 1,
        nscount: 0,
        arcount: 0,
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
