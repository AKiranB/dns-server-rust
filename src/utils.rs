use crate::DnsName;
use crate::{DnsAnswer, DnsQuestion};

pub fn read_questions(qdcount: u16, buf: &[u8]) -> (Vec<DnsQuestion>, Vec<usize>) {
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

pub fn build_answers(questions: &Vec<DnsQuestion>, offsets: Vec<usize>) -> Vec<DnsAnswer> {
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

pub fn write_answers(answers: Vec<DnsAnswer>) -> Vec<u8> {
    let mut answer_buf = vec![];
    for answer in answers {
        let answer_bytes = DnsAnswer::to_bytes(&answer);
        answer_buf.extend_from_slice(&answer_bytes);
    }
    answer_buf
}

pub fn write_questions(questions: Vec<DnsQuestion>) -> Vec<u8> {
    let mut question_buf = vec![];
    for question in questions {
        let question_bytes = DnsQuestion::to_bytes(&question);
        question_buf.extend_from_slice(&question_bytes);
    }
    question_buf
}
