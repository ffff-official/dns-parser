use Error;
use byteorder::{BigEndian, ByteOrder};

use crate::Name;

#[derive(Debug, Clone)]
pub struct Record<'a> {
    pub priority: u16,
    pub name: Name<'a>,
    pub params: Vec<SvcParam>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SvcParam {
    pub key: u16,
    pub value: Vec<u8>,
}

impl<'a> super::Record<'a> for Record<'a> {
    const TYPE: isize = 65;

    fn parse(rdata: &'a [u8], original: &'a [u8]) -> super::RDataResult<'a> {
        if rdata.len() < 3 {
            return Err(Error::WrongRdataLength);
        }

        let priority = BigEndian::read_u16(&rdata[0..2]);

        let mut offset = 2;
        let name = Name::scan(&rdata[2..], original)?;
        offset += name.byte_len();

        let mut params = Vec::new();

        while offset + 4 <= rdata.len() {
            let key = BigEndian::read_u16(&rdata[offset..offset + 2]);
            let length = BigEndian::read_u16(&rdata[offset + 2..offset + 4]) as usize;
            offset += 4;

            if offset + length > rdata.len() {
                return Err(Error::WrongRdataLength);
            }

            let value = rdata[offset..offset + length].to_vec();
            params.push(SvcParam { key, value });

            offset += length;
        }

        Ok(super::RData::SVC(Record {
            priority,
            name,
            params,
        }))
    }
}