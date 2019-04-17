use std::io::{Cursor, Error, ErrorKind};

use std::fmt;
use std::io;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

pub const DEFAULT_CART_TIMING: u32 = 0x80371240;
pub const DEFAULT_CLOCK_RATE: u32  = 0x0000000f;

pub const HEADER_NAME_LEN: usize = 20;

pub const HEADER_START: usize = 0;
pub const HEADER_LEN: u64 = 64;
pub const HEADER_END: usize = HEADER_START + (HEADER_LEN as usize);

pub const BOOTCODE_START: usize = HEADER_LEN as usize;
pub const BOOTCODE_LEN: u64 = 4096 - HEADER_LEN;
pub const BOOTCODE_END: usize = BOOTCODE_START + (BOOTCODE_LEN as usize);

pub const LOAD_START: usize = (HEADER_LEN + BOOTCODE_LEN) as usize;
pub const LOAD_LEN: u64 = 0x100000;

pub const ROM_LEN: usize = (HEADER_LEN + BOOTCODE_LEN + LOAD_LEN) as usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ByteSwapping {
    Native,
    U16LittleEndian,
}

impl fmt::Display for ByteSwapping {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ByteSwapping::Native          => write!(f, "Native"),
            ByteSwapping::U16LittleEndian => write!(f, "U16 Little Endian"),
        }
    }
}

#[repr(C)]
pub struct RomHeader {
	pub cart_timing: u32,
	pub clock_rate: u32,
	pub load_addr: u32,
	pub release: u32,
	pub crc1: u32,
	pub crc2: u32,
	pub rsvd_18: u32,
	pub rsvd_1c: u32,
	pub name: [u8; HEADER_NAME_LEN],
	pub rsvd_34: u32,
	pub manuf_id: u32,
	pub cart_id: u16,
	pub country_code: u16,
}

impl RomHeader {
    pub fn new() -> RomHeader {
        Default::default()
    }

	pub fn serialize(&self, writer: &mut std::io::Write) -> io::Result<()> {
		writer.write_u32::<BigEndian>(self.cart_timing)?;
		writer.write_u32::<BigEndian>(self.clock_rate)?;
		writer.write_u32::<BigEndian>(self.load_addr)?;
		writer.write_u32::<BigEndian>(self.release)?;
		writer.write_u32::<BigEndian>(self.crc1)?;
		writer.write_u32::<BigEndian>(self.crc2)?;
		writer.write_u32::<BigEndian>(self.rsvd_18)?;
		writer.write_u32::<BigEndian>(self.rsvd_1c)?;
		for name_char in self.name.iter() {
			writer.write_u8(*name_char)?;
		}
		writer.write_u32::<BigEndian>(self.rsvd_34)?;
		writer.write_u32::<BigEndian>(self.manuf_id)?;
		writer.write_u16::<BigEndian>(self.cart_id)?;
		writer.write_u16::<BigEndian>(self.country_code)?;

		Ok(())
	}
}

impl std::default::Default for RomHeader {
    fn default() -> Self {
        RomHeader {
			cart_timing: DEFAULT_CART_TIMING,
			clock_rate: DEFAULT_CLOCK_RATE,
			load_addr: 0,
			release: 0,
			crc1: 0,
			crc2: 0,
			rsvd_18: 0,
			rsvd_1c: 0,
			name: [0u8; HEADER_NAME_LEN],
			rsvd_34: 0,
			manuf_id: 0,
			cart_id: 0,
			country_code: 0,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ChecksumError {
    NotLongEnough,
    ErrorReadingBuffer,
}

pub fn detect_swapping(buffer: &[u8]) -> Option<ByteSwapping> {
    if buffer.len() < 4 {
        return None;
    }

    return match (buffer[0], buffer[1], buffer[2], buffer[3]) {
        (0x80, 0x37, 0x12, 0x40) => Some(ByteSwapping::Native),
        (0x37, 0x80, 0x40, 0x12) => Some(ByteSwapping::U16LittleEndian),
        (   _,    _,    _,    _) => None,
    };
}

pub fn swap_cart_to(new_swapping: ByteSwapping, buffer: &mut [u8]) -> Result<(), Error> {
    let original_swapping = match detect_swapping(buffer) {
        Some(swapping) => swapping,
        None => {
            return Err(Error::new(ErrorKind::Other, "Unknown original byte swapping"));
        },
    };

    if (buffer.len() % 2) != 0 {
        return Err(Error::new(ErrorKind::Other, "Not an even length for swapping"));
    }

    if original_swapping == new_swapping {
        return Ok(());
    }

    for ii in 0..(buffer.len() / 2) {
        let cur_base = (ii * 2) as usize;
        let temp = buffer[cur_base];
        buffer[cur_base] = buffer[cur_base + 1];
        buffer[cur_base + 1] = temp;
    }

    Ok(())
}

const CHECKSUM_START:  usize = BOOTCODE_END;
const CHECKSUM_LENGTH: usize = LOAD_LEN as usize;
const CHECKSUM_END: usize = CHECKSUM_START + CHECKSUM_LENGTH;
const CHECKSUM_START_VALUE: u32 = 0xf8ca4ddc;

pub fn calculate_cart_checksum(buffer: &[u8]) -> Result<(u32, u32), ChecksumError> {
    if buffer.len() < CHECKSUM_END {
        return Err(ChecksumError::NotLongEnough);
    }

    let checksum_slice = &buffer[CHECKSUM_START..CHECKSUM_END];

    let mut reader = Cursor::new(checksum_slice);

    let mut c1: u32;
    let mut k1: u32;
    let mut k2: u32;

    let mut t1 = CHECKSUM_START_VALUE;
    let mut t2 = CHECKSUM_START_VALUE;
    let mut t3 = CHECKSUM_START_VALUE;
    let mut t4 = CHECKSUM_START_VALUE;
    let mut t5 = CHECKSUM_START_VALUE;
    let mut t6 = CHECKSUM_START_VALUE;

    for _ in 0..(CHECKSUM_LENGTH / 4) {
        c1 = match reader.read_u32::<BigEndian>() {
            Ok(value) => value,
            Err(_) => {
                return Err(ChecksumError::ErrorReadingBuffer);
            },
        };

        k1 = t6.wrapping_add(c1);
        if k1 < t6 {
            t4 += 1;
        }
        t6 = k1;
        t3 ^= c1;
        k2 = c1 & 0x1f;
        k1 = c1.rotate_left(k2);
        t5 = t5.wrapping_add(k1);
        if c1 < t2 {
            t2 ^= k1;
        } else {
            t2 ^= t6 ^ c1;
        }
        t1 = t1.wrapping_add(c1 ^ t5);
    }

    return Ok((
        t6 ^ t4 ^ t3, 
        t5 ^ t2 ^ t1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculate_fails_with_slice_to_small() {
        let empty_array = [0u8;0];
        assert_eq!(calculate_cart_checksum(&empty_array), Err(ChecksumError::NotLongEnough));
    }

    #[test]
    fn checksum_test_vectors() {
        let mut zero_vec: Vec<u8> = Vec::new();
        for _ in 0..CHECKSUM_END {
            zero_vec.push(0);
        }
        assert_eq!(calculate_cart_checksum(&zero_vec), Ok((0xF8CA4DDC, 0x303A4DDC)));

        for i in 0..CHECKSUM_END {
            zero_vec[i] = 0xFF;
        }
        assert_eq!(calculate_cart_checksum(&zero_vec), Ok((0xF8C24DDC, 0xC1544DDC)));

        for i in 0..CHECKSUM_END {
            zero_vec[i] = 0x41;
        }
        assert_eq!(calculate_cart_checksum(&zero_vec), Ok((0xFDCF52E1, 0xCD5A4DDC)));
    }
}