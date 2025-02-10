use tfhe::{prelude::FheTrivialEncrypt, FheUint8, MatchValues};
use rayon::prelude::*;
use std::time::Instant;
use crate::utils::xor_blocks;

pub struct AES {
    aes_key         : [u8; 176],
    aes_key_fhe     : [FheUint8; 176],
    sbox_fhe        : MatchValues<u8>,
}

impl AES {

    // initialise
    pub fn new(aes_key: [FheUint8; 176]) -> AES {

        let sbox = [
            // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]; // F
                                                                                                             //
        let mut sbox_vec = Vec::new();
        for i in 0..256u16 {
           sbox_vec.push((u8::try_from(i).ok().unwrap(), sbox[usize::from(i)]));
        }
        let sbox_matcher = MatchValues::new(sbox_vec);

        AES{
            aes_key         : [0; 176],
            aes_key_fhe     : aes_key,
            sbox_fhe        : sbox_matcher.unwrap(),
        }
    }

    //set the AES key
    //(note this is not the 128 bit key, its the key after the offline key_expansion step)
    pub fn set_aes_key(&mut self, aes_key: [u8; 176]) {
        self.aes_key = aes_key;
    }

    //set the AES key
    //(note this is not the 128 bit key, its the key after the offline key_expansion step)
    pub fn set_aes_key_fhe(&mut self, aes_key: [FheUint8; 176]) {
        self.aes_key_fhe = aes_key;
    }

    pub fn encrypt_ctr_mode(&self, blocks: Vec<[u8; 16]>, mut iv: [u8; 16]) -> Vec<[u8; 16]> {
        let num_blocks = blocks.len();
        let mut results: Vec<[u8; 16]> = Vec::new();
        for i in 0..num_blocks {
            let c_n = self.encrypt_one_block(iv);
            let mut r_n = [0u8; 16];
            for j in 0..16 {
                r_n[j] = blocks[i][j]^c_n[j];
            }
            results.push(r_n);
            let j = u8::try_from(i+1).unwrap();
            iv[15] = j&0xf;
            iv[14] = (j>>4)&0xf;
        }
        return results 
    }

    pub fn encrypt_ctr_mode_fhe(&self, blocks: Vec<[FheUint8; 16]>, mut iv: [FheUint8; 16]) -> Vec<[FheUint8; 16]> {
        let num_blocks = blocks.len();
        let results = (0..num_blocks).into_par_iter().map( |i| { 
            let mut current_iv = iv.clone();
            current_iv[15] = FheUint8::encrypt_trivial(u8::try_from(i&0xf).unwrap());
            current_iv[14] = FheUint8::encrypt_trivial(u8::try_from((i>>4)&0xf).unwrap());
            let c_n = self.encrypt_one_block_fhe(current_iv);
            let r_n = xor_blocks(&blocks[i], &c_n);
            r_n
        }).collect();
        return results 
    }

    pub fn encrypt_one_block_fhe(&self, mut block: [FheUint8; 16]) -> [FheUint8; 16]{
        block = self.add_round_key_fhe(&block, 0);
        for t in 0..9{
            block = self.sub_bytes_fhe(&block);
            block = self.shift_rows_fhe(&block);
            block = self.mix_columns_fhe(&block);
            block = self.add_round_key_fhe(&block, t+1);
        }
        block = self.sub_bytes_fhe(&block);
        block = self.shift_rows_fhe(&block);
        block = self.add_round_key_fhe(&block, 10);
        block
    }

    //encrypts a single block
    pub fn encrypt_one_block(&self, mut block: [u8; 16]) -> [u8; 16]{
        block = self.add_round_key(block, 0);
        for t in 0..9{
             block = self.sub_bytes(block);
             block = self.shift_rows(block);
             block = self.mix_columns(block);
             block = self.add_round_key(block, t+1);
        }
        block = self.sub_bytes(block);
        block = self.shift_rows(block);
        block = self.add_round_key(block, 10);
        block
    }

    pub fn add_round_key_fhe(&self, block: &[FheUint8; 16], round_no: usize) -> [FheUint8; 16]{
        let mut result = block.clone();
        for i in 0..16{
            let key_idx = round_no*16+i;
            result[i] ^= &self.aes_key_fhe[key_idx];
        }
        result
    }

    pub fn add_round_key(&self, block: [u8; 16], round_no: usize) -> [u8; 16] {
        let mut result = [0; 16];
        for i in 0..16{
            let key_idx = round_no*16+i;
            result[i] = block[i]^self.aes_key[key_idx];
        }
        result
    }

    pub fn sub_bytes_fhe(&self, block: &[FheUint8; 16]) -> [FheUint8; 16] {
        let result: Vec::<FheUint8>  = block.par_iter().map(|x| x.match_value(&self.sbox_fhe).unwrap().0).collect();
        result.first_chunk::<16>().unwrap().clone()
    }

    pub fn sub_bytes(&self, block: [u8; 16]) -> [u8; 16] {
        let sbox = [
            // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]; // F
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = sbox[usize::from(block[i])];
        }
        result
    }

    pub fn shift_rows(&self, block: [u8; 16]) -> [u8; 16] {
        let mut result = [0u8; 16];
        for i in 0..4 {
            result[0+4*i] = block[0+4*i];
            result[1+4*i] = block[1+4*((i+1)%4)];
            result[2+4*i] = block[2+4*((i+2)%4)];
            result[3+4*i] = block[3+4*((i+3)%4)];
        }
        result
    }

    pub fn shift_rows_fhe(&self, block: &[FheUint8; 16]) -> [FheUint8; 16] {
        let mut result = block.clone();
        for i in 0..4 {
            result[1+4*i] = block[1+4*((i+1)%4)].clone();
            result[2+4*i] = block[2+4*((i+2)%4)].clone();
            result[3+4*i] = block[3+4*((i+3)%4)].clone();
        }
        result
    }

    // adapted from https://en.wikipedia.org/wiki/Rijndael_MixColumns
    pub fn mix_columns(&self, block: [u8; 16]) -> [u8; 16] {
        let mut result = [0u8; 16];
        for column in 0..4 {
            let mut b = [0u8; 4];
            for i in 4*column..4*(column+1) {
                //print!("{:?} ", block[idx]);
                let h = block[i] & 0x80;
                b[i-4*column] = block[i] << 1;
                if h == 0x80 {
                    b[i-4*column] ^= 0x1B;
                }
            }
            //println!("over");
            result[0+4*column] = b[0]^block[3+4*column]^block[2+4*column]^b[1]^block[1+4*column];
            result[1+4*column] = b[1]^block[0+4*column]^block[3+4*column]^b[2]^block[2+4*column];
            result[2+4*column] = b[2]^block[1+4*column]^block[0+4*column]^b[3]^block[3+4*column];
            result[3+4*column] = b[3]^block[2+4*column]^block[1+4*column]^b[0]^block[0+4*column];
        }
        result
    }

    pub fn mix_columns_fhe(&self, block: &[FheUint8; 16]) -> [FheUint8; 16] {
        let mut result = block.clone();
        let mut b = block.clone();
        for i in 0..16{
            let h = &block[i] >> 7u8;
            b[i] = &block[i] << 1u8;
            b[i] ^= h*0x1B
        }
       
        for column in 0..4 {
            
            result[0+4*column] = &b[0+4*column]^&block[3+4*column]^&block[2+4*column]^&b[1+4*column]^&block[1+4*column];
            result[1+4*column] = &b[1+4*column]^&block[0+4*column]^&block[3+4*column]^&b[2+4*column]^&block[2+4*column];
            result[2+4*column] = &b[2+4*column]^&block[1+4*column]^&block[0+4*column]^&b[3+4*column]^&block[3+4*column];
            result[3+4*column] = &b[3+4*column]^&block[2+4*column]^&block[1+4*column]^&b[0+4*column]^&block[0+4*column];
        }
        result
    }
}
