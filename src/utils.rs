use tfhe::boolean::prelude::*;
use tfhe::FheUint8;
use tfhe::prelude::*;
use rayon::prelude::*;

use crate::fhaes_boolean::AesByte;

pub fn get_trivial_block() -> [FheUint8; 16] {
    [();16].map(|_| FheUint8::encrypt_trivial(0u8))
}

pub fn rot_word(word: &[u8]) -> [u8; 4] {
    let mut result = [0u8; 4];
    for i in 0..4 {
        if i!=3 {
            result[i]=word[i+1];
        }else{
            result[i]=word[0];
        }
    }
    return result
}

pub fn sub_word(word: &[u8]) -> [u8; 4] {
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
    let mut result = [0u8; 4];
    for i in 0..4 {
        result[i] = sbox[usize::from(word[i])];
    }
    return result;
}

fn key_expand_core(word: &[u8]) -> [u8; 4] {
    let rot_result = rot_word(word);
    let sub_result = sub_word(&rot_result);
    return sub_result
}

pub fn xor_blocks(a: &[FheUint8; 16], b: &[FheUint8; 16]) -> [FheUint8; 16] {
    let mut result = get_trivial_block();
    for i in 0..16 {
        result[i] = &a[i]^&b[i];
    }
    result
}

pub fn key_expansion(key: &[u8; 16]) -> [u8; 176] {
    let mut expanded_key = [0u8; 176];
    let rcon = [1u8, 2u8, 4u8, 8u8, 16u8, 32u8, 64u8, 128u8, 27u8, 54u8];
    for i in 0..44 {
        if i<4 {
            for k in 0..4 {
                expanded_key[4*i+k] = key[4*i+k];
            }
        }else if i%4==0 {
            let core_result = key_expand_core(&expanded_key[4*(i-1)..4*i]);
            for k in 0..4 {
                expanded_key[4*i+k] = expanded_key[4*(i-4)+k];
                expanded_key[4*i+k] ^= core_result[k];
                if k==0 {
                    expanded_key[4*i+k] ^= rcon[(i/4)-1];
                }

            }
        }else{
            for k in 0..4 {
                expanded_key[4*i+k] = expanded_key[4*(i-4)+k];
                expanded_key[4*i+k] ^= expanded_key[4*(i-1)+k];
            }
        }
    }
    return expanded_key
}
pub fn xor_aes_byte(server_key: &ServerKey, a: &AesByte, b: &AesByte) -> AesByte {
    let b_bits = b.get_bits();
    let result_bits = a.get_bits()
        .into_par_iter()
        .zip(0..8)
        .map(|(x, y)| server_key.xor(&x, &b_bits[y]))
        .collect();
    AesByte::new(result_bits)
}

pub fn mix_mux_gate(server_key: &ServerKey, h: &Ciphertext, t: &Ciphertext, f: &Ciphertext) -> AesByte {
    //0x1B = 00011011
    let mut result_bits: Vec<Ciphertext> = Vec::new();
    let c0 = f.clone();
    let c1 = f.clone();
    let c2 = f.clone();
    let c3 = server_key.mux(h, t, f);
    let c4 = server_key.mux(h, t, f);
    let c5 = f.clone();
    let c6 = server_key.mux(h, t, f);
    let c7 = server_key.mux(h, t, f);
    result_bits.push(c7);
    result_bits.push(c6);
    result_bits.push(c5);
    result_bits.push(c4);
    result_bits.push(c3);
    result_bits.push(c2);
    result_bits.push(c1);
    result_bits.push(c0);
    AesByte::new(result_bits)
    
}

pub fn byte_from_u8(client_key: &ClientKey, input: u8) -> AesByte {
    let mut result_bytes = Vec::new();
    for i in 0..8 {
        let bit = ((input >> i) & 1) == 1;
        result_bytes.push(client_key.encrypt(bit));
    }
    return AesByte::new(result_bytes)
}

pub fn xor_aes_byte_blocks(server_key: &ServerKey, a: &Vec<AesByte>, b: &Vec<AesByte>) -> Vec<AesByte> {
    let result = a.par_iter().zip(0..16).map(|(x, y)| xor_aes_byte(server_key, x,&b[y])).collect();
    result
}

pub fn generate_counters(client_key: &ClientKey, num_blocks: u16) -> (Vec<AesByte>, Vec<AesByte>) {
   let counter1 = (0..num_blocks).into_par_iter().map(|x| byte_from_u8(client_key,u8::try_from(x&0xf).unwrap())).collect();
   let counter2 = (0..num_blocks).into_par_iter().map(|x| byte_from_u8(client_key,u8::try_from((x>>4)&0xf).unwrap())).collect();
   (counter1, counter2)
}
