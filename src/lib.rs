pub mod fhaes;
pub mod utils;
pub mod fhaes_boolean;

use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use fhaes_boolean::*;
use fhaes::AES;
use utils::{key_expansion, byte_from_u8};
use tfhe::prelude::*;
use rayon::prelude::*;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use std::array;

    use rayon::prelude::*;
    use tfhe::boolean::{gen_keys, prelude::ServerKey};

    use crate::utils::generate_counters;

    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn key_expansion_test() {
        let key = [1u8; 16];
        let expected_result = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            124, 125, 125, 125, 125, 124, 124, 124, 124, 125, 125, 125, 125,
            124, 124, 124, 110, 109, 109, 130, 19, 17, 17, 254, 111, 108, 108,
            131, 18, 16, 16, 255, 160, 167, 123, 75, 179, 182, 106, 181, 220,
            218, 6, 54, 206, 202, 22, 201, 220, 224, 166, 192, 111, 86, 204,
            117, 179, 140, 202, 67, 125, 70, 220, 138, 150, 102, 216, 63, 249,
            48, 20, 74, 74, 188, 222, 9, 55, 250, 2, 131, 155, 17, 52, 165, 98,
            33, 32, 239, 40, 157, 254, 230, 31, 103, 252, 101, 94, 161, 121, 101,
            60, 128, 89, 138, 20, 29, 167, 108, 11, 122, 91, 9, 4, 152, 120, 78,
            56, 24, 33, 196, 44, 5, 134, 168, 39, 127, 221, 161, 205, 89, 74, 130,
            245, 65, 107, 70, 217, 68, 237, 238, 254, 59, 48, 79, 25, 93, 206, 57,
            236, 28, 165, 127, 53, 88, 72, 145, 203, 99, 120, 222];
        let expanded_key = key_expansion(&key);
        assert_eq!(expanded_key, expected_result);
    }


    #[test]
    fn aes_encrypt_one_block_fhe() {
        let config = ConfigBuilder::default().build();
        let key = [0u8; 16];
        let expanded_key = key_expansion(&key);
        let (_, server_key) = generate_keys(config);
        rayon::broadcast(|_| set_server_key(server_key.clone()));
        set_server_key(server_key.clone());
        let fhe_key_aes = expanded_key.map(|x| FheUint8::encrypt_trivial(x));
        let mut fhe_aes = AES::new(fhe_key_aes);
        let block = array::from_fn::<u8, 16, _>(|x|x.try_into().unwrap());
        let block_enc = block.map(|x| FheUint8::encrypt_trivial(x));
        fhe_aes.set_aes_key(expanded_key);
        let sub_clear = fhe_aes.encrypt_one_block(block);
        println!("sub clear: {:?}", sub_clear);
        let sub_fhe: Vec::<u8> = fhe_aes.encrypt_one_block_fhe(block_enc).par_iter().map(|x|x.try_decrypt_trivial().unwrap()).collect();
        assert_eq!(sub_clear, sub_fhe[..]);
    }

    #[test]
    fn aes_ctr_test() {
        let config = ConfigBuilder::default().build();
        let key = [0u8; 16];
        let expanded_key = key_expansion(&key);
        let (_, server_key) = generate_keys(config);
        rayon::broadcast(|_| set_server_key(server_key.clone()));
        set_server_key(server_key.clone());
        let fhe_key_aes = expanded_key.map(|x| FheUint8::encrypt_trivial(x));
        let mut fhe_aes = AES::new(fhe_key_aes);
        let mut iv = [1u8; 16];
        iv[15] = 0u8;
        iv[14] = 0u8;
        iv[13] = 0u8;
        iv[12] = 0u8;
        let iv_fhe = iv.map(|x| FheUint8::encrypt_trivial(x));
        let block = array::from_fn::<u8, 16, _>(|x|x.try_into().unwrap());
        let block_enc = block.map(|x| FheUint8::encrypt_trivial(x));
        let blocks_fhe = vec![block_enc.clone(), block_enc.clone()];
        let blocks = vec![block, block.clone()];
    
        fhe_aes.set_aes_key(expanded_key);
        let ctr_enc = fhe_aes.encrypt_ctr_mode(blocks, iv);
        let ctr_enc_fhe: Vec<Vec<u8>> = fhe_aes.encrypt_ctr_mode_fhe(blocks_fhe, iv_fhe).par_iter().map(|x| x.par_iter().map(|y| y.try_decrypt_trivial().unwrap()).collect()).collect();
        println!("Decrypted ciphertext: {:?}", ctr_enc);
        for i in 0..ctr_enc.len() {
            assert_eq!(ctr_enc[i], ctr_enc_fhe[i][..]);
        }
    }

    #[test]
    fn aes_encrypt_one_block_boolfhe() {
        let key = [0u8; 16];
        let expanded_key = key_expansion(&key);
        let (client_key, server_key) = gen_keys();
        let fhe_key_aes = expanded_key.map(|x| byte_from_u8(&client_key, x));
        let t = client_key.encrypt(true);
        let f = client_key.encrypt(false);
        let mut fhe_aes = AesBoolean::new(fhe_key_aes, server_key, t, f);
        let block = array::from_fn::<u8, 16, _>(|x|x.try_into().unwrap());
        let block_enc = block.into_par_iter().map(|x| byte_from_u8(&client_key, x)).collect();
        let sub_fhe: Vec::<u8> = fhe_aes.encrypt_one_block_fhe(block_enc).par_iter().map(|x|x.decrypt(&client_key)).collect();
        println!("fhe result bool: {:?}", sub_fhe)
    }

    #[test]
    fn aes_encrypt_ctr_boolfhe() {
        let key = [0u8; 16];
        let expanded_key = key_expansion(&key);
        let (client_key, server_key) = gen_keys();
        let fhe_key_aes = expanded_key.map(|x| byte_from_u8(&client_key, x));
        let mut iv = [1u8; 16];
        iv[15] = 0u8;
        iv[14] = 0u8;
        iv[13] = 0u8;
        iv[12] = 0u8;

        let iv_fhe: Vec<AesByte> = iv.iter().map(|x| byte_from_u8(&client_key, *x)).collect();
        let t = client_key.encrypt(true);
        let f = client_key.encrypt(false);
        let mut fhe_aes = AesBoolean::new(fhe_key_aes, server_key, t, f);
        let block = array::from_fn::<u8, 16, _>(|x|x.try_into().unwrap());
        let block_enc: Vec<AesByte> = block.into_par_iter().map(|x| byte_from_u8(&client_key, x)).collect();
        let block_two = block_enc.clone();
        let blocks = vec![block_enc, block_two.clone()];
        let (counter1, counter2) = generate_counters(&client_key, 2);
        let encrypted_blocks = fhe_aes.encrypt_ctr_mode_fhe(blocks, iv_fhe, counter1, counter2);
        let decoded_encryption: Vec::<Vec<u8>> = encrypted_blocks.
            par_iter().
            map(|x|x.par_iter().map(|y| y.decrypt(&client_key)).collect()).collect();
        println!("fhe result bool: {:?}", decoded_encryption);
        assert_eq!(vec![vec![163u8, 193, 189, 7, 149, 185, 73, 225, 2, 137, 78, 5, 233, 84, 234, 237], vec![200u8, 201, 182, 23, 199, 152, 198, 229, 185, 16, 179, 154, 41, 136, 210, 72]], decoded_encryption);
    }
}
