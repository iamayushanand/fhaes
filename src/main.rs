use clap::Parser;
use fhaes::fhaes::AES;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8, CpuFheUint8Array};
use tfhe::prelude::*;
use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use rand::Rng;
use hex;
use fhaes::utils::key_expansion;
use rayon::prelude::*;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    //Initialisation vector 
    #[arg(long)]
    iv: String,

    //Number of blocks to encrypt
    #[arg(short, long)]
    number_of_outputs: u8,

    // AES key
    #[arg(short, long)]
    key: String
}

fn cleartext_aes(key: [u8; 16], input: [u8; 16]) -> [u8; 16] {
    let key = GenericArray::from(key);
    let mut input = GenericArray::from(input);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut input);
    return input.as_slice().try_into().unwrap();
}

fn cleartext_ctr(key: [u8; 16], blocks: Vec<[u8; 16]>, mut iv: [u8; 16]) -> Vec<[u8; 16]> {
    let num_blocks = blocks.len();
    let mut results: Vec<[u8; 16]> = Vec::new();
    for i in 0..num_blocks {
        let c_n = cleartext_aes(key, iv);
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

fn generate_random_block() -> [u8; 16] {
    let mut block = [0u8; 16];
    block = block.map(|_x| rand::thread_rng().gen());
    block 
}

fn main() {
    let args = Args::parse();

    let config = ConfigBuilder::default().build();
    let (_, server_key) = generate_keys(config);
    rayon::broadcast(|_| set_server_key(server_key.clone()));
    set_server_key(server_key.clone());

    let mut blocks: Vec<[u8; 16]> = Vec::new();
    for _ in 0..args.number_of_outputs {
        blocks.push(generate_random_block());
    }

    let blocks_enc = blocks.iter().map(|x| x.map(|y| FheUint8::encrypt_trivial(y))).collect();
    let mut key = [0u8; 16];
    hex::decode_to_slice(args.key, &mut key).expect("Invalid key");
    let mut iv = [0u8; 16];
    hex::decode_to_slice(args.iv, &mut iv).expect("Invalid iv");

    let iv_fhe = iv.map(|x| FheUint8::encrypt_trivial(x));
    let ke_instant = Instant::now();
    let expanded_key = key_expansion(&key);
    println!("AES key expansion took: {} ms", ke_instant.elapsed().as_millis());

    let fhe_key_aes = expanded_key.map(|x| FheUint8::encrypt_trivial(x));
    let mut fhe_aes = AES::new(fhe_key_aes);
    fhe_aes.set_aes_key(expanded_key);

    let cleartext_enc = cleartext_ctr(key.clone(), blocks, iv);
    let enc_instant = Instant::now();
    let fhe_enc = fhe_aes.encrypt_ctr_mode_fhe(blocks_enc, iv_fhe);
    println!("AES of {} outputs computed in : {} ms", args.number_of_outputs, enc_instant.elapsed().as_millis());

    let fhe_enc: Vec<Vec<u8>> = fhe_enc.par_iter().map(|x| x.par_iter().map(|y| y.try_decrypt_trivial().unwrap()).collect()).collect();
    println!("cleartext enc: {:?}", cleartext_enc);
    println!("fhe enc: {:?}", fhe_enc);
}
