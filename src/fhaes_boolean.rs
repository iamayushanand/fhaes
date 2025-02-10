use tfhe::boolean::prelude::*;
use rayon::prelude::*;
use std::time::Instant;
use crate::utils::{byte_from_u8, mix_mux_gate, xor_aes_byte, xor_aes_byte_blocks};

#[derive(Clone)]
pub struct AesByte {
    bits: Vec<Ciphertext>
}

impl AesByte {
    pub fn get_bits(self: &AesByte) -> Vec<Ciphertext> {
        self.bits.clone()
    }

    pub fn top_bit(self: &AesByte) -> Ciphertext {
        self.bits[7].clone()
    }

    pub fn shift_left(self: &AesByte, f: &Ciphertext) -> AesByte {
       let mut result_bits = self.bits.clone();
       for i in (1..8).rev() {
           result_bits[i]=result_bits[i-1].clone();
       }
       result_bits[0] = f.clone();
       AesByte {
           bits: result_bits
       }
    }

    pub fn new(input_bits: Vec<Ciphertext>) -> AesByte {
        AesByte {
            bits: input_bits
        }
    }

    pub fn decrypt(self: &AesByte, client_key: &ClientKey) -> u8 {
        let result_bits: Vec<bool> = self.bits.iter().map(|x| client_key.decrypt(x)).collect();
        let mut result = 0;
        for i in 0..8 {
            result += (1<<i)*u8::from(result_bits[i]);
        }
        result
    }

    pub fn sbox(self: &AesByte, server_key: &ServerKey) -> AesByte {
        let U0 = self.bits[7].clone();
        let U1 = self.bits[6].clone();
        let U2 = self.bits[5].clone();
        let U3 = self.bits[4].clone();
        let U4 = self.bits[3].clone();
        let U5 = self.bits[2].clone();
        let U6 = self.bits[1].clone();
        let U7 = self.bits[0].clone();
        let t1 = server_key.xor(&U3, &U5);
        let t2 = server_key.xor(&U0, &U6);
        let t3 = server_key.xor(&U0, &U3);
        let t4 = server_key.xor(&U0, &U5);
        let t5 = server_key.xor(&U1, &U2);
        let t6 = server_key.xor(&t5, &U7);
        let t7 = server_key.xor(&t6, &U3);
        let t8 = server_key.xor(&t2, &t1);
        let t9 = server_key.xor(&t6, &U0);
        let t10 = server_key.xor(&t6, &U6);
        let t11 = server_key.xor(&t10, &t4);
        let t12 = server_key.xor(&U4, &t8);
        let t13 = server_key.xor(&t12, &U5);
        let t14 = server_key.xor(&t12, &U1);
        let t15 = server_key.xor(&t13, &U7);
        let t16 = server_key.xor(&t13, &t5);
        let t17 = server_key.xor(&t14, &t3);
        let t18 = server_key.xor(&U7, &t17);
        let t19 = server_key.xor(&t16, &t17);
        let t20 = server_key.xor(&t16, &t4);
        let t21 = server_key.xor(&t5, &t17);
        let t22 = server_key.xor(&t2, &t21);
        let t23 = server_key.xor(&U0, &t21);
        let t24 = server_key.and(&t8, &t13);
        let t25 = server_key.and(&t11, &t15);
        let t26 = server_key.xor(&t25, &t24);
        let t27 = server_key.and(&t7, &U7);
        let t28 = server_key.xor(&t27, &t24);
        let t29 = server_key.and(&t2, &t21);
        let t30 = server_key.and(&t10, &t6);
        let t31 = server_key.xor(&t30, &t29);
        let t32 = server_key.and(&t9, &t18);
        let t33 = server_key.xor(&t32, &t29);
        let t34 = server_key.and(&t3, &t17);
        let t35 = server_key.and(&t1, &t19);
        let t36 = server_key.xor(&t35, &t34);
        let t37 = server_key.and(&t4, &t16);
        let t38 = server_key.xor(&t37, &t34);
        let t39 = server_key.xor(&t26, &t14);
        let t40 = server_key.xor(&t28, &t38);
        let t41 = server_key.xor(&t31, &t36);
        let t42 = server_key.xor(&t33, &t38);
        let t43 = server_key.xor(&t39, &t36);
        let t44 = server_key.xor(&t40, &t20);
        let t45 = server_key.xor(&t41, &t22);
        let t46 = server_key.xor(&t42, &t23);
        let t47 = server_key.xor(&t43, &t44);
        let t48 = server_key.and(&t43, &t45);
        let t49 = server_key.xor(&t46, &t48);
        let t50 = server_key.and(&t47, &t49);
        let t51 = server_key.xor(&t50, &t44);
        let t52 = server_key.xor(&t45, &t46);
        let t53 = server_key.xor(&t44, &t48);
        let t54 = server_key.and(&t53, &t52);
        let t55 = server_key.xor(&t54, &t46);
        let t56 = server_key.xor(&t45, &t55);
        let t57 = server_key.xor(&t49, &t55);
        let t58 = server_key.and(&t46, &t57);
        let t59 = server_key.xor(&t58, &t56);
        let t60 = server_key.xor(&t49, &t58);
        let t61 = server_key.and(&t51, &t60);
        let t62 = server_key.xor(&t47, &t61);
        let t63 = server_key.xor(&t62, &t59);
        let t64 = server_key.xor(&t51, &t55);
        let t65 = server_key.xor(&t51, &t62);
        let t66 = server_key.xor(&t55, &t59);
        let t67 = server_key.xor(&t64, &t63);
        let t68 = server_key.and(&t66, &t13);
        let t69 = server_key.and(&t59, &t15);
        let t70 = server_key.and(&t55, &U7);
        let t71 = server_key.and(&t65, &t21);
        let t72 = server_key.and(&t62, &t6);
        let t73 = server_key.and(&t51, &t18);
        let t74 = server_key.and(&t64, &t17);
        let t75 = server_key.and(&t67, &t19);
        let t76 = server_key.and(&t63, &t16);
        let t77 = server_key.and(&t66, &t8);
        let t78 = server_key.and(&t59, &t11);
        let t79 = server_key.and(&t55, &t7);
        let t80 = server_key.and(&t65, &t2);
        let t81 = server_key.and(&t62, &t10);
        let t82 = server_key.and(&t51, &t9);
        let t83 = server_key.and(&t64, &t3);
        let t84 = server_key.and(&t67, &t1);
        let t85 = server_key.and(&t63, &t4);
        let t86 = server_key.xor(&t83, &t84);
        let t87 = server_key.xor(&t78, &t86);
        let t88 = server_key.xor(&t77, &t87);
        let t89 = server_key.xor(&t68, &t70);
        let t90 = server_key.xor(&t69, &t68);
        let t91 = server_key.xor(&t71, &t72);
        let t92 = server_key.xor(&t80, &t89);
        let t93 = server_key.xor(&t75, &t91);
        let t94 = server_key.xor(&t76, &t92);
        let t95 = server_key.xor(&t93, &t94);
        let t96 = server_key.xor(&t91, &t90);
        let t97 = server_key.xor(&t71, &t73);
        let t98 = server_key.xor(&t81, &t86);
        let t99 = server_key.xor(&t89, &t97);
        let S3 = server_key.xor(&t88, &t96);
        let t100 = server_key.xor(&t74, &t93);
        let t101 = server_key.xor(&t82, &t95);
        let t102 = server_key.xor(&t98, &t99);
        let S7 = server_key.xnor(&t80, &t102);
        let t103 = server_key.xor(&t83, &t100);
        let t104 = server_key.xor(&t87, &t79);
        let S0 = server_key.xor(&t88, &t100);
        let S6 = server_key.xnor(&t95, &t102);
        let S4 = server_key.xor(&t99, &S3);
        let S1 = server_key.xnor(&S3, &t100);
        let t105 = server_key.xor(&t101, &t103);
        let S2 = server_key.xnor(&t105, &t85);
        let S5 = server_key.xor(&t104, &t101);

        let mut result_bits = Vec::new();
        result_bits.push(S7);
        result_bits.push(S6);
        result_bits.push(S5);
        result_bits.push(S4);
        result_bits.push(S3);
        result_bits.push(S2);
        result_bits.push(S1);
        result_bits.push(S0);
        AesByte{
            bits: result_bits
        }
    }
}

pub struct AesBoolean {
    aes_key_fhe     : [AesByte; 176],
    server_key      : ServerKey,
    true_bit        : Ciphertext,
    false_bit       : Ciphertext
}

impl AesBoolean {

    // initialise
    pub fn new(aes_key: [AesByte; 176], key: ServerKey, t: Ciphertext, f: Ciphertext) -> AesBoolean {

        AesBoolean{
            aes_key_fhe     : aes_key,
            server_key      : key,
            true_bit        : t,
            false_bit       : f

        }
    }

    pub fn encrypt_ctr_mode_fhe(&self, 
        blocks: Vec<Vec<AesByte>>, 
        iv: Vec<AesByte>, 
        counters_1: Vec<AesByte>, 
        counters_2: Vec<AesByte>) -> Vec<Vec<AesByte>> {
        let num_blocks = blocks.len();
        let results = (0..num_blocks).into_par_iter().map( |i| { 
            let mut current_iv = iv.clone();
            current_iv[15] = counters_1[i].clone();
            current_iv[14] = counters_2[i].clone();
            let c_n = self.encrypt_one_block_fhe(current_iv);
            let r_n = xor_aes_byte_blocks(&self.server_key, &blocks[i], &c_n);
            r_n
        }).collect();
        return results 
    }

    pub fn encrypt_one_block_fhe(&self, mut block: Vec<AesByte>) -> Vec<AesByte>{
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

    pub fn add_round_key_fhe(&self, block: &Vec<AesByte>, round_no: usize) -> Vec<AesByte>{
        let mut result = block.clone();
        for i in 0..16{
            let key_idx = round_no*16+i;
            result[i] = xor_aes_byte(&self.server_key, &result[i], &self.aes_key_fhe[key_idx]);
        }
        result
    }

    pub fn sub_bytes_fhe(&self, block: &Vec<AesByte>) -> Vec<AesByte> {
        //todo
        //let result = &block.par_iter().map_init(||{} , |rng, x| x.sbox(&self.server_key));
        let result = block.into_par_iter().map(|x| x.sbox(&self.server_key)).collect();
        result
    }

    pub fn shift_rows_fhe(&self, block: &Vec<AesByte>) -> Vec<AesByte> {
        let mut result = block.clone();
        for i in 0..4 {
            result[1+4*i] = block[1+4*((i+1)%4)].clone();
            result[2+4*i] = block[2+4*((i+2)%4)].clone();
            result[3+4*i] = block[3+4*((i+3)%4)].clone();
        }
        result
    }

    pub fn mix_columns_fhe(&self, block: &Vec<AesByte>) -> Vec<AesByte> {
        let mut result = block.clone();
        let mut b = block.clone();
        for i in 0..16{
            let h = &block[i].top_bit();
            b[i] = block[i].shift_left(&self.false_bit);
            b[i] = xor_aes_byte(&self.server_key, &b[i], &mix_mux_gate(&self.server_key,&h,&self.true_bit,&self.false_bit));
            // 0x1B
        }
       
        for column in 0..4 {
            
            //result[0+4*column] =  b[0+4*column].clone();
            //result[0+4*column] =  xor_aes_byte(&self.server_key,&b[0+4*column],&block[3+4*column])
            result[0+4*column] = xor_aes_byte(&self.server_key, &xor_aes_byte(&self.server_key, 
                                &xor_aes_byte(&self.server_key,&b[0+4*column],&block[3+4*column]),&block[2+4*column]),
                                &xor_aes_byte(&self.server_key, &b[1+4*column],&block[1+4*column]));
            result[1+4*column] = xor_aes_byte(&self.server_key, &xor_aes_byte(&self.server_key, 
                                &xor_aes_byte(&self.server_key,&b[1+4*column],&block[0+4*column]),&block[3+4*column]),
                                &xor_aes_byte(&self.server_key, &b[2+4*column],&block[2+4*column]));
            result[2+4*column] = xor_aes_byte(&self.server_key, &xor_aes_byte(&self.server_key, 
                                &xor_aes_byte(&self.server_key,&b[2+4*column],&block[1+4*column]),&block[0+4*column]),
                                &xor_aes_byte(&self.server_key, &b[3+4*column],&block[3+4*column]));
            result[3+4*column] = xor_aes_byte(&self.server_key, &xor_aes_byte(&self.server_key, 
                                &xor_aes_byte(&self.server_key,&b[3+4*column],&block[2+4*column]),&block[1+4*column]),
                                &xor_aes_byte(&self.server_key, &b[0+4*column],&block[0+4*column]));
        }
        result
    }
}
