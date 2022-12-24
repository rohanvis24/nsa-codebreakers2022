use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use std::fs::File;
use hex_literal::hex;
use std::io;
use std::io::Read;
use std::str;

use indicatif::ProgressBar;

fn main() -> io::Result<()> {
    let h: [u8; 16] = *b"0123456789abcdef";
    let goal_arr: [u8; 4] = [37, 80, 68, 70];

    let mut key: [u8; 16] = *b"00000000-e723-11";
    let iv = hex!("e5b98d6404d48c846d304b8527b1f445");
    
    let mut key_arr = GenericArray::from([0u8; 16]);
    let mut block_copy = GenericArray::from([0u8; 16]);

    let mut f = File::open("/home/rohanvis24/cbc22_task9/important_data_modded.pdf.enc")?;
    let mut block = [0u8; 16];
    f.read_exact(&mut block)?;
    
    let duration: u64 = 256*256*256*256;
    let bar = ProgressBar::new(duration);
    for _i in 0..duration {
        key[7] = key[7] + 1;
        if key[7] == h[15] + 1 {
            key[7] = h[0];
            key[6] = key[6] + 1;
            if key[6] == h[15] + 1 {
                key[6] = h[0];
                key[5] = key[5] + 1;
                if key[5] == h[15] + 1 {
                    key[5] = h[0];
                    key[4] = key[4] + 1;
                    if key[4] == h[15] + 1 {
                        key[4] = h[0];
                        key[3] = key[3] + 1;
                        if key[3] == h[15] + 1 {
                            key[3] = h[0];
                            key[2] = key[2] + 1;
                            if key[2] == h[15] + 1 {
                                key[2] = h[0];
                                key[1] = key[1] + 1;
                                if key[1] == h[15] + 1 {
                                    key[1] = h[0];
                                    key[0] = key[0] + 1;
                                    if key[0] == h[15] + 1 {
                                        println!("Exhausted all keys");
                                        break;
                                    }
                                    if key[0] == h[9] + 1 {
                                        key[0] = h[10];
                                    }
                                }
                                if key[1] == h[9] + 1 {
                                    key[1] = h[10];
                                }
                            }
                            if key[2] == h[9] + 1 {
                                key[2] = h[10];
                            }
                        }
                        if key[3] == h[9] + 1 {
                            key[3] = h[10];
                        }
                    }
                    if key[4] == h[9] + 1 {
                        key[4] = h[10];
                    }
                }
                if key[5] == h[9] + 1 {
                    key[5] = h[10];
                }
            }
            if key[6] == h[9] + 1 {
                key[6] = h[10];
            }
        }
        if key[7] == h[9] + 1 {
            key[7] = h[10];
        }
       
        //progress bar update
        bar.inc(1);

        //decryption
        for i in 0..16 {
            block_copy[i] = block[i];
            key_arr[i] = key[i];
        }
        
        let cipher = Aes128::new(&key_arr);
        cipher.decrypt_block(&mut block_copy);

        for a in 0..16 {
            block_copy[a] = block_copy[a] ^ iv[a];
        }
        
        if &block_copy[0..4] == goal_arr {
            println!("=======================================================================================================================");
            println!("FOUND KEY: {:?}", &key);
            println!("Ascii: {:?}", str::from_utf8(&key).unwrap());
            println!("=======================================================================================================================");
        }
    }
    bar.finish();
    Ok(())
}
