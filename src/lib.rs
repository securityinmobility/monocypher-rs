#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::io::{
    Error,
    ErrorKind
};

/// Function to verify the signature of given data using a given public key
/// The signature is expected to be a 64 byte long vector
/// If the check is successfull, the function returns Ok(())
/// Otherwise it returns an Error of type std::io::Error
pub fn verify_signature_ed25519(data: &Vec<u8>, signature: &Vec<u8>, public_key: &Vec<u8>) -> Result<(), Error> {
    unsafe{ 
        if crypto_ed25519_check(
            signature.as_ptr() as *const u8, 
            public_key.as_ptr() as *const u8,
            data.as_ptr() as *const u8,
            data.len()) 
            == 0 {
            return Ok(())
        }
    };
    return Err(Error::new(ErrorKind::InvalidData, "Signature was wrong"))
}

/// Function to sign the given data using the given private key
/// The private key is expected to be a 32 byte long vector
/// The function returns a 64 byte long vector containing the signature
pub fn sign_ed25519(data: &Vec<u8>, private_key: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut signature = vec![0; 64];
    unsafe { crypto_ed25519_sign(
        signature.as_mut_ptr() as *mut u8, 
        private_key.as_ptr(), 
        data.as_ptr(), 
        data.len()) };
    Ok(signature)
}

/// Hashes the given data using the blake2b algorithm with a 512 bit output size
pub fn blake2b_512(data: &Vec<u8>) -> Result<Vec<u8>, Error>{
    blake2b(data, 64)
}

/// Hashes the given data using the blake2b algorithm with a 256 but output size
pub fn blake2b_256(data: &Vec<u8>) -> Result<Vec<u8>, Error>{
    blake2b(data, 32)
}

/// Hashes the given data using the blake2b algorithm
fn blake2b(data: &Vec<u8>, hash_size: usize) -> Result<Vec<u8>, Error>{
    let mut result = vec![0; hash_size];
    unsafe { crypto_blake2b(result.as_mut_ptr() as *mut u8, 
        hash_size, 
        data.as_ptr(), 
        data.len()) };
    Ok(result.to_vec())
}

//pub fn chacha20_poly1305_encrypt(data: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>) -> Result<(Vec<u8>, [u8; 16]), //Error> {
//    let key: [u8; 32] = key.as_slice().try_into().map_err(|e| Error::new//(ErrorType::CryptographyError, &format!("Error converting key to array, {}", e)))?;
//    let nonce: [u8; 16] = nonce.as_slice().try_into().map_err(|e| Error::new//(ErrorType::CryptographyError, &format!("Error converting nonce to array, {}", e)))?;
//    Ok(aead(data, key, nonce, &[]))
//}

mod test_monocypher_binding{
    use super::*;
    use std::{
        fs,
        env
    };
    
    #[test]
    fn test_verify_signature_ed25519(){
        let data = vec![0x10, 0x20, 0x30, 0x40];
        let signature = vec![0x72,0x43,0x8f,0x03,0x5d,0x07,0xa1,0x0c,0x10,0x38,0xf5,0x1c,0xdd,0x31,0x66,0xb9,0x0b,0x37,0x54,0x5a,0xcc,0x34,0x6c,0x82,0xdd,0x7c,0xbe,0xbb,0xe6,0xd8,0x11,0x71,0x9e,0xb6,0x65,0xee,0xf2,0xfa,0x04,0x04,0xbe,0xa5,0x20,0xe3,0xbb,0x7d,0x87,0x18,0x16,0xba,0xc9,0x51,0x3e,0x47,0xbf,0x33,0xda,0x20,0x15,0xd3,0x6c,0xfe,0x55,0x09];        
        let key: Vec<u8> = vec![0x79,0x12,0xf9,0xf5,0xc6,0x82,0x0b,0x4c,0x00,0x99,0xb5,0x92,0x6c,0xb0,0xb0,0x0b,0x20,0x67,0xc1,0xda,0x3c,0xa1,0x45,0x89,0x81,0xdc,0x69,0xc8,0x39,0xb8,0xae,0xa5];
        let result = verify_signature_ed25519(&data, &signature, &key);
        assert!(result.is_ok());
    }

    /// Test the sign and verify functions using the test vectors from the sign.input file
    /// The file is originating from https://ed25519.cr.yp.to/python/sign.input and
    /// is referenced in RFC8032
    #[test]
    fn test_sign_and_verify_from_file() {

        // Read the sign.input file
        let file_content = fs::read_to_string(format!("{}/src/test_sign.input", env::var("CARGO_MANIFEST_DIR").unwrap())).expect("Failed to read sign.input file");
        let lines: Vec<&str> = file_content.lines().collect();
        let mut counter = 0;
        // Iterate over each line in the file
        for line in lines {
            // Split the line into private_key, public_key, message, and expected_signature
            let parts: Vec<&str> = line.split(':').collect();
            let private_key = hex_to_bytes(parts[0]).expect("Failed to decode private key");
            let public_key = hex_to_bytes(parts[1]).expect("Failed to decode public key");
            let message = hex_to_bytes(parts[2]).expect("Failed to decode message");
            let expected_signature = hex_to_bytes(parts[3]).expect("Failed to decode expected signature")[..64].to_vec();

            // Sign the message using the private key
            let signature = sign_ed25519(&message, &private_key).expect("Failed to sign message");

            // Verify that the signature matches the expected signature
            assert_eq!(signature, expected_signature);

            // Verify the signature using the public key
            let result = verify_signature_ed25519(&message, &expected_signature, &public_key);
            assert!(result.is_ok());
            counter += 1;
        }
        assert_eq!(counter, 1024);
    }

    fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 == 0 {
            (0..s.len())
                .step_by(2)
                .map(|i| s.get(i..i + 2)
                          .and_then(|sub| u8::from_str_radix(sub, 16).ok()))
                .collect()
        } else {
            None
        }
    }

    #[test]
    fn test_blake2b(){
        assert_eq!(blake2b_512(&"TEST".as_bytes().to_vec()).unwrap(), vec![0x53,0x22,0xbc,0x39,0xe2,0x00,0xa6,0xd2,0xef,0x54,0xac,0x67,0x16,0x37,0x6d,0x50,0x00,0xf9,0x8a,0x97,0x15,0xcb,0x52,0x93,0xed,0xd6,0xe1,0xe0,0xf8,0x86,0x5d,0x3b,0x22,0xcb,0x0f,0xa9,0x2e,0x09,0xd5,0x2a,0xbe,0xf0,0xcf,0x58,0xa2,0xb0,0x67,0xd4,0xbc,0x64,0xfb,0xee,0x1e,0x4b,0xce,0x0e,0x9e,0x64,0x2c,0xe8,0x03,0xdc,0x6f,0x99])
    }

    #[test]
    fn test_blake2b_256(){
        assert_eq!(blake2b_256(&vec![0xcf,0xcc,0x95,0xee,0x42,0xe9,0x65,0x25,0xc5,0xbf]).unwrap(), 
            vec![0xa3,0xc7,0x12,0xbf,0x4f,0xa1,0xbc,0x88,0x60,0xc1,0x9f,0xaf,0x8e,0x8f,0xde,0xe0,0xdc,0x06,0x54,0x62,0xc7,0x88,0x1a,0x90,0xfa,0x11,0x6f,0x10,0xa7,0x22,0x00,0x4f]);
        
        
    }
}