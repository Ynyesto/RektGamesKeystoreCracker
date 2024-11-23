// use eth_keystore::decrypt_key;
// use std::{fs::File, io::{BufReader, BufRead}, str};

// #[tokio::main]
// async fn main() {
//     // Paths to the keystore file and rockyou.txt
//     let keystore_path = "keystores/redguild1.json";
//     let rockyou_path = "rockyou.txt";   

//     // Open rockyou.txt and read line by line as raw bytes
//     let rockyou_file = File::open(rockyou_path).expect("Failed to open rockyou.txt");
//     let reader = BufReader::new(rockyou_file);

//     for (index, line) in reader.split(b'\n').enumerate() {
//         match line {
//             Ok(raw_line) => {
//                 // Attempt to convert the line to UTF-8
//                 if let Ok(password) = str::from_utf8(&raw_line) {
//                     // Attempt to decrypt the keystore with the current password
//                     match decrypt_key(keystore_path, password.as_bytes()) {
//                         Ok(private_key) => {
//                             println!(
//                                 "Password found: {}\nPrivate Key: 0x{}",
//                                 password,
//                                 hex::encode(private_key)
//                             );
//                             return;
//                         }
//                         Err(_) => {
//                             // Uncomment this line to log each attempt (optional, can slow down brute-forcing)
//                             // eprintln!("Attempt {}: Password '{}' failed", index + 1, password);
//                         }
//                     }
//                 }
//             }
//             Err(e) => {
//                 eprintln!("Skipping invalid line {}: {:?}", index + 1, e);
//             }
//         }
//     }

//     println!("Password not found in rockyou.txt");
// }

// use eth_keystore::decrypt_key;
// use rayon::prelude::*;
// use std::{
//     fs::File,
//     io::{BufRead, BufReader},
//     sync::atomic::{AtomicBool, Ordering},
//     time::Instant,
// };

// fn main() {
//     // Paths to the keystore file and rockyou.txt
//     let keystore_path = "keystores/redguild2.json";
//     let rockyou_path = "rockyou.txt";

//     // Start timer
//     let start_time = Instant::now();

//     // Load passwords from rockyou.txt
//     let rockyou_file = File::open(rockyou_path).expect("Failed to open rockyou.txt");
//     let passwords: Vec<String> = BufReader::new(rockyou_file)
//         .lines()
//         .filter_map(|line| line.ok()) // Skip invalid lines
//         .collect();

//     // Atomic flag to stop threads when the password is found
//     let found = AtomicBool::new(false);

//     // Brute-force in parallel
//     passwords.par_iter().for_each(|password| {
//         if found.load(Ordering::Relaxed) {
//             return; // Skip further work if the password is already found
//         }

//         // Attempt to decrypt the keystore
//         if let Ok(private_key) = decrypt_key(keystore_path, password.as_bytes()) {
//             println!(
//                 "Password found: {}\nPrivate Key: 0x{}",
//                 password,
//                 hex::encode(private_key)
//             );
//             found.store(true, Ordering::Relaxed);
//         }
//     });

//     // End timer
//     let duration = start_time.elapsed();

//     if found.load(Ordering::Relaxed) {
//         println!("Password found in {:.2?}", duration);
//     } else {
//         println!("Password not found in rockyou.txt. Time elapsed: {:.2?}", duration);
//     }
// }

use eth_keystore::decrypt_key;
use rayon::prelude::*;
use std::{
    fs::File,
    io::{BufReader, Read},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

fn main() {
    // Paths to the keystore file and rockyou.txt
    let keystore_path = "keystores/redguild1.json";
    let rockyou_path = "rockyou.txt";

    // Start timer
    let start_time = Instant::now();

    // Read the rockyou.txt file as raw bytes
    let rockyou_file = File::open(rockyou_path).expect("Failed to open rockyou.txt");
    let mut reader = BufReader::new(rockyou_file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect("Failed to read rockyou.txt");

    // Split the raw bytes by newline
    let passwords: Vec<&[u8]> = buffer.split(|&byte| byte == b'\n').collect();

    // Atomic flag to stop threads when the password is found
    let found = AtomicBool::new(false);

    // Brute-force in parallel
    passwords.par_iter().for_each(|password| {
        if found.load(Ordering::Relaxed) {
            return; // Skip further work if the password is already found
        }

        // Attempt to decrypt the keystore
        if let Ok(private_key) = decrypt_key(keystore_path, password) {
            println!(
                "Password found: {}\nPrivate Key: 0x{}",
                String::from_utf8_lossy(password),
                hex::encode(private_key)
            );
            found.store(true, Ordering::Relaxed);
        }
    });

    // End timer
    let duration = start_time.elapsed();

    if found.load(Ordering::Relaxed) {
        println!("Password found in {:.2?}", duration);
    } else {
        println!("Password not found in rockyou.txt. Time elapsed: {:.2?}", duration);
    }
}


