use std::{io, vec};
use argh::FromArgs;
use std::process;
use std::path::Path;

/* Structures and enumerations */

#[derive(FromArgs)]
/// Create a polymorphic shellcode from a given shellcode
struct Args {
    /// choose which kind of encryption you want
    #[argh(option, short = 'e', long = "enc")]
    encoding: String,

    /// choose the key for the choosen encryption
    #[argh(option, short = 'k', long = "key")]
    key: i16,

    /// path to the file which contains unauthorized opcodes
    #[argh(option, short = 'f', long = "file", default = "String::from(\"None\")")]
    file: String,

    /// find automatically the good index for encryption to pass the rules
    #[argh(switch, short = 'a', long = "auto")]
    auto: bool,
}

/// Check if the size and the character of the shellcode are correct
fn is_right_format(shellcode : &str) -> bool {
    let good_length = (shellcode.len() -1) % 4; // minus 1 to remove the \n
    let mut ret = true;

    if good_length != 0 {
        println!("Error: Length of shellcode is not correct");
        ret = false;
    };

    if ret {
        let mut index_start = 0; // Index start opcode
        for _ in 0..shellcode.len() / 4{
            if shellcode.chars().nth(index_start) != Some('\\') {
                ret = false;
                println!("Error: \\ not found at index {}", index_start);
                break;
            }
            if shellcode.chars().nth(index_start+1) != Some('x') {
                ret = false;
                println!("Error: x not found at index {}", index_start+1);
                break;
            }
            if !shellcode.chars().nth(index_start+2).unwrap().is_ascii_hexdigit() {
                ret = false;
                println!("Error: hex digit not found at index {}", index_start+2);
                break;
            }
            if !shellcode.chars().nth(index_start+2).unwrap().is_ascii_hexdigit() {
                ret = false;
                println!("Error: hex digit not found at index {}", index_start+3);
                break;
            }
            index_start += 4;
        }
    }
    ret
}

/// Encode the shellcode and add the decoder ahead of it
fn encode_shellcode(shellcode: String, decoder: &str, key: i16) -> String {
    // TODO fonction encodage etape 1

    let start_decoder = "\\xeb\\x11\\x5e\\x31\\xc9\\xb1";
    let end_decoder = "\\x80\\xe9\\x01\\x75\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff";
    let xor_decoder = "\\x80\\x74\\x0e\\xff";
    let add_decoder = "\\x80\\x6c\\x0e\\xff";
    let sub_decoder = "\\x80\\x44\\x0e\\xff";
    let mut encoded_shellcode = String::new();
    let length = shellcode.len() / 4;

    // Creation of the decoder
    encoded_shellcode.push_str(start_decoder);
    encoded_shellcode.push_str(&format!("\\x{:02x}", length));

    match decoder {
        "sub" => encoded_shellcode.push_str(sub_decoder),
        "add" => encoded_shellcode.push_str(add_decoder),
        "xor" => encoded_shellcode.push_str(xor_decoder),
        _ => println!("Error: decoder not found"),
    }

    encoded_shellcode.push_str(&format!("\\x{:02x}", key));
    encoded_shellcode.push_str(end_decoder);

    // Encoding the provided shellcode
    let mut index_start = 0; // Index start opcode
    for _ in 0..shellcode.len() / 4{
        let opcode = &shellcode[index_start+2..index_start+4];
        match decoder {
            "sub" => {
                let encoded_opcode = format!("\\x{:02x}", (i16::from_str_radix(opcode, 16).unwrap() - key) & 0xff);
                encoded_shellcode.push_str(&encoded_opcode);
            },
            "add" => {
                let encoded_opcode = format!("\\x{:02x}", (i16::from_str_radix(opcode, 16).unwrap() + key) & 0xff);
                encoded_shellcode.push_str(&encoded_opcode);
            },
            "xor" => {
                let encoded_opcode = format!("\\x{:02x}", (i16::from_str_radix(opcode, 16).unwrap() ^ key) & 0xff);
                encoded_shellcode.push_str(&encoded_opcode);
            },
            _ => println!("Error: decoder not found"),
        }
        index_start += 4;
    }

    encoded_shellcode
}

/// Test if the shellcode pass the rules provided by the user
/*
fn test_rules(shellcode: String, rules: Vec<String>) -> bool {
    // TODO fonction test rules etape 3
    false
}*/

fn main() {

    // Variables 
    let mut shellcode = String::new();
    let encoding = vec!["sub", "add", "xor"];
    let mut args_good = false;

    // Get the arguments
    let args: Args = argh::from_env();

    // Check if the encoding method exist
    for method in encoding {
        if args.encoding.contains(method){
            args_good = true;
        }
    }

    // Check if the key doesn't exceed the limit
    if args.key > 255 || args.key < 0 {
        args_good = false;
    }

    // Check when auto is enable if a file is provided 
    if args.auto && args_good {
        args_good = !args.file.contains("None");
    }

    // Check if the file exist 
    if !args.file.contains("None") && args_good {
        args_good = Path::new(&args.file).exists();
    }

    // Check shellcode format 

    // Get the shellcode from the user
    println!("shellcode with format \\x..");
    io::stdin()
        .read_line(&mut shellcode)
        .expect("Reading error");

    let shellcode_format = is_right_format(&shellcode);

    // Exit if encoding method doesn't exist
    if !shellcode_format || !args_good {
        process::exit(0x0100);
    }

    // Encode the shellcode
    let encoded_shellcode = encode_shellcode(shellcode, &args.encoding, args.key);

    // Read the file if provided

    println!("Encoded shellcode: {}", encoded_shellcode);

}
