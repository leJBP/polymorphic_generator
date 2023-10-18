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

    /// choose which kind of encryption you want
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
        println!("Length of shellcode is not correct");
        ret = false;
    };

    if ret {
        let mut index_start = 0; // Index start opcode
        for _ in 0..shellcode.len() / 4{
            if shellcode.chars().nth(index_start) != Some('\\') {
                ret = false;
            }
            if shellcode.chars().nth(index_start+1) != Some('x') {
                ret = false;
            }
            if !shellcode.chars().nth(index_start+2).unwrap().is_ascii_hexdigit() {
                ret = false;
            }
            if !shellcode.chars().nth(index_start+2).unwrap().is_ascii_hexdigit() {
                ret = false;
            }
            index_start += 4;
        }
    }
    ret
}

/// Encode the shellcode and add the decoder ahead of it
fn encode_shellcode(shellcode: String, decoder: String, key: i16) -> String {
    // TODO fonction encodage

    let start_decoder = "\\xeb\\x11\\x5e\\x31\\xc9\\xb1";
    let end_decoder = "\\x80\\xe9\\x01\\x75\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff";
    let xor_decoder = "\\x80\\x74\\x0e\\xff";
    let add_decoder = "\\x80\\x6c\\x0e\\xff";
    let sub_decoder = "\\x80\\x44\\x0e\\xff";

    shellcode
}

/// Test if the shellcode pass the rules provided by the user
fn test_rules(shellcode: String, rules: Vec<String>) -> bool {
    // TODO fonction test rules
    false
}

/// Read the file which contains the rules and create a list of the rules
fn read_file(path: String) -> bool {
    //TODO fonction lecture règles + mofidier type de retour
    false
}

fn main() {

    // Variables 
    let mut shellcode = String::new();
    let encoding = vec!["sub", "add", "xor"];
    let mut args_good = false;
    let mut shellcode_format = true;

    // Get the arguments
    let args: Args = argh::from_env();

    // Check if the encoding method exist
    for method in encoding {
        if args.encoding.contains(method){
            args_good = true;
        }
    }

    // Check if the key is a positive integer 
    if args.key < 0 && args_good {
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

    shellcode_format = is_right_format(&shellcode);

    // Exit if encoding method doesn't exist
    if !args_good || !shellcode_format {
        process::exit(0x0100);
    }

}
