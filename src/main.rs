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

fn encode_shellcode(shellcode: String, decoder: String, key: i16) -> String {
    // TODO fonction encodage
    shellcode
}

fn test_rules(shellcode: String, rules: Vec<String>) -> bool {
    // TODO fonction test rules
    false
}

fn read_file(path: String) -> bool {
    //TODO fonction lecture règles + mofidier type de retour
    false
}

fn main() {

    /* Variables */
    let mut shellcode = String::new();
    let encoding = vec!["sub", "add", "xor"];
    let mut args_good = false;

    /* Get the arguments */
    let args: Args = argh::from_env();

    /* Check if the encoding method exist */
    for method in encoding {
        if args.encoding.contains(method){
            args_good = true;
        }
    }

    /* Check if the key is a positive integer */
    if args.key < 0 && args_good {
        args_good = false;
    }

    /* Check when auto is enable if a file is provided */
    if args.auto && args_good {
        args_good = !args.file.contains("None");
    }

    /* Check if the file exist */
    if !args.file.contains("None") && args_good {
        args_good = Path::new(&args.file).exists();
    }

    /* Exit if encoding method doesn't exist */
    if !args_good {
        process::exit(0x0100);
    }

    /* Get the shellcode from the user */
    println!("shellcode with format \\x..");
    io::stdin()
        .read_line(&mut shellcode)
        .expect("Reading error");

}
