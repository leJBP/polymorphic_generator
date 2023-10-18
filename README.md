# Polymorphism shellcode generator

This little project allow the user to create a polymorphic shellcode from a given shellcode.

## Build

You can build the source with `cargo` with the following command:

```cargo build```

## Usage

To use this program you should provide a shellcode with a `\x` format with always two hex characters following the `\x`. Furthermore, there is few options available the following instruction depict all of them.

```

Usage: polymorphic_generator -e <enc> -k <key> [-f <file>] [-a]

Create a polymorphic shellcode from a given shellcode

Options:
  -e, --enc         choose which kind of encryption you want
  -k, --key         choose which kind of encryption you want
  -f, --file        path to the file which contains unauthorized opcodes
  -a, --auto        find automatically the good index for encryption to pass the
                    rules
  --help            display usage information 

```

The file you can provide should contain all the opcodes you doesn't want in your encoded shellcode. To help you in your process there is the automatic key finding option. You can only use this option when you provide a file.

The file should have the following format :

```
09
0a
0b
08 05  (here you doesn't allow your shellcode to have the \x08\x05 combination in your shellcode)
```

Concerning the key the value should be between 0 and 255.

## Thanking

This program is inspired from the Jonathan Salwan version which was written in C.

> https://www.exploit-db.com/papers/13874