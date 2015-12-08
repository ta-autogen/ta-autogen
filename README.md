This tool creates trusted applications from security sensitive applications using pre-defined set of OpenSSL cryptographic functions and supported annotations.

## Installation guides: ##

* Open-TEE: https://github.com/Open-TEE/project
* PyCParser: https://github.com/eliben/pycparser

## Run tests: ##

To run the test suite provided, configure /etc/opentee.conf ta_dir_path location to point to <tool_source_dir/lib>.

Configure the `opentee_path.conf` file to point the location of the Open-TEE source and emulator. By default, Open-TEE installs itself to `/opt/Open-TEE/`. Use absolute paths, do not use any special variables such as `~` or `$HOME`.

	OPENTEE_PATH = <path to /opt/Open-TEE>
	DIR_PATH = <path to Open-TEE source>

 Launch the Open-TEE emulator and run

	./gentests.sh

The script will create 4 test applications to CA and TA folders.
Compile the tests with `make` and run them with `make check`.

## Tool usage: ##
	
	python parser.py -i <input_file>

Input file parameter is mandatory. You can define additional arguments to the tool, such as output path `-o` and automatic Makefile generation `-m` for compiling sources to Open-TEE. These commands are available from help with `-h` flag.

By default, the generated trusted application source files are included to `/CA` and `/TA` directories to the same filepath that the parser application resides in. If an output path is defined, these directories are created to that path if they do not exist.

The generated makefiles will move the compiled applications to the same level with the CA and TA dirs, to the bin and lib directories. Remember to point the Open-TEE configuration file to the lib directory.

## Code annotation: ##

Supported OpenSSL functions:
* HMAC
* AES_ecb_encrypt
* AES_ctr128_encrypt
* RSA_private_encrypt
* RSA_public_decrypt
* RSA_public_encrypt
* RSA_private_decrypt
* AES_set_encrypt_key
* AES_set_decrypt_key
* RSA_generate_key_ex

These functions are automatically detected and isolated to the trusted application.

Supported annotations:
* `#pragma secure function <function_name>`
* `#pragma secure global <variable_name>`
* `#pragma shared var <parameter_name>`
* `#pragma shared header <header_name>`

Sensitive parts of the program code can be marked with these annotations. The annotations are analyzed by the tool and partitioned to the trusted application.
