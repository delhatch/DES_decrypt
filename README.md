# DES_decrypt

Author

Del Hatch

** DES decryption software

The purpose of this project is to create an easy-to-run executable that will perform DES decryption on a binary file.

The output is written to a user-specified binary file.

A pre-compiled executable for Windows machines is provided.

** Inputs

The command-line executable requires three parameters, in this order:

1) The name of the file containing the DES key. This must be an 8-byte long hex file. See the file key.hex as an example.

2) The name of the encrypted data input file. This must be a binary file. See the file test.hex as an example.

3) The name of an output file. The cleartext results will be written to this file, as binary data. NOTE: This program will over-write (delete) any pre-existing file with the same name.

EXAMPLE:

>des_decrypt.exe key.hex test.hex output.hex

** Miscellaneous

The provided test.hex file, when decrypted with the included key.hex file, will result in clear text of all zeros.

This is the first decryption test vector in the included des_test_vectors.txt file. Other test vectors are included in that file.






