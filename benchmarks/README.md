### Benchmark Results

This page contains the benchmark results grouped with respect to the microcontroller and functionality (AEAD or Hash). Each result file contains code size and timing measurements for all the implementations that have been benchmarked. Descriptions of the column names in the `csv` files are as follows:

 - `submission` : submission name
 - `variant` : variant name
 - `implementation` : implementation name (matches the name of the folder that contains the implementation)
 - `primary` : indicates whether the variant is primary or not
 - `config` : optimization flag used in compilation (one of Os, O1, O2, O3)
 - `size` : flash size (in bytes) 
 - `enc(x:y)` : timing measurement (in microseconds or cycles) for AEAD encryption of `x` bytes of associated data and `y` bytes of message
 - `dec(x:y)` : timing measurement (in microseconds or cycles) for AEAD decryption whose input is `x` bytes of associated data and the ciphertext obtained from encrypting `x` bytes of associated data and `y` bytes of message
 - `h(x)` : timing measurement (in microseconds or cycles) for hashing `x` bytes of message

### Notes

 - An implementation compiled with a certain flag does not appear in the result file if any of the followings occur:
    * Compilation failure
    * Build failure due to large program size
 - If the build succeeds then there will be an entry for that implementation and compilation flag in the result file. However, for some of the implementations the timing measurements could not be obtained for some/all inputs. These entries are marked with a `-` symbol. This can be due to the following reasons:
    * Decryption function returning an error code
    * Decryption function returning an incorrect message length
    * Decryption function not recovering the message
    * Program crash
 - In the case of a decryption failure, the timing measurement is not recorded but the experiment proceeds with the next input. On the contrary, when the program crashes, the measurements for the remaining inputs cannot be performed.
