# Benchmarking of NIST LWC Finalists on Microcontrollers

This repository hosts the benchmarking framework used to evaluate the software performance of the finalists of the NIST Lightweight Cryptography Standardization Project on microcontrollers.

 - `src`: benchmarking framework source code and the build scripts used to perform the experiments
 - `implementations`: implementations of the **Finalists** gathered from public sources
 - `benchmarks`: benchmark results

# Finalists

More information on finalists can be found [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists).

 - ASCON
 - Elephant
 - GIFT-COFB
 - Grain-128AEAD
 - ISAP
 - PHOTON-Beetle
 - Romulus
 - SPARKLE
 - TinyJambu
 - Xoodyak

# Implementations

More information on implementations included in this effort can be found [here](implementations/). Please note that this repository only includes implementations that have successfully passed known answer tests on at least one of the test platforms listed below. 

# Platforms

Benchmarking was performed on the following development boards:

 - Arduino Uno R3 (ATmega328P)
 - Arduino Nano Every (ATmega4809)
 - Arduino MKR Zero (SAMD21G18A)
 - Arduino Nano 33 BLE (nRF52840)
 - Arduino Due (AT91SAM3X8E)
 - Digilent uC32 (PIC32MX340F512H)
 - Digilent chipKIT MX3 (PIC32MX320F128H)[^1]
 - NodeMCU v2 (ESP8266)
 
[^1]: Digilent uC32 board used with chipKIT MX3 memory profile.

# Results

Benchmarking results can be found [here](benchmarks/).

# Contact

[Lightweight Cryptography Project Webpage](https://csrc.nist.gov/projects/lightweight-cryptography)

[E-mail](mailto:lightweight-crypto@nist.gov)

# Disclaimer

Commercial equipment and software referred to in this website are identified for informational purposes only and does not imply recommendation of or endorsement by the National Institute of Standards and Technology, nor does it imply that the products so identified are necessarily the best available for the purpose.
