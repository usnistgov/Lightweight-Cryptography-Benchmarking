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

Currently, the benchmarking is being performed on the following development boards:

 - [Arduino Uno R3 (AVR ATmega328P)](https://store.arduino.cc/usa/arduino-uno-rev3)
 - [Arduino Nano Every (AVR ATmega4809)](https://store.arduino.cc/usa/nano-every)
 - [Arduino MKR Zero (ARM Cortex-M0+)](https://store.arduino.cc/usa/arduino-mkrzero)
 - [Arduino Nano 33 BLE (ARM Cortex-M4)](https://store.arduino.cc/usa/nano-33-ble)
 - [Arduino Due (AARM Cortex-M3)](https://store.arduino.cc/products/arduino-due)
 - [Digilent uC32 (PIC32MX340F512H)](https://store.digilentinc.com/uc32-arduino-programmable-pic32-microcontroller-board-limited-time/)
 - [Espressif ESP8266 (Tensilica L106)](https://www.espressif.com/en/products/socs/esp8266)

# Results

The latest benchmarking results can be found [here](benchmarks/).

# Contact

[Lightweight Cryptography Project Webpage](https://csrc.nist.gov/projects/lightweight-cryptography)

[E-mail](mailto:lightweight-crypto@nist.gov)

# Disclaimer

Commercial equipment and software referred to in this website are identified for informational purposes only and does not imply recommendation of or endorsement by the National Institute of Standards and Technology, nor does it imply that the products so identified are necessarily the best available for the purpose.
