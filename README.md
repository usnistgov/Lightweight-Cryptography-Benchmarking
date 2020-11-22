# Benchmarking of Lightweight Cryptographic Algorithms on Microcontrollers

This repository hosts the benchmarking framework used to evaluate the software performance of the candidates of the NIST Lightweight Cryptography Standardization Project on microcontrollers.

 - `src`: benchmarking framework source code and the build scripts used to perform the experiments.
 - `implementations`: implementation of the **Round 2 Candidates** and is gathered from publicly available implementations of the candidates.
 - `benchmarks`: (currently empty) will be populated by the benchmark results after they have been completed and verified.

# Implementations

The table below gives the distribution of the benchmarked implementations with respect to algorithm type and programming language:

|	Language	|	AEAD	|	Hash	|	Total	|
|	-	|	-	|	-	|	-	|
|	C	|	161	|	41	|	202	|
|	C / AVR	|	73	|	15	|	88	|
|	C / ARM / AVR | 9	|	4	|	13	|
|	ARM	|	35	|	4	|	39	|
|	AVR	|	19	|	16	|	35	|
|	**Total**	|	297	|	80	|	377	|

More information on implementations can be found [here](implementations/).

### Submitting new implementations

The recommended way of requesting a new implementation to be included in the benchmarking is to make it publicly accessible and announce via the [LWC Forum](lwc-forum@list.nist.gov).

# Platforms

Currently, the benchmarking is being performed on the following development boards:

 - [Arduino Uno R3 (AVR ATmega328P)](https://store.arduino.cc/usa/arduino-uno-rev3)
 - [Arduino Nano Every (AVR ATmega4809)](https://store.arduino.cc/usa/nano-every)
 - [Arduino MKR Zero (ARM Cortex-M0+)](https://store.arduino.cc/usa/arduino-mkrzero)
 - [Arduino Nano 33 BLE (ARM Cortex-M4F)](https://store.arduino.cc/usa/nano-33-ble)
 - [Digilent uC32 (PIC32MX340F512H)](https://store.digilentinc.com/uc32-arduino-programmable-pic32-microcontroller-board-limited-time/)
 - [Espressif ESP8266 (Tensilica L106)](https://www.espressif.com/en/products/socs/esp8266)

# Results

A presentation summarizing the benchmark results was made in the [NIST Lightweight Cryptography Workshop 2020](https://csrc.nist.gov/Events/2020/lightweight-cryptography-workshop-2020):

[Benchmarking Round 2 Candidates on Microcontrollers](https://csrc.nist.gov/CSRC/media/Presentations/benchmarking-round-2-candidates/images-media/session-1-calik-benchmarking-second-round-cadidates.pdf)

# Contact

[Lightweight Cryptography Project Webpage](https://csrc.nist.gov/projects/lightweight-cryptography)

[E-mail](lightweight-crypto@nist.gov)

# Disclaimer

Commercial equipment and software referred to in this paper are identified for informational purposes only and does not imply
recommendation of or endorsement by the National Institute of Standards and Technology, nor does it imply that the products so identified
are necessarily the best available for the purpose.
