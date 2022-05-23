## Requirements

 - [Python](https://www.python.org)
 - [PlatformIO](https://platformio.org)
 - PlatformIO *Board* and *Platform* files for the target devices.
 - [Visual Studio Code](https://code.visualstudio.com/) This is optional but quite handy if you want to work with an IDE. After installing the PlatformIO extension, you can also install the board and platform files from the IDE for the microcontrollers, which will be required to build the applications.
  - For batch processing with the build script, the implementations must be in a folder named `implementations` that is two levels above this folder. If you clone the repository, the implementations will be in the correct location.

The benchmarking framework was developed and tested on Windows 10. It does not use a Windows specific feature, though. So, in principle you might be able to use it by meeting the above requirements. You can let us know if you have (or don't have) any issues on different platforms.

You need to make sure that the `PATH` environment variable is set for running `python` and `platformio` commands work from the current path. On Windows 10, the PlatformIO binaries are located at `/c/Users/[username]/.platformio/penv/Scripts/`.

If your system has python installed as `python3`, you can define the environment variable `PYTHON`. Similarly, you can define `PLATFORMIO`. The defaults are `python` and `platformio.exe`.

Typical setting for Linux:
````
export PYTHON=python3;export PLATFORMIO=platformio
````

## Experiments and Operating Modes

The framework is designed to process implementations and experiments one at a time. The implementation that is to be benchmarked must be copied under the `src\iut` folder. There must be exactly one implementation in this folder, otherwise the build will fail.

The experiment that is going to be carried out is defined in the `lwc_mode.h` file which must be located in the `src` folder. The file must contain exactly one of the following preprocessor definitions:

| Symbol | Experiment Type | |
| :------ | :------: | :----- |
| LWC_MODE_GENKAT_AEAD | KAT | Generates KAT file for the AEAD implementation.|
| LWC_MODE_GENKAT_HASH | KAT | Generates KAT file for the Hash implementation.|
| LWC_MODE_USE_AEAD_ENCRYPT | Code Size | Only AEAD encryption function is used.
| LWC_MODE_USE_AEAD_DECRYPT | Code Size | Only AEAD decryption function is used.
| LWC_MODE_USE_AEAD_BOTH | Code Size | AEAD encryption and decryption functions are both used.
| LWC_MODE_USE_HASH | Code Size | Hash function is invoked once.|
| LWC_MODE_TIMING_AEAD | Timing | Performs timing measurements for the AEAD implementation.
| LWC_MODE_TIMING_HASH | Timing | Performs timing measurements for the Hash implementation.|


The build script that is explained in the next section creates a new `lwc_mode.h` file for each experiment before the build. Build will fail if there is no `lwc_mode.h` in the `src` folder or it does not contain one of the above definitions.

## Building with the script `build.sh`

The bash script `build.sh` processes the implementations by building them within the framework and depending on the experiment being done it uploads the program to the target device and captures the program output. At a minimum, the script must be provided a target platform name, which can be one of the platforms defined in the `platformio.ini` file. Currently, the valid platform names are `{mkrzero, uno, f411re, nano33ble, nano_every}`.

By default, the script processes all implementations and does all the experiments. However, the behaviour can be changed by providing command line arguments, for instance to process only one or more *submissions*, or *variants*, as well as performing select experiments. Running the script with no arguments gives an explanation of the set of available command line arguments. Some examples:


``` bash
./build.sh --target mkrzero # Processes all implementations for all experiments
```

``` bash
./build.sh --target mkrzero --experiment "kat timing" # Perform only KAT and Timing experiments on all implementations (skip code size experiments)
```

``` bash
./build.sh --target mkrzero --submission "ace ascon comet" # Process all implementations of the submissions ACE, ASCON, and COMET
```

``` bash
./build.sh --target mkrzero --primary --aead # Process only implementations of primary AEAD variants
```

``` bash
./build.sh --target mkrzero --impl ref --experiment kat # Perform KAT verification for all reference implementations
```


**Note:** For code size experiments, the device is not required since the code sizes are extracted from the build output. However, for *KAT* and *Timing* experiments, the program must run on the device and the output needs to be captured.

### Results

The build script will save the results in the `outputs` folder. The results for each target platform are stored under their respective folders.
