# Nuertey-LDESeries-Mbed - Type-Driven SPI Framing Protocol For First Sensor AG LDE Series Low Pressure Sensor

This sensor driver is targetted for the ARM Mbed platform and encapsulates the digital SPI interface and accompanying protocol as presented by the LDE Series of digital low differential pressure sensors.

For ease of use, power, flexibility and readability of the code, the protocol has been written in a modern C++ (C++20) metaprogrammed and templatized class-encapsulated idiom. 

A goal of the design is to encourage and promote zero-cost abstractions, even and especially so, in the embedded realms. Note that care has been taken to deduce and glean those abstractions from the problem-domain itself. And in the doing so, care has also been taken to shape the abstractions logically. 

From its datasheet, the First Sensor AG LDE Series sensor is characterized as:

"The LDE differential low pressure sensors are based on thermal flow measurement of gas through a micro-flow channel integrated within the sensor chip. The innovative LDE technology features superior sensitivity especially for ultra low pressures. The extremely low gas flow through the sensor ensures high immunity to dust contamination, humidity and long tubing compared to other flow-based pressure sensors."

- https://www.first-sensor.com/cms/upload/datasheets/DS_Standard-LDE_E_11815.pdf

![LDE Series Sensor Driver Class Diagram](https://github.com/nuertey/RandomArtifacts/blob/master/NuerteyLDESeriesDevice2.png?raw=true)

Quoting the above datasheet further:
 
    Features
 
     – Ultra-low pressure ranges from 25 to 500 Pa (0.1 to 2 in H2O) 
     – Pressure sensor based on thermal microflow measurement
     – High flow impedance
     – very low flow-through leakage
     – high immunity to dust and humidity
     – no loss in sensitivity using long tubing
     – Calibrated and temperature compensated
     – Unique offset autozeroing feature ensuring superb long-term stability
     – Offset accuracy better than 0.2% FS
     – Total accuracy better than 0.5% FS typical
     – On-chip temperature sensor
     – Analog output and digital SPI interface
     – No position sensitivity
 
   Certificates
 
     – Quality Management System according to EN ISO 13485 and EN ISO 9001
     – RoHS and REACH compliant
 
   Media compatibility
 
     – Air and other non-corrosive gases
 
   Applications
 
     Medical
     – Ventilators
     – Spirometers
     – CPAP
     – Sleep diagnostic equipment
     – Nebulizers
     – Oxygen conservers/concentrators
     – Insufflators/endoscopy
 
     Industrial
     – HVAC
     – VAV
     – Filter monitoring
     – Burner control
     – Fuel cells
     – Gas leak detection
     – Gas metering
     – Fume hood
     – Instrumentation
     – Security systems

## Sensor Type Defines and Attributes


```c++
// \"
// Series     Pressure Range                    Calibration
// 
// LDE        S025     25 Pa (0.1 in H2O)       B Bidirectional
//            S050     50 Pa (0.2 in H2O)       U Unidirectional
//            S100    100 Pa (0.4 in H2O)
//            S250    250 Pa (1 in H2O)
//            S500    500 Pa (2 in H2O)
// \"

// Metaprogramming types to distinguish the particular LDE series 
// pressure sensor incarnation:
struct LDE_S025_U_t {};
struct LDE_S050_U_t {};
struct LDE_S100_U_t {};
struct LDE_S250_U_t {}; // Example, LDES250UF6S. 
struct LDE_S500_U_t {}; // Example, LDES500UF6S.
struct LDE_S025_B_t {};
struct LDE_S050_B_t {};
struct LDE_S100_B_t {};
struct LDE_S250_B_t {}; // Example, LDES250BF6S
struct LDE_S500_B_t {};
```

## DEPENDENCIES - CODING LANGUAGE/OS/COMPILATION TARGET/COMPILER:
  - C++20
  - mbed-ce
    - https://github.com/mbed-ce/mbed-os.git
    - commit 8a8bc9ca361d1cc8590832c35298551ec2d265cc (HEAD -> master, origin/master, origin/HEAD)
  - NUCLEO F767ZI
  - GCC ARM 14.2.1 (GNU Arm Embedded Toolchain)
    - arm-none-eabi-g++ (Arm GNU Toolchain 14.2.Rel1 (Build arm-14.52)) 14.2.1 20241119
    - arm-none-eabi-gcc (Arm GNU Toolchain 14.2.Rel1 (Build arm-14.52)) 14.2.1 20241119
 
## Compilation Output (Mbed CLI 1)

```console
(py312-venv) osboxes@osboxes:~/Workspace/mbed-ce-Nuertey-LDESeries/build$ cmake .. -GNinja -DMBED_TARGET=NUCLEO_F767ZI -DCMAKE_BUILD_TYPE=Develop
-- Found Python3: /home/osboxes/Workspace/mbed-ce-Nuertey-LDESeries/mbed-os/venv/bin/python3 (found version "3.12.7") found components: Interpreter
-- Mbed: First CMake run detected, generating configs...
INFO: Found existing Mbed program at path '/home/osboxes/Workspace/mbed-ce-Nuertey-LDESeries'
Summary of available memory banks:
Target RAM banks: -----------------------------------------------------------
0. IRAM1, start addr 0x20020000, size 384.0 KiB
1. IRAM2, start addr 0x20000000, size 128.0 KiB

Target ROM banks: -----------------------------------------------------------
0. ROM_VIA_ITCM_BUS, start addr 0x00200000, size 2.0 MiB
1. ROM_VIA_AXIM_BUS, start addr 0x08000000, size 2.0 MiB

mbed_config.cmake has been generated and written to '/home/osboxes/Workspace/mbed-ce-Nuertey-LDESeries/build/mbed_config.cmake'
CMake Warning (dev) at mbed-os/tools/cmake/app.cmake:37 (enable_language):
  project() should be called prior to this enable_language() call.
Call Stack (most recent call first):
  CMakeLists.txt:6 (include)
This warning is for project developers.  Use -Wno-dev to suppress it.

-- The C compiler identification is GNU 14.2.1
-- The CXX compiler identification is GNU 14.2.1
-- The ASM compiler identification is GNU
-- Found assembler: /usr/local/gcc-arm/bin/arm-none-eabi-gcc
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/local/gcc-arm/bin/arm-none-eabi-gcc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/local/gcc-arm/bin/arm-none-eabi-g++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Mbed: Loading default upload method configuration from /home/osboxes/Workspace/mbed-ce-Nuertey-LDESeries/mbed-os/targets/upload_method_cfg/NUCLEO_F767ZI.cmake
-- Mbed: Not building any Mbed OS tests.
-- Mbed: Code upload enabled via upload method MBED
-- Configuring done (2.5s)
-- Generating done (0.2s)
-- Build files have been written to: /home/osboxes/Workspace/mbed-ce-Nuertey-LDESeries/build
(py312-venv) osboxes@osboxes:~/Workspace/mbed-ce-Nuertey-LDESeries/build$ ninja
[1/255] Generating ../mbed-nucleo-f767zi.link_script.ld
Preprocess linker script: STM32F767xI.ld -> mbed-nucleo-f767zi.link_script.ld
[255/255] Linking CXX executable Nuertey-LDESeries.elf
-- built: /home/osboxes/Workspace/mbed-ce-Nuertey-LDESeries/build/Nuertey-LDESeries.bin
-- built: /home/osboxes/Workspace/mbed-ce-Nuertey-LDESeries/build/Nuertey-LDESeries.hex
/home/osboxes/Workspace/mbed-ce-Nuertey-LDESeries/mbed-os/tools/python/memap/memap.py:63: DeprecationWarning: the 'HEADER' constant is deprecated, use the 'HRuleStyle' and 'VRuleStyle' enums instead
  from prettytable import PrettyTable, HEADER
| Module                           |           .text |       .data |          .bss |
|----------------------------------|-----------------|-------------|---------------|
| CMakeFiles/Nuertey-LDESeries.dir |     3451(+3451) |       4(+4) |     244(+244) |
| [fill]                           |       426(+426) |     17(+17) |       42(+42) |
| [lib]/c.a                        | 126451(+126451) | 4071(+4071) |     862(+862) |
| [lib]/gcc.a                      |     7548(+7548) |       0(+0) |         0(+0) |
| [lib]/misc                       |       292(+292) |     12(+12) |       25(+25) |
| [lib]/stdc++.a                   | 227069(+227069) |   172(+172) |   4328(+4328) |
| mbed-os/CMakeFiles               |   44566(+44566) |   444(+444) | 10059(+10059) |
| Subtotals                        | 409803(+409803) | 4720(+4720) | 15560(+15560) |
Total Static RAM memory (data + bss): 20280(+20280) bytes
Total Flash memory (text + data): 414523(+414523) bytes

RAM Bank IRAM1: 0(+0)/393216 bytes used, 0.0% (+0.0%) used
RAM Bank IRAM2: 20536(+0)/131072 bytes used, 15.7% (+0.0%) used
ROM Bank ROM_VIA_ITCM_BUS: 427807(+0)/2097152 bytes used, 20.4% (+0.0%) used
ROM Bank ROM_VIA_AXIM_BUS: 0(+0)/2097152 bytes used, 0.0% (+0.0%) used

(py312-venv) osboxes@osboxes:~/Workspace/mbed-ce-Nuertey-LDESeries/build$ ls -ll
total 32132
-rw-rw-r--  1 osboxes osboxes 11589303 Jan 12 03:44 build.ninja
-rw-rw-r--  1 osboxes osboxes    21846 Jan 12 03:44 CMakeCache.txt
drwxrwxr-x  6 osboxes osboxes     4096 Jan 12 03:44 CMakeFiles
-rw-rw-r--  1 osboxes osboxes     2073 Jan 12 03:44 cmake_install.cmake
-rw-rw-r--  1 osboxes osboxes    29994 Jan 12 03:44 mbed_config.cmake
-rw-rw-r--  1 osboxes osboxes     2704 Jan 12 03:45 mbed-nucleo-f767zi.link_script.ld
drwxrwxr-x 15 osboxes osboxes     4096 Jan 12 03:44 mbed-os
-rw-rw-r--  1 osboxes osboxes     4173 Jan 12 03:44 memory_banks.json
-rwxrwxr-x  1 osboxes osboxes   412940 Jan 12 03:45 Nuertey-LDESeries.bin
-rwxrwxr-x  1 osboxes osboxes  5067772 Jan 12 03:45 Nuertey-LDESeries.elf
-rw-rw-r--  1 osboxes osboxes 15077405 Jan 12 03:45 Nuertey-LDESeries.elf.map
-rw-rw-r--  1 osboxes osboxes        0 Jan 12 03:45 Nuertey-LDESeries.elf.map.old
-rw-rw-r--  1 osboxes osboxes  1161563 Jan 12 03:45 Nuertey-LDESeries.hex


```

## Execution Output Snippet: 

> [!CAUTION]
> Further debug of sensor circuit wiring and testing continues... 

```shell-session

nuertey@nuertey-PC-LL850RSB:~$ kermit -c
Connecting to /dev/ttyACM0, speed 115200
 Escape character: Ctrl-\ (ASCII 28, FS): enabled
Type the escape character followed by C to get back,
or followed by ? to see other options.
----------------------------------------------------


Nuertey-LDESeries-Mbed - Beginning... 

True differential pressure as measured in a Dry Air atmosphere:
    ->0.00 Pa

True differential pressure as measured in an Oxygen Gas atmosphere (O2):
    -> 0.00 Pa

True differential pressure as measured in a Nitrogen Gas atmosphere (N2):
    -> 0.00 Pa

True differential pressure as measured in an Argon Gas atmosphere (Ar):
    -> 0.00 Pa

True differential pressure as measured in a Carbon Dioxide atmosphere (CO2):
    -> 0.00 Pa

On-chip temperature sensor:
    -> 0.00 °C
On-chip temperature sensor:
    -> 32.00 °F
On-chip temperature sensor:
    -> 273.00 K
True differential pressure as measured in a Dry Air atmosphere:
    ->0.00 Pa

True differential pressure as measured in an Oxygen Gas atmosphere (O2):
    -> 0.00 Pa

True differential pressure as measured in a Nitrogen Gas atmosphere (N2):
    -> 0.00 Pa

True differential pressure as measured in an Argon Gas atmosphere (Ar):
    -> 0.00 Pa

True differential pressure as measured in a Carbon Dioxide atmosphere (CO2):
    -> 0.00 Pa

On-chip temperature sensor:
    -> 0.00 °C
On-chip temperature sensor:
    -> 32.00 °F
On-chip temperature sensor:
    -> 273.00 K
True differential pressure as measured in a Dry Air atmosphere:
    ->0.00 Pa

True differential pressure as measured in an Oxygen Gas atmosphere (O2):
    -> 0.00 Pa

True differential pressure as measured in a Nitrogen Gas atmosphere (N2):
    -> 0.00 Pa

True differential pressure as measured in an Argon Gas atmosphere (Ar):
    -> 0.00 Pa

True differential pressure as measured in a Carbon Dioxide atmosphere (CO2):
    -> 0.00 Pa

On-chip temperature sensor:
    -> 0.00 °C
On-chip temperature sensor:
    -> 32.00 °F
On-chip temperature sensor:
    -> 318.55 K
True differential pressure as measured in a Dry Air atmosphere:
    ->0.00 Pa

True differential pressure as measured in an Oxygen Gas atmosphere (O2):
    -> 0.00 Pa

True differential pressure as measured in a Nitrogen Gas atmosphere (N2):
    -> 0.00 Pa

True differential pressure as measured in an Argon Gas atmosphere (Ar):
    -> 0.00 Pa

True differential pressure as measured in a Carbon Dioxide atmosphere (CO2):
    -> 0.00 Pa

On-chip temperature sensor:
    -> 0.00 °C
On-chip temperature sensor:
    -> 32.00 °F
On-chip temperature sensor:
    -> 273.00 K
True differential pressure as measured in a Dry Air atmosphere:
    ->0.00 Pa

True differential pressure as measured in an Oxygen Gas atmosphere (O2):
    -> 0.00 Pa

True differential pressure as measured in a Nitrogen Gas atmosphere (N2):
    -> 0.00 Pa

True differential pressure as measured in an Argon Gas atmosphere (Ar):
    -> 0.00 Pa

True differential pressure as measured in a Carbon Dioxide atmosphere (CO2):
    -> 0.00 Pa

On-chip temperature sensor:
    -> 0.00 °C
On-chip temperature sensor:
    -> 32.00 °F
On-chip temperature sensor:
    -> 273.00 K

Communications disconnect (Back at nuertey-PC-LL850RSB)
----------------------------------------------------
C-Kermit 9.0.302 OPEN SOURCE:, 20 Aug 2011, for Linux+SSL+KRB5 (64-bit)
 Copyright (C) 1985, 2011,
  Trustees of Columbia University in the City of New York.
Type ? or HELP for help.
(/home/nuertey/) C-Kermit>


```

## Pictures Of STM32F767 MCU, the Running Code and LDES500UF6S Pressure Sensor in Action

![alt text](https://github.com/nuertey/RandomArtifacts/blob/master/IMG_0003.JPG?raw=true)

![alt text](https://github.com/nuertey/RandomArtifacts/blob/master/IMG_0004.JPG?raw=true)

![alt text](https://github.com/nuertey/RandomArtifacts/blob/master/IMG_0005.JPG?raw=true)

![alt text](https://github.com/nuertey/RandomArtifacts/blob/master/IMG_0006.JPG?raw=true)

![alt text](https://github.com/nuertey/RandomArtifacts/blob/master/IMG_0007.JPG?raw=true)

![alt text](https://github.com/nuertey/RandomArtifacts/blob/master/IMG_0009.JPG?raw=true)

![alt text](https://github.com/nuertey/RandomArtifacts/blob/master/IMG_0010.JPG?raw=true)


## License
MIT License

Copyright (c) 2025 Nuertey Odzeyem

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
