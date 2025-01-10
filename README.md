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
struct LDE_S500_U_t {};
struct LDE_S025_B_t {};
struct LDE_S050_B_t {};
struct LDE_S100_B_t {};
struct LDE_S250_B_t {}; // Example, LDES250BF6S
struct LDE_S500_B_t {};
```

## DEPENDENCIES - CODING LANGUAGE/OS/COMPILATION TARGET/COMPILER:
  - C++20
  - mbed-os-6.15.1
  - NUCLEO F767ZI
  - GCC ARM 10.3.1
    - arm-none-eabi-g++ (GNU Arm Embedded Toolchain 10.3-2021.10) 10.3.1 20210824 (release)
    - gcc-arm-none-eabi-10.3-2021.10/bin

```console 
(py37-venv) nuertey@nuertey-PC:/.../Nuertey-LDESeries-Mbed$ mbed config -L

[mbed] Global config:
GCC_ARM_PATH=.../opt/gcc-arm-none-eabi-10.3-2021.10/bin

[mbed] Local config (/.../Nuertey-LDESeries-Mbed):
TARGET=nucleo_f767zi
TOOLCHAIN=GCC_ARM

(py37-venv) nuertey@nuertey-PC:/.../Nuertey-LDESeries-Mbed$ cd mbed-os/

(py37-venv) nuertey@nuertey-PC:/.../Nuertey-LDESeries-Mbed/mbed-os$ 

(py37-venv) nuertey@nuertey-PC:/.../Nuertey-LDESeries-Mbed/mbed-os$ mbed ls

[mbed] Working path "/.../Nuertey-LDESeries-Mbed/mbed-os" (library)
[mbed] Program path "/.../Nuertey-LDESeries-Mbed"

mbed-os (#2eb06e762085, tags: mbed-os-6.15.1, mbed-os-6.15.1-rc1)

```
 
## Compilation Output (Mbed CLI 1)

```console
...
Compile [ 99.9%]: mbed_crc_api.c
Compile [100.0%]: stm32f7xx_hal_smbus.c
Compile [100.0%]: gpio_api.c
Link: Nuertey-LDESeries-Mbed
Elf2Bin: Nuertey-LDESeries-Mbed
| Module               |           .text |       .data |          .bss |
|----------------------|-----------------|-------------|---------------|
| NuerteyNTPClient.o   |     4042(+4042) |       4(+4) |     101(+101) |
| Utilities.o          |     9592(+9592) |       4(+4) |     449(+449) |
| [fill]               |       308(+308) |     21(+21) |       82(+82) |
| [lib]/c.a            |   81456(+81456) | 2574(+2574) |       97(+97) |
| [lib]/gcc.a          |     7416(+7416) |       0(+0) |         0(+0) |
| [lib]/m.a            |       264(+264) |       0(+0) |         0(+0) |
| [lib]/misc           |       188(+188) |       4(+4) |       28(+28) |
| [lib]/nosys.a        |         32(+32) |       0(+0) |         0(+0) |
| [lib]/stdc++.a       | 174244(+174244) |   145(+145) |   5720(+5720) |
| main.o               |     3726(+3726) |       4(+4) |     261(+261) |
| mbed-os/cmsis        |     9890(+9890) |   168(+168) | 14400(+14400) |
| mbed-os/connectivity |   54186(+54186) |   103(+103) | 24059(+24059) |
| mbed-os/drivers      |     1146(+1146) |       0(+0) |   1852(+1852) |
| mbed-os/events       |     1776(+1776) |       0(+0) |   3104(+3104) |
| mbed-os/hal          |     1528(+1528) |       8(+8) |     114(+114) |
| mbed-os/platform     |     7166(+7166) |   340(+340) |     493(+493) |
| mbed-os/rtos         |     1280(+1280) |       0(+0) |         8(+8) |
| mbed-os/targets      |   17476(+17476) |       9(+9) |   1352(+1352) |
| Subtotals            | 375716(+375716) | 3384(+3384) | 52120(+52120) |
Total Static RAM memory (data + bss): 55504(+55504) bytes
Total Flash memory (text + data): 379100(+379100) bytes

Image: ./BUILD/NUCLEO_F767ZI/GCC_ARM-MY_PROFILE/Nuertey-LDESeries-Mbed.bin

```

## Tested Target (and Peripheral):

Lacking an actual LDE Series pressure sensor on my workbench for testing, I am left to appeal to you OEMs or better-equipped IoT hobbyists out there. If you have a spare LDE Series pressure sensor dev board that can be connected to my STM32F767-ZI [Nucleo-144], kindly send me an email at nuertey_odzeyem@hotmail.com 


## License
MIT License

Copyright (c) 2021 Nuertey Odzeyem

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
