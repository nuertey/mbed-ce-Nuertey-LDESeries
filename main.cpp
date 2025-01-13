/***********************************************************************
* @file      main.cpp
*
*    An ARM Mbed application that illustrates how a NUCLEO-F767ZI can be 
*    connected to a First Sensor AG LDE Series low pressure sensor device. 
*
* @brief   Test First Sensor AG LDE Series low pressure sensor device.
* 
* @note    
*
* @warning Note that the I/O pins of STM32 NUCLEO-F767ZI are 3.3 V 
*          compatible instead of 5 V for say, the Arduino Uno V3 
*          microcontroller.
* 
*          Furthermore, the STM32 GPIO pins are not numbered 1-64; rather, 
*          they are named after the MCU IO port that they are controlled
*          by. Hence PA_5 is pin 5 on port A. This means that physical
*          pin location may not be related to the pin name. Consult 
*          the "Extension connectors" sub-chapter of the "Hardware 
*          layout and configuration" chapter of the STM32 Nucleo-144 
*          boards UM1974 User manual (en.DM00244518.pdf) to know where
*          each pin is located. Note that all those pins shown can be 
*          used as GPIOs, however most of them also have alternative 
*          functions which are indicated on those diagrams.
*
* @author    Nuertey Odzeyem
* 
* @date      January 10th, 2025
*
* @copyright Copyright (c) 2025 Nuertey Odzeyem. All Rights Reserved.
***********************************************************************/
#include "NuerteyLDESeriesDevice.h"

#define LED_ON  1
#define LED_OFF 0

// \" 3.1 Simple point-to-point connection
//
// In the case of single LDE/LME 5 V devices (and LDE 3 V devices with a
// microcontroller capable of driving the SPI bus with 2 mA per line),
// the pins for the SPI bus may be directly connected between the sensor
// and the microcontroller. No further external components are necessary.
// The use of pull-up resistors is not recommended. \"
//
// https://www.first-sensor.com/cms/upload/appnotes/AN_LDE-LME-SPI-bus_E_11168.pdf

// \" Specification notes (cont.)
//
// (17) For correct operation of LDE…3... devices, the device driving
// the SPI bus must have a minimum drive capability of ±2 mA. \"

// \" Care should be taken to ensure that the sensor is properly 
// connected to the master microcontroller. Refer to the manufacturer's
// datasheet for more information regarding physical connections. \"

// \" Application circuit
//
// The use of pull-up resistors is generally unnecessary for SPI as most
// master devices are configured for push-pull mode. If pull-up resistors
// are required for use with 3 V LDE devices, however, they should be 
// greater than 50 kW.
//
// ...
//
// If these series resistors are used, they must be physically placed as
// close as possible to the pins of the master and slave devices. \"

// Connector: CN7 
// Pin      : 14 
// Pin Name : D11       * Arduino-equivalent pin name
// STM32 Pin: PA7
// Signal   : SPI_A_MOSI/TIM_E_PWM1
//
// Connector: CN7 
// Pin      : 12 
// Pin Name : D12       * Arduino-equivalent pin name
// STM32 Pin: PA6
// Signal   : SPI_A_MISO 
//
// Connector: CN7 
// Pin      : 10 
// Pin Name : D13        * Arduino-equivalent pin name
// STM32 Pin: PA5
// Signal   : SPI_A_SCK
//
// Connector: CN7 
// Pin      : 16 
// Pin Name : D10       * Arduino-equivalent pin name
// STM32 Pin: PD14
// Signal   : SPI_A_CS/TIM_B_PWM3

// TBD, do actually connect these pins to the sensor once it arrives.
//
//        PinName mosi
//        PinName miso
//        PinName sclk
//        PinName ssel
NuerteyLDESeriesDevice g_LDESeriesDevice(D11, D12, D13, D10); 

// TBD Nuertey Odzeyem; FYI: Innovations for future usage:

// "The current pin name feature is focused on two specific areas:
// 
// General pin names
// This defines the usage of LEDs, Buttons, and UART as an interface to
// the PC. All boards are expected to be compliant with this. 
// 
// Arduino Uno connector
// This is a very popular connector that facilitates extending Mbed 
// boards with components. The standard helps to identify boards that
// have a connector compliant with the physical requirements as well as
// the required MCU signals available on it (e.g. Digital input, output,
// ADC, I2C, SPI, UART). Boards that include a definition of the legacy
// Arduino connector in targets.json are expected to be reviewed, 
// migrated and tested accordingly, and eventually indicate this using
// the “ARDUINO_UNO” field. 
// 
// For example in the past, a SPI driver was initialised using:
// 
// SPI spi(D11, D12, D13); // mosi, miso, sclk
//
// Now when using the signals on the Arduino Uno connector:
//
// SPI spi(ARDUINO_UNO_SPI_MOSI, ARDUINO_UNO_SPI_MISO, ARDUINO_UNO_SPI_SCK); "

// https://os.mbed.com/blog/entry/Improved-Pin-names-for-Mbed-boards/
        
// As per my ARM NUCLEO-F767ZI specs:        
DigitalOut        g_LEDGreen(LED1);
DigitalOut        g_LEDBlue(LED2);
DigitalOut        g_LEDRed(LED3);

int main()
{
    printf("\r\n\r\nNuertey-LDESeries-Mbed - Beginning... \r\n\r\n");
    
	// Allow the sensor device time to stabilize from powering on 
	// and time enough for it to accumulate continuously measuring
	// temperature and pressure. Ergo:
	//
	// \" Power-on time 25 ms. \"
	//
	// \" When powered on, the sensor begins to continuously measure
	// pressure. \"
	ThisThread::sleep_for(25ms);  

	// Do not return from main() as in Embedded Systems, there is nothing
	// (conceptually) to return to. Otherwise the processor would halt and 
	// a crash will occur!    
    while (true)
    {
		// Indicate with LEDs that we are commencing.
		g_LEDBlue = LED_ON;
		g_LEDGreen = LED_ON;      

		// Poll and query temperature and pressure measurements from LDE
		// sensor part number, LDES250BF6S, for example:
		printf("True differential pressure as measured in a Dry Air atmosphere:\n\t->%s Pa\n\n", 
			TruncateAndToString<double>(
			g_LDESeriesDevice.GetPressure<LDE_S250_B_t, DryAirAtmosphere_t>()).c_str());

		printf("True differential pressure as measured in an Oxygen Gas atmosphere (O2):\n\t-> %s Pa\n\n", 
			TruncateAndToString<double>(
			g_LDESeriesDevice.GetPressure<LDE_S250_B_t, OxygenGasAtmosphere_t>()).c_str());
			
		printf("True differential pressure as measured in a Nitrogen Gas atmosphere (N2):\n\t-> %s Pa\n\n", 
			TruncateAndToString<double>(
			g_LDESeriesDevice.GetPressure<LDE_S250_B_t, NitrogenGasAtmosphere_t>()).c_str());
			
		printf("True differential pressure as measured in an Argon Gas atmosphere (Ar):\n\t-> %s Pa\n\n", 
			TruncateAndToString<double>(
			g_LDESeriesDevice.GetPressure<LDE_S250_B_t, ArgonGasAtmosphere_t>()).c_str());
			
		printf("True differential pressure as measured in a Carbon Dioxide atmosphere (CO2):\n\t-> %s Pa\n\n", 
			TruncateAndToString<double>(
			g_LDESeriesDevice.GetPressure<LDE_S250_B_t, CarbonDioxideAtmosphere_t>()).c_str());
		
		printf("On-chip temperature sensor:\n\t-> %s °C\n", 
			TruncateAndToString<double>(
			g_LDESeriesDevice.GetTemperature<Celsius_t>()).c_str());
		
		printf("On-chip temperature sensor:\n\t-> %s °F\n", 
			TruncateAndToString<double>(
			g_LDESeriesDevice.GetTemperature<Fahrenheit_t>()).c_str());
		
		printf("On-chip temperature sensor:\n\t-> %s K\n",  
			TruncateAndToString<double>(
			g_LDESeriesDevice.GetTemperature<Kelvin_t>()).c_str());

		// Allow the user the chance to view the results:
		ThisThread::sleep_for(5s);

		g_LEDGreen = LED_OFF;
		g_LEDBlue = LED_OFF;
	}
	
    printf("\r\n\r\nNuertey-LDESeries-Mbed Application - Exiting.\r\n\r\n");
}
