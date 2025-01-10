/***********************************************************************
* @file      Protocol.h
*
*    Type-driven SPI framing protocol for the First Sensor AG LDE Series
*    – digital low differential pressure sensors.
* 
*    For ease of use, power, flexibility and readability of the code,  
*    the protocol has been written in a modern C++ (C++20) 
*    metaprogrammed and templatized class-encapsulated idiom. 
* 
*    A goal of the design is to encourage and promote zero-cost 
*    abstractions, even and especially so, in the embedded realms. Note
*    that care has been taken to deduce and glean these abstractions 
*    from the problem-domain itself. And in the doing so, care has also 
*    been taken to shape the abstractions logically.
* 
* @brief   
* 
* @note    
*
* @warning  
*
* @author  Nuertey Odzeyem
* 
* @date    November 28, 2021
*
* @copyright Copyright (c) 2021 Nuertey Odzeyem. All Rights Reserved.
***********************************************************************/
#pragma once

// Note that from hence, relevant sections of the 'DS_Standard-LDE_E_11815.pdf'
// are appropriately quoted (\" ... \") as needed. These are intended to
// serve as a sort of Customer requirement repository and to evidence 
// traceability.
//
// https://www.first-sensor.com/cms/upload/datasheets/DS_Standard-LDE_E_11815.pdf

#include "Utilities.h"

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

// A concept is a named set of requirements. The definition of a 
// concept must appear at namespace scope. 
//
// The intent of concepts is to model semantic categories (Number,
// Range, RegularFunction) rather than syntactic restrictions
// (HasPlus, Array). According to ISO C++ core guideline T.20,
// "The ability to specify meaningful semantics is a defining
// characteristic of a true concept, as opposed to a syntactic
// constraint."
template<typename S>
concept IsLDESeriesSensorType = (std::is_same_v<S, LDE_S025_U_t>
                              || std::is_same_v<S, LDE_S050_U_t>
                              || std::is_same_v<S, LDE_S100_U_t>
                              || std::is_same_v<S, LDE_S250_U_t>
                              || std::is_same_v<S, LDE_S500_U_t>
                              || std::is_same_v<S, LDE_S025_B_t>
                              || std::is_same_v<S, LDE_S050_B_t>
                              || std::is_same_v<S, LDE_S100_B_t>
                              || std::is_same_v<S, LDE_S250_B_t>
                              || std::is_same_v<S, LDE_S500_B_t>);

// \" Gas correction factors (6)
//
// Gas type                Correction factor
//
// Dry air                 1.0
// Oxygen (O2)             1.07
// Nitrogen (N2)           0.97
// Argon (Ar)              0.98
// Carbon dioxide (CO2)    0.56               \"

// Metaprogramming types to distinguish atmospheric medium types:
struct DryAirAtmosphere_t        {};
struct OxygenGasAtmosphere_t     {};
struct NitrogenGasAtmosphere_t   {};
struct ArgonGasAtmosphere_t      {};
struct CarbonDioxideAtmosphere_t {};

template<typename T>
concept IsAtmosphericMediumType = (std::is_same_v<T, DryAirAtmosphere_t>
                                || std::is_same_v<T, OxygenGasAtmosphere_t>
                                || std::is_same_v<T, NitrogenGasAtmosphere_t>
                                || std::is_same_v<T, ArgonGasAtmosphere_t>
                                || std::is_same_v<T, CarbonDioxideAtmosphere_t>);

// Metaprogramming types to distinguish sensor temperature scales:
struct Celsius_t    {};
struct Fahrenheit_t {};
struct Kelvin_t     {};

template<typename T>
concept IsTemperatureScaleType = (std::is_same_v<T, Celsius_t>
                               || std::is_same_v<T, Fahrenheit_t>
                               || std::is_same_v<T, Kelvin_t>);

// \" The LDE serial interface is a high-speed synchronous data input 
// and output communication port. The serial interface operates using 
// a standard 4-wire SPI bus. \"
constexpr size_t NUMBER_OF_BITS = 8;

// \" The entire 16 bit content of the LDE register is then read out on
// the MISO pin, MSB first, by applying 16 successive clock pulses to 
// SCLK with /CS asserted low. \"
constexpr auto   NUMBER_OF_SPI_FRAME_BYTES = 2;

// Convenience aliases:
using SPIFrame_t = std::array<char, NUMBER_OF_SPI_FRAME_BYTES>;

template<typename T>
concept IsLDESeriesSPIFrameType = ((std::is_integral_v<T> && (sizeof(T) == 1))
                                 || std::is_same_v<T, SPIFrame_t>);
                              
namespace ProtocolDefinitions
{        
    // Another benefit of such an approach is, our ScalingFactorMap is 
    // statically generated at compile-time hence useable in constexpr
    // contexts.    
    template <typename S>
    struct ScalingFactorMap { static const double VALUE; };
    
    template <typename S>
    const double ScalingFactorMap<S>::VALUE = 0.0;
    
    // Partial template specializations mimics core 'map' functionality.
    // Good and quiet thought makes programming fun and creative :).
    template <>
    const double ScalingFactorMap<LDE_S025_U_t>::VALUE = 1200.0;
                                                              
    template <>                                               
    const double ScalingFactorMap<LDE_S050_U_t>::VALUE =  600.0;
                                                              
    template <>                                               
    const double ScalingFactorMap<LDE_S100_U_t>::VALUE =  300.0;
                                                              
    template <>                                               
    const double ScalingFactorMap<LDE_S250_U_t>::VALUE =  120.0;
                                                              
    template <>                                               
    const double ScalingFactorMap<LDE_S500_U_t>::VALUE =   60.0;
    
    template <>
    const double ScalingFactorMap<LDE_S025_B_t>::VALUE = 1200.0;

    template <>
    const double ScalingFactorMap<LDE_S050_B_t>::VALUE =  600.0;
                                                              
    template <>                                               
    const double ScalingFactorMap<LDE_S100_B_t>::VALUE =  300.0;
                                                              
    template <>                                               
    const double ScalingFactorMap<LDE_S250_B_t>::VALUE =  120.0;
                                                              
    template <>                                               
    const double ScalingFactorMap<LDE_S500_B_t>::VALUE =   60.0;
    
    // \" Scale factor TS = 95 counts/°C \"
    constexpr double TEMPERATURE_SCALING_FACTOR = 95.0; 

    // \" Gas correction factors (6) \"    
    template <IsAtmosphericMediumType A>
    struct GasCorrectionFactor { static const double value; };
    
    template <IsAtmosphericMediumType A>
    const double GasCorrectionFactor<A>::value = 0.0;
    
    template <>
    const double GasCorrectionFactor<DryAirAtmosphere_t>::value = 1.0;
                                                                       
    template <>                                                        
    const double GasCorrectionFactor<OxygenGasAtmosphere_t>::value = 1.07;
                                                                       
    template <>                                                        
    const double GasCorrectionFactor<NitrogenGasAtmosphere_t>::value = 0.97;
                                                                       
    template <>                                                        
    const double GasCorrectionFactor<ArgonGasAtmosphere_t>::value = 0.98;
                                                              
    template <>                                               
    const double GasCorrectionFactor<CarbonDioxideAtmosphere_t>::value = 0.56;
    
    // \"
    // Data read – pressure
    //
    // When powered on, the sensor begins to continuously measure pressure.
    // To initiate data transfer from the sensor, the following three unique
    // bytes must be written sequentially, MSB first, to the MOSI pin (see
    // Figure 5):
    // \"
    constexpr int POLL_CURRENT_PRESSURE_MEASUREMENT{0x2D};
    constexpr int SEND_RESULT_TO_DATA_REGISTER     {0x14};
    constexpr int READ_DATA_REGISTER               {0x98};

    // \"
    // Data read – temperature
    //
    // The on-chip temperature sensor changes 95 counts/°C over the
    // operating range. The temperature data format is 15-bit plus sign
    // in two’s complement format. To read temperature, use the following
    // sequence:
    // \"
    constexpr int POLL_CURRENT_TEMPERATURE_MEASUREMENT{0x2A};
    // constexpr int SEND_RESULT_TO_DATA_REGISTER     {0x14};
    // constexpr int READ_DATA_REGISTER               {0x98};

    // \"
    // The entire 16 bit content of the LDE register is then read out on
    // the MISO pin, MSB first, by applying 16 successive clock pulses
    // to SCLK with /CS asserted low. Note that the value of the LSB is
    // held at zero for internal signal processing purposes. This is 
    // below the noise threshold of the sensor and thus its fixed value
    // does not affect sensor performance and accuracy. \"
    constexpr char       LDE_SERIES_SPI_DUMMY_BYTE {0x00};
    constexpr SPIFrame_t LDE_SERIES_SPI_DUMMY_FRAME{0x00, 0x00};

    template <IsLDESeriesSPIFrameType T>
    inline void DisplaySPIFrame(const T& frame)
    {        
        if constexpr(std::is_same_v<T, SPIFrame_t>)
        {
            if (!frame.empty())
            {
                std::ostringstream oss;

                oss << "\n\t0x";
                for (auto& byte : frame)
                {
                    oss << std::setfill('0') << std::setw(2) << std::hex 
                        << std::uppercase << static_cast<unsigned>(byte);
                }
                oss << '\n';
                
                printf("%s\n", oss.str().c_str());
            }
        }
        else
        {
            std::ostringstream oss;

            oss << "\n\t0x";
            oss << std::setfill('0') << std::setw(2) << std::hex 
                << std::uppercase << static_cast<unsigned>(frame);    
            oss << '\n';
            
            printf("%s\n", oss.str().c_str());
        }
    }

    inline int16_t Deserialize(const SPIFrame_t& frame)
    {
        // \" (10) The digital output signal is a signed, two complement
        // integer. Negative pressures will result in a negative output. \"
        int16_t sensorData = (static_cast<int16_t>(frame.at(0) << 8) 
                            | static_cast<int16_t>(frame.at(1)));

        return sensorData;
    }
    
} // End of namespace ProtocolDefinitions.
