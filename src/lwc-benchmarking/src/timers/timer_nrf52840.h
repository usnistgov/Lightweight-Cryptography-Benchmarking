//
// NIST-developed software is provided by NIST as a public service.
// You may use, copy and distribute copies of the software in any medium,
// provided that you keep intact this entire notice. You may improve, 
// modify and create derivative works of the software or any portion of
// the software, and you may copy and distribute such modifications or
// works. Modified works should carry a notice stating that you changed
// the software and should note the date and nature of any such change.
// Please explicitly acknowledge the National Institute of Standards and 
// Technology as the source of the software.
//
// NIST-developed software is expressly provided "AS IS." NIST MAKES NO 
// WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY OPERATION
// OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. NIST
// NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE 
// UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST 
// DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE
// OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
// RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
//
// You are solely responsible for determining the appropriateness of using and 
// distributing the software and you assume all risks associated with its use, 
// including but not limited to the risks and costs of program errors, compliance 
// with applicable laws, damage to or loss of data, programs or equipment, and 
// the unavailability or interruption of operation. This software is not intended
// to be used in any situation where a failure could cause risk of injury or 
// damage to property. The software developed by NIST employees is not subject to
// copyright protection within the United States.
//

#pragma once


#ifdef LWC_PLATFORM_NANO33BLE

#include "nrf.h"

class timer_cycles {

public:

    timer_cycles(uint32_t& output, bool disable_interrupts = true) : _output(output), _disable_interrupts(disable_interrupts) {

        static bool initialized = false;

        if(!initialized) {

            // enable DWT
            CoreDebug->DEMCR |= 0x01000000;

            // Reset cycle counter
            DWT->CYCCNT = 0;

            // enable cycle counter
            DWT->CTRL |= 0x1;

            initialized = true;
        }

        if(_disable_interrupts)
            __disable_irq();

        _start = DWT->CYCCNT;
    }

    void start() {
        
        __disable_irq();

        _start = DWT->CYCCNT;
    }

    uint32_t stop() const {

        uint32_t elapsed = DWT->CYCCNT - _start;

        __enable_irq();

        return elapsed;
    }

    ~timer_cycles() {

        uint32_t end = DWT->CYCCNT;

        _output = end - _start;

        if(_disable_interrupts)
            __enable_irq();
    }

    static const char *name() {
        return "nrf52840 RTC";
    }

private:

    uint32_t &_output;
    volatile uint32_t _start;
    bool _disable_interrupts;
};

#endif // LWC_PLATFORM_NANO33BLE
