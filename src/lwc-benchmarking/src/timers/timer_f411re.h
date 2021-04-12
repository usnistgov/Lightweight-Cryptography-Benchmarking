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


#ifdef LWC_PLATFORM_F411RE

class timer_cycles {

public:

    timer_cycles(uint32_t& output) : _output(output) {

        static bool reload_register_set = false;

        if(!reload_register_set) {
            SysTick_Config(1 << 24);
            reload_register_set = true;
        }

        __disable_irq();

        _start = SysTick->VAL;
    }

    ~timer_cycles() {

        uint32_t end = SysTick->VAL;

        _output = (end <= _start) ? (_start - end) : (_start + (SysTick->LOAD - end));

       __enable_irq();
    }

    static const char *name() {
        return "systick";
    }

private:

    uint32_t &_output;
    volatile uint32_t _start;
};


struct systick_reload_max {

    // set to max value
    systick_reload_max() {
        SysTick_Config(1 << 24);
    }

    // restore at destruction
    ~systick_reload_max() {
        SysTick_Config( SystemCoreClock / 1000 );
    }
};

#endif // LWC_PLATFORM_F411RE
