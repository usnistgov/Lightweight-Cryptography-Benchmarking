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

#include <Arduino.h>
#include "lwc_benchmark.h"

// Disable watchdog timer on ESP for KAT and Timing experiments
#if defined(LWC_PLATFORM_NODEMCUV2) && !defined(LWC_EXPERIMENT_SIZE)
#include <Esp.h>
#endif

void setup()
{
// Don't use IO for size experiments to reduce the overall size of the binary
#ifndef LWC_EXPERIMENT_SIZE

  // initialize LED digital pin as an output.
   pinMode(LED_BUILTIN, OUTPUT);

   Serial.begin(9600);
   Serial.println();

  // Wait for a few seconds before running the experiments in order to allow
  // enonugh time for opening the terminal window if run from the IDE
  stop_watch(5);
#endif  

  int ret = do_experiments();
  
#ifndef LWC_EXPERIMENT_SIZE
  SOUT << "# lwc exit " << ret << SENDL;
#endif
}


void loop()
{
// Don't use IO for size experiments to reduce the overall size of the binary
#ifndef LWC_EXPERIMENT_SIZE
  // This loop just blinks.
  // It visually signals that the setup() function has completed.


#if defined(LWC_PLATFORM_NODEMCUV2) && !defined(LWC_EXPERIMENT_SIZE)
  yield();
#endif

  // turn the LED on (HIGH is the voltage level)
  digitalWrite(LED_BUILTIN, HIGH);
  // wait for a second
  delay(1000);
  // turn the LED off by making the voltage LOW
  digitalWrite(LED_BUILTIN, LOW);
   // wait for a second
  delay(1000);
#endif  
}
