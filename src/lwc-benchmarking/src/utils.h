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

#include <Arduino.h>


// Helper functions for using the Serial output functions more effectively.
// The sout and sendl classes provide a similar functionality as std::cout and std::endl
class sout{};
class sendl{};

extern sout SOUT;
extern sendl SENDL;

template<typename T>
sout& operator<<(sout &s, const T &t) {

    Serial.print(t);
    return s;
}

sout& operator<<(sout &s, sendl&);

// Waits for the number of seconds specified by the first parameter
void stop_watch(int seconds, const char *caption = nullptr);

// Returns a string describing the current platform
const char* get_platform_name();


// This class behaves like std::array of bytes and used for inputs and outputs to the algorithms
// Some platforms don't have C++ STL support, so we cannot derive from std::array
template<unsigned int N, typename T = uint8_t>
class buffer //: public std::array<unsigned char, N>
{
public:

    // iniatilize the buffer by setting the ith byte to value i
    void init() {

        for(unsigned int i = 0; i < N; i++)
            //(*this)[i] = i;
            _data[i] = i & 0xff;
    }

    void clear() {

        for(unsigned int i = 0; i < N; i++)
            //(*this)[i] = 0;
            _data[i] = 0;
    }

    // print the first 'size' bytes of the buffer in hex to serial output
    void print_hex(const char *name, unsigned int size = N) const {

        SOUT << name;

        auto hex_print = [](unsigned char digit) {

            if(digit < 10)  SOUT << static_cast<char>(('0' + digit));
            else            SOUT << static_cast<char>(('A' + (digit - 10)));
        };

        for(unsigned int i = 0; i < size; i++) {

            for(unsigned int b = 0; b < sizeof(T); b++) {

                uint8_t byte_val = (_data[i] >> (8 * (sizeof(T) - 1 - b))) & 0xff;

                hex_print(byte_val >> 4);
                hex_print(byte_val & 0xf);
            }
        }

        SOUT << SENDL;
    }
 
    T* begin() {
        return _data;
    }

    T* end() {
        return _data + N;
    }

    T* data() {
        return _data;
    }

    size_t size() const {
        return N;
    }

    T& operator[](unsigned int index) {
        return _data[index];
    }

    const T& operator[](unsigned int index) const {
        return _data[index];
    }

 private:
    T _data[N];
};


// Checks for equivalence between two sequences up to 'size' elements
// The sequences are specified by forward iterators
// Returns true if the first 'size' elements are equal, false otherwise.
template<typename Iter>
bool compare_buffers(Iter it1, Iter it2, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++, ++it1, ++it2) {

        if((*it1) != (*it2))
            return false;
    }

    return true;
}

// Checks whether the first N bytes of a buffer is identity, i.e., buffer[i] = i
// This is used to check whether the decryption recovers the plaintext, which is initialized
// as an identity buffer.
template<typename Iter>
bool is_identity_buffer(Iter it, uint64_t size) {

    for(unsigned int i = 0; i < size; i++, ++it)
        if((*it) != (i & 0xff)) {
            //SOUT << "buffer mismatch at pos " << i << SENDL;
            return false;
        }

    return true;
}

// Helper functions for sort()
namespace {

    template<typename T>
    void swap(T& v1, T& v2) {

        T tmp(v1);
        v1 = v2;
        v2 = tmp;
    }

    template<typename T>
    T* partition(T* begin, T* end)
    {
        T* i = begin;

        for(T* j = begin; j < end; j++) {

            if((*j) <= (*end)) {
                swap(*i, *j);
                ++i;
            }
        }

        swap(*i, *end);

        return i;
    }
}

// Sorts the sequence of elements in [begin, end]
template<typename T>
void sort(T* begin, T* end)
{
    if(begin < end)
    {
        auto q = partition(begin, end);
        sort(begin, q - 1);
        sort(q + 1, end);
    }
}

// Calculate the median of a sequence of values
// Sorts the input array inplace
template<unsigned int N, typename T>
T median(buffer<N, T> &arr) 
{
    sort(arr.begin(), arr.end() - 1);
    return arr[N / 2];
}
