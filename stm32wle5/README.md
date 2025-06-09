# Intro
Demonstrates reception and transmission of meshtastic packets on an stm32wl5 board.

# Notes
This sketch includes a copy of the Arduino rweather/Crypto library (v 0.4.0).
This library was modified to resolve a conflict in the 'RNG' symbol, which is defined in both the stm32 header files and the Crypto library header files.

The modification consists of a change in Crypto/RNG.cpp, around line 23:

```code
#include <Arduino.h>
#ifdef RNG
#undef RNG
#endif
```