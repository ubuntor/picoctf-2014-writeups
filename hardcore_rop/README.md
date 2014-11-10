# Hardcore ROP

Let's take a look at the source:
```
test
```

Looks like the program creates a buffer at 0x0f000000 with length 40960 (0xa000), and fills it with random bytes, with rets (0xc3) sprinkled in. We also get to supply the random seed, so it stays constant with each run.

Since PIE, ASLR, and NX are enabled, we'll have to ROP using that buffer, since it's the only constant memory address we know.

Trying random seeds to generate good ROP gadgets, we find "quam", which gives us lots of goodies, including a pop/pop/pop/ret, memory dereferencing, and movs.
