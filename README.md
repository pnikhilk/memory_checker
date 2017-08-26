# memory_checker
A PIN to check memory violation done by binaries.

It checks for memory operations requested by applications like:
1. Allocate memory but does not free.
2. Using already freed memory.
3. Free already freed memory.
4. Attempt to free invalid memory address.
