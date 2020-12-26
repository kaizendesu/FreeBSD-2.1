# Walkthrough of FreeBSD 2.1's Kill Signal System Call

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
kill
	psignal
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: kern_sig.c
	kill			----
	psignal			----
```

## Important Data Structures

## Code Walkthrough

```c
```
