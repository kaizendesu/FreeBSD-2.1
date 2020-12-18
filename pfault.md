# Walkthrough of FreeBSD 2.1's Page Fault Code

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
_alltraps
	trap
		trap_pfault
			grow
			vm_fault
				vm_map_lookup
					vm_map_lookup_entry
					vm_object_shadow
				vm_page_lookup
				tsleep
			pmap_use_pt
			pmap_unuse_pt
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: exception.s
	_alltraps

File: trap.c
	trap
	trap_pfault

File: vm_machdep.c
	grow

File: vm_fault.c
	vm_fault

File: vm_map.c
	vm_map_lookup
	vm_map_lookup_entry

File: vm_object.c
	vm_object_shadow

File: vm_page.c
	vm_page_lookup
	vm_page_unqueue
	vm_page_activate

File: kern_synch.c
	tsleep

File: pmap.c
	pmap_use_pt
	pmap_unuse_pt
```

## Important Data Structures

## Code Walkthrough

```c
```
