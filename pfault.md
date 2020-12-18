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
					timeout
					unsleep
					mi_switch
					untimeout
				vm_page_unqueue
				vm_page_activate
				vm_page_alloc
					vm_page_remove
					vm_page_insert
				vm_fault_additional_pages
					vm_pager_has_page
					vm_fault_page_lookup
				vm_pager_get_pages
					vm_page_free
				vm_page_zero_fill
					pmap_zero_page
				vm_page_copy
					pmap_copy_page
				vm_object_collapse
				pmap_enter
				vm_page_wire
				vm_page_unwire
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
	vm_fault_additional_pages
	vm_fault_page_lookup

File: vm_map.c
	vm_map_lookup
	vm_map_lookup_entry

File: vm_object.c
	vm_object_shadow
	vm_object_collapse

File: vm_page.c
	vm_page_lookup
	vm_page_alloc
	vm_page_remove
	vm_page_insert
	vm_page_unqueue
	vm_page_activate
	vm_page_alloc
	vm_page_free
	vm_page_zero_fill
	vm_page_copy
	vm_page_wire
	vm_page_unwire

File: kern_synch.c
	tsleep
	unsleep
	mi_switch

File: kern_clock.c
	timeout
	untimeout

File: vm_pager.c
	vm_pager_has_page
	vm_pager_get_pages

File: pmap.c
	pmap_zero_page
	pmap_copy_page
	pmap_enter
	pmap_use_pt
	pmap_unuse_pt
```

## Important Data Structures

## Code Walkthrough

```c
```
