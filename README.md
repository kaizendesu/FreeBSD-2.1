## How to Read Operating System Code Effectively

1. Create a flow diagram of all the relevant functions and their subroutines
in the order that they are executed. The flow diagram will have a minimum
depth of four layers, with each layer describing a stack frame/context.

2. Create the code reading checklist that will list every relevant function
we want to read by filename and in the order they are called within that
file. Create four dashes "----" to with the following meanings:
	* The first check means I have read the function and have an idea of
      what it does.
	* The second check means that I have heavily commented the function.
	* The third check means that I have read through the code again with
      a focus on the bigger picture and anything I may have overlooked.
	* The fourth check means I have added the commented code to the walkthrough.
	
3. Create the "Important Data Structures and Definitions" section by scanning
the code for the most used data structures, identifying which header files they
are defined in, reading the definitions of said structures, and also reading
any detailed comments describing the structures and the overall system.

4. Create the Code Walkthrough section with two subheadings: Pseudocode Overview
and Documented Code. Pseudocode Overview describes what each function in the flow
diagram does without any focus on the actual implementation, while Documented Code
is heavily commented code excerpts that illustrate the most significant details in
the walkthrough.

5. Read through each function in order line by line, focusing on what each code block
is doing and creating inline comments that describe the code in plain english. Also
include comments that break up large if statements and other sections of code that
focus on something in particular. For example, if-statements with long special cases
or a list of kernel asserts before calling an important function.

When you finish reading through and documenting a function line by line, fill in its
pseudocode counterpart in the Pseudocode Overview, describing what the function does
without focusing on implementation details.

6. After reading through every function line by line and creating its pseudocode
counterpart, summarize the code in its entirety step by step, using only a single
sentence to describe each major function does.

7. Decide on which functions to include in the walkthrough document and copy
them to it.
