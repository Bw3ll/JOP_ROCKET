import sys
import re
import os.path
import sys
import sets
import copy
# Regs =[]
Regs =["EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP"]
RegsDG =[]
RegsPrint =["EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP"]
Input = []
CF = []
IA86 =["EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP"]
RegsVP=["EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP"]
IA862 =["EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP"]
CF2 = ["JMP", "CALL", "ALL"]
InputAcceptable = ["ja", "jb", "jc", "jd", "jdi","jsi", "jbp", "jsp", "j", "c", "ca","cb", "cc", "cd", "cdi", "csi","cbp", "csp", "pja", "pjb", "pjc", "pjd", "pjdi","pjsi", "pjbp", "pjsp", "pj", "pc", "pca","pcb", "pcc", "pcd", "pcdi", "pcsi","pcbp", "pcsp","ma", "a", "s", "m","d", "move", "mov", "movv", "movs","l", "xc", "st", "po", "pu","id", "inc", "dec", "bit", "sl","sr", "rr", "rl", "all", "rec","da", "db", "dc", "dd", "ddi","dsi", "dbp", "dis","ba", "bb", "bc", "bd", "bdi","bsi", "bbp", "bdis","oa", "ob", "oc", "od", "odi","osi", "obp", "odis", "stack", "deref", "emp","dplus", "mit", "md","ld","cd","scd","std", "str", "pad","2dg", "jpp"] #,"", "", "", "", "","", "", "", "", "","", "", "", "", "","", "", "", "", "","", "", "", "", "",

NumOpsD = 13    # 13
linesGoBack = 4
linesGoBackFindOP = 8




def sp():  # show print - printing is not quite right in Cygwin without this. that is, it waits to print later after input. 
	sys.stdout.flush()
def showOptions():
	options = "\nOptions:\n"
	options += "For detailed help, enter 'h ' and option of interest. E.g. h d\n"
	options += "h: Display options.\n"
	options += "f: Change peName.\n"
	options += "j: Generate pre-built JOP chains! (NEW)\n"
	options += "r: Specify target 32-bit registers, delimited by commas. E.g. eax, ebx, edx\n"
	options += "t: Set control flow, e.g. JMP, CALL, ALL\n"
	options += "g: Discover or get gadgets; this gets gadgets ending in *specified* registers.\n"
	options += "G: Discover or get gadgets ending in JMP; this gets ALL registers. (NEW)\n"
	options += "Z: Discover or get gadgets ending in JMP & CALL; this gets ALL registers. (NEW)\n"
	options += "C: Discover or get gadgets ending in CALL; this gets ALL registers. (NEW)\n"
	# options += "d: Get d. gadgets, e.g. by REG or ALL.\n"
	options += "p: Print sub-menu.E.g. Print ALL, all by REG, by operation, etc.\n"
	options += "P: Print EVERYTHING - no print sub-menu (New)\n"
	options += "M: Mitigations sub-menu.E.g. DEP, ASLR, SafeSEH, CFG.\n"
	options += "D: Set level of depth for d. gadgets.\n"
	options += "m: Extract the modules for specified registers.\n"
	options += "n: Change number of opcodes to disassemble.\n"
	options += "l: Change lines to go back when searching for an operation, e.g. ADD\n"
	options += "s: Scope--look only within the executable or executable and all modules\n"
	options += "u: Unassembles from offset. See detailed: b-h\n"
	# options += "b: Hash boring redundancy limit. See detailed: u-h\n"  # RETIRED
	# options += "a: Do 'everything' for selected PE and modules. Does not build chains.\n"
	options += "w: Show mitigations for PE and ennumerated modules.\n"
	options += "b: Show or add bad characters.\n"
	# options += "v: Generates CSV of all operations from all modules.\n"
	options += "c: Clears everything.\n"
	options += "k: Clears selected DLLs.\n"
	options += "i: change imagebase for the image executable\n"
	options += "y: Useful information.\n"
	options += "q: Credits\n"
	options += "x: exit.\n"
	print options
	sp()

def usefulInfo():
	print "USAGE\nWhen supplying input, you may supply a PE local to the directory on the \ncommand line.To be able to enumerate modules from a PE, you must \nprovide its file location as input. This input can be an argument \non the command line, e.g.\n\tpython rocket.py input.txt\nInput must be absolute path, e.g.\n\tC:\\Program Files (x86)\\HxD\\HxD.exe\n\tC:\\\\Program Files (x86)\\\\HxD\\\\HxD.exe\n"
	print "d. gadgets\nHaving d. gadgets is a necessity if you follow dispatcher gadget \nparadigm. To find these, first select registers (r), get gadgets (g), \nand then select d. gadgets (d).\n"
	print "PRINTING\nOnce you obtain all the gadgets needed, enter the print submenu (p), and\n make your selections. These are saved to the JOP ROCKET directory.\n"
	# print "BORING HASH REDUNDANCY LIMIT\nThe JOP ROCKET algorithms find EVERY JOP gadget, but there can be\n redundancy in the results. Hashing can reduce this, but sometimes \nit can obscure good, needed results. Raising the hash boring redundancy \nlimit can reduce the impact of hashing on results, but it will enlarge \nthe redundancy. This value should also be increased if changing the \nlinesGoBack (l) value.\n"
	sp()
def helpDetailed(val):
	if val == "f":
		print  "Change filename to of target. This assumes it is in local directory.\n"
	if val == "r":
		print  "This specifies registers as targets, e.g. JMP EAX, CALL EBX.\n"
	if val == "t":
		print  "This sets scope for whether searching by JMP or CALL to a reg.\n"
	if val == "p":
		print  "This takes you to printing sub-menu. Type x to return to main menu.\n"
	if val == "d":
		print  "\nDISPATCHER GADGET HELP\n\nInput should be delimited by commas, e.g. eax, ebx, esi.\n**These are the registers that it will search for d. gadgets. \n**The dispatcher gadget advances by going forwards or backwards. \n**You might add 10 to eax and then go to eax, which takes you to the \nnext location in the dispatch table. \n\nYou can adjust the depth as well.\n**Adjustments will make d. gadgets less likely to be viable.\n\nYou must run specify desired register (r) and get gadgets (g) BEFORE \nentering get dispatcher gadget (d); the registers must match. Output \nwill then be ready to print.\n"
	if val == "m":
		print  "By default, this will ONLY search the executable image, no modules. To \nsearch modules, they must be enumerated; this can take some time, if large. \nThen you must set register (r) and get gadgets (g) or get dispatcher \ngadgets (d) after enumerating modules.\n\nThere is no way at this time to exclude modules.\n"
	if val == "l":
		print  "No further information is provided.\n"
	if val == "s":
		print  "This sets the scope. If the scope includes all modules, it will obtain \nall the specified registers for both functional gadgets and dispatcher \ngadgets as specified.\n"
	if val == "c":
		print  "Clear the data structures which hold various values obtained from \ndisassembling the binaries. Switching to a different binary requires this.\nIf you run GET on the same registers multiple times, they will appear \nmore than once in results. \nFound gadgets will remain in memory until cleared."
	if val == "D":
		print  "That is, how many lines should there be between the call/jmp and the \ninstruction that is modifying the dispatcher table. The greater \nthis value, the more other registers can be potentially be made \nmore difficult to use. Though this may not always matter.\n"
	if val == "G":
		print  "This will normally be run with the other 'get gadgets' routine, provided \nthe user has selected the target dispatcher gadget functions.\n"
	if val == "u":
		print  "**Experimental\nThis unassembles from supplied offset from image base of executable. \nThe offset entered appears at the bottom. This does not unassemble from \nmodules. This is similar to u command in WinDbg.\nDefault # of bytes to carve out a chunk is 6. Thus, some instructions \npreceding the address at the offset you entered could change depending \non if execution started elsewhere.\n\nUse offset, bytes to change that value.\nAcceptable input:\n\t10b9\n10b9, 12\n24d3\n24d3, 10"
	if val == "bb":
		# print  "ROCKET will naturally produce redundant results due to how it finds \nresults. A hash of b value lines is taken and checked to see if there is \nalready output of the same size. If the value is higher, there will be more\nredundant results, but potentially you may see instructions further from \nthe JMP or CALL, which may be useful. These might otherwise be excluded.\n" 
		pass
	if val == "v":
		print  "This will enumerate all modules, obtain all gadgets from all modules.\nThe results will be printed to file as a CSV. \nThis feature is experimental."
	UI()

		
	sp()
def showPrintOptions():
	
	options ="**Functional commands:\n\nde - View selections\nz - Run print routines for selctions\n"
	options +="P - Print EVERTHING all operations and regs selected (NEW)\n"
	options +="Note: JOP chains MUST be generated separately on JOP chain sub-menu\n"
	options +="g - Enter operations to print\n"
	options +="\t*!*You MUST specify operations to print.*!*\n"
	options +="r - Set registers to print\n"  # options ="Clear all Options\n" have this as option
	options +="\t*!*You MUST specify the registers to print.*!*\n"
	options +="C - Clear all selected operations\n"
	options +="mit - Print Mitigations for scanned modules\n"  # options ="Clear all Options\n" have this as option
	options +="\tMust scan for mitigations first\n"
	options +="x - Exit print menu\n\n"  # options ="Clear all Options\n" have this as option
	options +="dis - Print all d. gadgets\tbdis - Print all the BEST d. gadgets\n"	
	options +="odis - Print all other d. gadgets\t\n\n"	
	options +="da - Print d. gadgets for EAX\t\tba - Print best d. gadgets for EAX\n"	
	options +="db - Print d. gadgets for EBX\t\tbb - Print best d. gadgets for EBX\n"	
	options +="dc - Print d. gadgets for ECX\t\tbc - Print best d. gadgets for ECX\n"	
	options +="dd - Print d. gadgets for EDX\t\tbd - Print best d. gadgets for EDX\n"	
	options +="ddi - Print d. gadgets for EDI\t\tbdi - Print best d. gadgets for EDI\n"	
	options +="dsi - Print d. gadgets for ESI\t\tbsi - Print best d. gadgets for ESI\n"	
	options +="dbp - Print d. gadgets for EBP\t\tbbp - Print best d. gadgets for EBP\n"
	options +=" \n"
	options +="oa - Print d. gadgets for EAX\t\tob - Print best d. gadgets for EBX\n"	
	options +="oc - Print d. gadgets for ECX\t\tod - Print best d. gadgets for EDX\n"	
	options +="odi - Print d. gadgets for EDI\t\tosi - Print best d. gadgets for ESI\n"
	options +="obp - Print d. gadgets for EBP\t\t \n"
	options +="dplus - print all alternative d. gadgets - jmp ptr dword [ reg +/-]\n"
	options +="\n2dg (NEW)- print all two-gadget dispatchers! (NEW) - jmp/call\n"
	options +="\tThese should be chained with a dereference gadget.\n"
	options +="\tE.g. See Empty JMP PTR and JMP PTR POP \n"
	options +=" \n"
	options +="j - Print all JMP REG\t\t\tc - Print all CALL REG\n"
	options +="\tja - Print all JMP EAX\t\t\tca - Print all CALL EAX\n"
	options +="\tjb - Print all JMP EBX\t\t\tcb - Print all CALL EBX\n"
	options +="\tjc - Print all JMP ECX\t\t\tcc - Print all CALL ECX\n"
	options +="\tjd - Print all JMP EDX\t\t\tcd - Print all CALL EDX\n"
	options +="\tjdi - Print all JMP EDI\t\t\tcdi - Print all CALL EDI\n"
	options +="\tjsi - Print all JMP ESI\t\t\tcsi - Print all CALL ESI\n"
	options +="\tjbp - Print all JMP EBP\t\t\tcbp - Print all CALL EBP\n"
	options +="\tjsp - Print all JMP ESP\t\t\tcsp - Print all CALL ESP\n"
	options +="emp - Print all 'empty' JMP PTR [reg]  (NEW) \n"
	options +="jpp - Print all JMP PTR [reg] # POP (NEW) \n"
	options +="\tWorks with two-gadget dispatcher that starts with Call\n"
	options +="pj - Print JMP PTR [REG]\t\tpc - Print CALL PTR [REG]\n"
	options +="\tpja - Print JMP PTR [EAX]\t\tpca - Print CALL PTR [EAX]\n"
	options +="\tpjb - Print JMP PTR [EBX]\t\tpcb - Print CALL PTR [EBX\n"
	options +="\tpjc - Print JMP PTR [ECX]\t\tpcc - Print CALL PTR [ECX\n"
	options +="\tpjd - Print JMP PTR [EDX]\t\tpcd - Print CALL PTR [EDX\n"
	options +="\tpjdi - Print JMP PTR [EDI]\t\tpcdi - Print CALL PTR [EDI]\n"
	options +="\tpjsi - Print JMP PTR [ESI]\t\tpcsi - Print CALL PTR [ESI]\n"
	options +="\tpjbp - Print JMP PTR [EBP]\t\tpcbp - Print CALL PTR [EBP]\n\n"
	options +="\tpjsp - Print JMP PTR [ESP]\t\tpcsp - Print CALL PTR [ESP]\n\n"
	options +="ma - Print all arithmetic\t\tst - Print all stack operations\n"
	options +="\ta - Print all ADD\t\t\tpo - Print POP\n"
	options +="\ts - Print all SUB\t\t\tpu - Print PUSH\n"
	options +="\t                 \t\t\tpad - Popad\n"
	options +="\t\t\t\t\t\tstack - all stack pivots (NEW)\n"
	options +="\tm - Print all MUL\t\tid - Print INC, DEC\n"
	options +="\td - Print all DIV\t\t\tinc - Print INC\n"
	
	options +="move - Print all movement\t\t\tdec - Print DEC\n"
	options +="\tmov - Print all MOV\t\tbit - Print all Bitwise\n"
	options +="\tmovv - Print all MOV Value\t\tsl - Print Shift Left\n"
	options +="\tmovs - Print all MOV Shuffle\t\tsr - Print Shift Right\n"
	options +="\tderef - Print all MOV Dword\n" 
	options +="\t\tPTR dereferences (NEW)\t\tn - neg\n"
	options +="\tl - Print all LEA\t\t\trr - Print Rotate Right\n"
	options +="\txc - Print XCHG\t\t\t\trl - Print Rotate Left\n"


	options +="str - Print all strings (good for DG)\t\txo - XOR\n"
	options +="\tcd - cmpsd\t\t\n"
	options +="\tld - lodsd\t\t\n"
	options +="\tmd - movsd\t\t\n"
	# options +="\tstd - stosd\t\t\n"
	options +="\tscd - scasd\t\t\n"

	options +="\nall - Print all the above\t\t\trec - Print all operations only (Recommended)\n\n"
		
	print options
	sp()
