from capstone import *
import re
import pefile
import sys
import binascii
import copy
#import prog
global MyBytes
global objs

OP_JMP_EAX = b"\xff\xe0"
OP_JMP_EBX = b"\xff\xe3"
OP_JMP_ECX = b"\xff\xe1"
OP_JMP_EDX = b"\xff\xe2"
OP_JMP_ESI = b"\xff\xe6"
OP_JMP_EDI = b"\xff\xe7"
OP_JMP_ESP = b"\xff\xe4"
OP_JMP_EBP = b"\xff\xe5"
OP_JMP_R8 = b"\x41\xff\xe0"
OP_JMP_R9 = b"\x41\xff\xe1"
OP_JMP_R10 = b"\x41\xff\xe2"
OP_JMP_R11 = b"\x41\xff\xe3"
OP_JMP_R12 = b"\x41\xff\xe4"
OP_JMP_R13 = b"\x41\xff\xe5"
OP_JMP_R14 = b"\x41\xff\xe6"
OP_JMP_R15 = b"\x41\xff\xe7"

OP_JMP_PTR_EAX = b"\xff\x20"
OP_JMP_PTR_EBX = b"\xff\x23"
OP_JMP_PTR_ECX = b"\xff\x21"
OP_JMP_PTR_EDX = b"\xff\x22"
OP_JMP_PTR_EDI = b"\xff\x27"
OP_JMP_PTR_ESI = b"\xff\x26"
OP_JMP_PTR_EBP = b"\xff\x65\x00"
OP_JMP_PTR_ESP = b"\xff\x24\x24"

OP_CALL_EAX = b"\xff\xd0"
OP_CALL_EBX = b"\xff\xd3"
OP_CALL_ECX = b"\xff\xd1"
OP_CALL_EDX = b"\xff\xd2"
OP_CALL_EDI = b"\xff\xd7"
OP_CALL_ESI = b"\xff\xd6"
OP_CALL_EBP = b"\xff\xd5"
OP_CALL_ESP = b"\xff\xd4"

OP_CALL_PTR_EAX =  b"\xff\x10"
OP_CALL_PTR_EBX =  b"\xff\x13"
OP_CALL_PTR_ECX =  b"\xff\x11"
OP_CALL_PTR_EDX =  b"\xff\x12"
OP_CALL_PTR_EDI =  b"\xff\x17"
OP_CALL_PTR_ESI =  b"\xff\x16"
OP_CALL_PTR_EBP =  b"\xff\x55\x00"
OP_CALL_PTR_ESP =  b"\xff\x14\x24"

OP_CALL_FAR_EAX =  b"\xff\x18"
OP_CALL_FAR_EBX =  b"\xff\x1b"
OP_CALL_FAR_ECX =  b"\xff\x19"
OP_CALL_FAR_EDX =  b"\xff\x1a"
OP_CALL_FAR_EDI =  b"\xff\x1f"
OP_CALL_FAR_ESI =  b"\xff\x1e"
OP_CALL_FAR_EBP =  b"\xff\x1c\x24"
OP_CALL_FAR_ESP =  b"\xff\x5d\x00"


listOP_Base = []
listOP_Base_CNT = []
listOP_Base_NumOps = []
listOP_Base_Module = []

listOP_BaseDG = []
listOP_BaseDG_CNT = []
listOP_BaseDG_NumOps = []
listOP_BaseDG_Module = []


def addListBase(address, valCount, NumOpsDis, modName):
#	print "addlistbase"
	listOP_Base.append(address)
	listOP_Base_CNT.append(valCount)
	listOP_Base_NumOps.append(NumOpsDis)
	listOP_Base_Module.append(modName)


def searchListBase2(address, NumOpsDis):
	print "searchListBase2"
	i=0
	t=0
	for each in listOP_Base:
		if address == listOP_Base[i]:
			if NumOpsDis == listOP_Base_NumOps[i]:
				t = t +1

	print "ttt"
	print t



def switch33 (val): #switching the focus
	matchObj = re.match( r'^mov [e]*c[x|l],+|^ad[d|c]+ [e]*cx,|^s[u|b]+b [e]*cx,|^pop ecx|^mul ecx|^inc ecx|^dec ecx|^add esp', val, re.M|re.I)
	if matchObj:
		return 1
	if not matchObj:
		return 0


#i-lGoBack2

def switch32(val2, i, lGoBack2): #switching the focus

	print "found it:"

	lGoBack = val2.__len__()
	#lGoBack2 = lGoBack-1	
	
	no=0
	print "in switch 2"
	for v in range (lGoBack2):
		
		print "i: " + str(i) + " --                  " +  str(val2[lGoBack2-i])
		if switch(val2[lGoBack2-i]) == 1:
			print str(i) + " ; s2valb: " + str(val2[lGoBack2-i])
			#print switch(val2[i-lGoBack2-i])
			print "yes. "
			no += 1
			print "no=" + str(no)
		i +=1
		if lGoBack2 == i:
			if no == 0:
				print "COOL! "  + str(no)
			if no > 1:
				print "NOPE! "  + str(no)
