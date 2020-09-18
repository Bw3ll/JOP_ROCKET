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


OP_RET = b"\xc3"

listOP_Base = []
listOP_Base_CNT = []
listOP_Base_NumOps = []
listOP_Base_Module = []

listOP_BaseDG = []
listOP_BaseDG_CNT = []
listOP_BaseDG_NumOps = []
listOP_BaseDG_Module = []


