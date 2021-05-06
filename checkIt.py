import re


main = [13,24,32,42, 55, 66,77,88]
cnt = [13,24,32,42, 55, 66,77,88]
numOps = [13,24,32,42, 55, 66,77,88]
mod = [13,24,32,42, 55, 66,77,88]
byt = [3,8,3,8,5,6,4,2]
def sortBytes(main,cnt,numOps, mod, byt):
	n = len(byt) 
	byt
	
	for i in range(n): 
		# Last i elements are already in place 
		for j in range(0, n-i-1): 
			# traverse the array from 0 to n-i-1 
			# Swap if the element found is greater 
			# than the next element 
			if byt[j] > byt[j+1] : 
				byt[j], byt[j+1] = byt[j+1], byt[j] 
				cnt[j], cnt[j+1] = cnt[j+1], cnt[j] 
				numOps[j], numOps[j+1] = numOps[j+1], numOps[j] 
				mod[j], mod[j+1] = mod[j+1], mod[j] 
				main[j], main[j+1] = main[j+1], main[j] 
	# print byt  
	return main, cnt, numOps, mod, byt


main, cnt, numOps, mod, byt = sortBytes(main,cnt,numOps,mod,byt)

# print "m" 
# print main
# print "c"
# print cnt
# print "n"
# print numOps
# print "m" 
# print mod
# print "b\n\n\n\n\n"
# print byt

special=0x0

val2 = []
val2.append("add esp, 0x1")

val2.append("add esp, 0x2")

val2.append("add esp, 0x3")
val2.append("push eax")

val2.append("add esp, 0x4")
val2.append("pop eax")
val2.append("sub esp,  0x2")
val2.append("jmp eax")

lGoBack=3


# print "doit"


def splitWordrs(stringReplace):
	array = stringReplace.split(" ")
	new2=[]
	x=0
	for word in array:
		new2.append(word)
	# new3 = new1.split(",")
	try:
		return new2[1]	
	except:
		return new2[0]	



def splitWordrs2(stringReplace):
	array = stringReplace.split(" ")
	new2=[]
	x=0
	for word in array:
		new2.append(word)
	# new3 = new1.split(",")
	try:
		return new2[2]	
	except:
		return new2[0]	

reax = 0
rebx=0
recx=0
redx=5
redi=3
resi=0
resp=0
rebp=0

def espRetCheck(eax, ebx, ecx, edx,  edi, esi, esp, ebp, result):
	f=0
	print "result: " + str(result)
	if result == "edx":
		f= edx
		print "\t\t\tADDING edx " + str(edx)
	if result == "edi":
		f=edi
		print "\t\t\tADDING edx " + str(edi)
	print "\treturnVal: " + str(f) 
	return f


# print "new"

val2 = []
val2.append("add esp, 0x1")

val2.append("add esp, 0x2")

#val2.append("add esp, edx")

val2.append("add esp, edx")
#val2.append("add esp, edx")
val2.append("push eax")
val2.append("mov edx, edx")

val2.append("mov edx, edx")
#val2.append("mov edx, edx")
val2.append("add esp, 0x4")
val2.append("pop eax")
val2.append("sub esp,  0x34")
val2.append("jmp eax")



reax = 0
rebx=0
recx=0
redx=5
redi=0
resi=0
resp=0
rebp=0
def cpuCheck(instructions, reax,rebx,recx, redx, redi, resi,resp,rebp):
	temp = 0
	lim=len(val2)
	print lim
	special =0
	specAddEsp = re.match( r'\badd esp\b', val2[temp], re.M|re.I)
	spec = re.match( r'\bpop\b', val2[temp], re.M|re.I)
	if (spec or specAddEsp):
		while (temp < lim):
			spec = re.match( r'\bpop\b', val2[temp], re.M|re.I)
			specAddEsp = re.match( r'\badd esp\b', val2[temp], re.M|re.I)
			specSubEsp = re.match( r'\bsub esp\b', val2[temp], re.M|re.I)
			push= re.match( r'\bpush\b', val2[temp], re.M|re.I)
			movR= re.match( r'\bmov e*\b', val2[temp], re.M|re.I)
			if spec:
				#special = special +0x4	
				#print  " POP result: " +str(result) + " temp: " + str(temp) + " special: " + str(special)
				pass
			if specAddEsp:
				specAddEsp = re.search( r'e[abcdsb]*[xip]*', val2[temp], re.M|re.I)
				if (specAddEsp):
					result = specAddEsp.group()
					# print "MET " + str(result) 
					#special = special + int(result,16)
					#if edxCheck(result):
					
					#	special = special + redx
					out= espRetCheck(reax, rebx, recx, redx,  redi, resi, resp, rebp,result)
					special = special + out
					# print   " ADD result: " +str(result) + " temp: " + str(temp)+ " special: " + str(special)
					# print "\t\treax: " + str(reax) + " rebx: " + str(rebx) + " recx: " + str(recx) + " redx: " + str(redx) + " redi: " + str(redi) + " resi: " + str(resi) + " rebp: " + str(rebp) + " resp: " + str(resp) 
			if movR:
				movR = re.search( r'e[abcd]x*', val2[temp], re.M|re.I)
				if (movR):
					result = movR.group()
					# print "hi " + str(result)

					#special = special + int(result,16)
					#if edxCheck(result):
					
					#	special = special + redx
					#reax,rebx,recx, redx, redi, resi,resp,rebp = espRetCheck(reax,rebx,recx, redx, redi, resi,resp,rebp,result)
					#print   " MOV result: " +str(result) + " temp: " + str(temp)+ " special: " + str(special)
					#print "\t\tMOV** reax: " + str(reax) + " rebx: " + str(rebx) + " recx: " + str(recx) + " redx: " + str(redx) + " redi: " + str(redi) + " resi: " + str(resi) + " rebp: " + str(rebp) + " resp: " + str(resp) 

			if specSubEsp:
				#specSubEsp = re.search( r'0x[0-9A-F]*', val2[temp], re.M|re.I)
				#if (specSubEsp):
				#	result = specSubEsp.group()
				#	special = special - int(result,16)
				pass
			if push:
				special = special -0x4	
				print  " PUSH result: " +str(result) + " temp: " + str(temp) + " special: " + str(special)
			temp = temp +1
	

	pass

	return reax, rebx, recx,redx,redi,resi,resp,rebp




def splitterRetval(stringReplace):
	#format  push edx # pop ebx # pop eax # push ebp # pop ebx # add esp, 0x10 # jmp eax
	array = stringReplace.split(" # ")
	new = ""
	for word in array:
		new =  word
	# new2 = new.split(")")eturn array
	return array


def splitterRetval2(stringReplace):
	# format = line2="0x0040142d, # (base + 0x142d), # push edx # pop ebx # pop eax # push ebp # pop ebx # add esp, 0x10 # jmp eax #  mytester10.exe 16 [0x10 bytes] 0x4c"
	array = stringReplace.split(" # ")
	new = ""
	del array[0]
	del array[0]
	del array[len(array)-1]
	return array

 #  #  - 0 bytes   pop eax # push edx # add ecx, 0x20007 # jmp ebx
val3 = []
val3.append("pop eax 1")
val3.append("pop ebx 2 ")
val3.append("push ebx 3")
val3.append("push edx 4")
val3.append("add ecx, 0x20007 5")
val3.append("pop edi 6")
val3.append("jmp edx")
#val3.append("jmp edx")
#notes -- HASHcheck, run it, then sort it. BOOM
#maybe readd addresses??




#### do a simple check for perfect, then simple check for not perfect!!!
### if neg -- more filler
### if pos -- push
###3 if imperfect -- warning message

val54 = []
val54.append("pop eax 0")
val54.append("add esp, 0x234 ")
val54.append("pop ebx ")
val54.append("push ebx ")
val54.append("push ebx ")
val54.append("push ebx ")

val54.append("push ebx ")

val54.append("push ebx ")


val54.append("sub esp, 0x100 ")
val54.append("jmp edx")

best=4
specAfter=0
def checkIt(val2,r1,r2):	

	# for x in val2:
	# 	print x
	global specAfter
	# print "inCheckit POP " + r1 + "  JMP " + r2 
	# print r1 +r2
	# print val2
	# print "lookingh"
	#for i,e in reversed(list(enumerate(val2))):
	temp = 0
	lim=len(val2)
	# print "lim " + str(lim)
	#print val2[temp]
	#print "lim " + str(lim)
	specAfter=0
	specBefore=0
	popStart = re.match( r'\bpop eax\b|\bpop ebx\b|\bpop ecx\b|\bpop edx\b|\bpop edi\b|\bpop esi\b|\bpop ebp\b|\bpop esp\b', val2[temp], re.M|re.I)
	if (popStart):
		# print "t0: " + str(temp) + " lim: " + str(lim) + " " + val2[temp]
		while (temp < lim):
			p ="pop "
			j = "jmp "
			pu = "push "
			r1t=p+r1
			r1tPush=pu+r1
			r2t=j+r2
			popTEST= re.match( r1t, val2[temp], re.M|re.I)
			jmpTEST= re.match( r2t, val2[temp], re.M|re.I)

			# jmpDEAX = re.match( r'\bjmp dword ptr [eax]\b', val2[temp], re.M|re.I)
			if popTEST:
				if (temp != 0):
					# print "No needs to be top"
					return False, 0
				# print "t1: " + str(temp) + " lim: " + str(lim)
				# print "pop test! " +val2[temp] + " # " + str(specAfter) 
				d=temp +1
				once = False
				while (d < lim):
					# popEAX = re.match( r'\bpop eax\b', val2[d], re.M|re.I)
					# popEBX = re.match( r'\bpop ebx\b', val2[d], re.M|re.I)
					# popECX = re.match( r'\bpop ecx\b', val2[d], re.M|re.I)
					# popEDX = re.match( r'\bpop edx\b', val2[d], re.M|re.I)
					# popEDI = re.match( r'\bpop edi\b', val2[d], re.M|re.I)
					# popESI = re.match( r'\bpop esi\b', val2[d], re.M|re.I)
					# popEBP = re.match( r'\bpop ebp\b', val2[d], re.M|re.I)
					# popESP = re.match( r'\bpop esp\b', val2[d], re.M|re.I)

					# if popEBP or popEBX:
					# 	specAfter +=4
					# 	print "doh " +  val2[d] + " # " + str(specAfter) 
					
					push= re.match( r'\bpush\b', val2[d], re.M|re.I)
					pop= re.match( r'\bpop\b', val2[d], re.M|re.I)
					addESP = re.match( r'\badd esp\b|\badc esp\b', val2[d], re.M|re.I)
					subESP = re.match( r'\bsub esp\b|\bsbb esp\b', val2[d], re.M|re.I)
					if push or pop or addESP or subESP:	
						# print "\t\tone: "+ val2[d]
						# if pop:
						# 	# print "second pop"
						if not once:
							once = True
							f=d
							while (f < lim):
								push= re.match( r'\bpush\b', val2[f], re.M|re.I)
								pop= re.match( r'\bpop\b', val2[f], re.M|re.I)
								addESP = re.match( r'\badd esp\b|\badc esp\b', val2[f], re.M|re.I)
								subESP = re.match( r'\bsub esp\b|\bsbb esp\b', val2[f], re.M|re.I)
								if push:
									specAfter -=4
									# print "push \t\t" +  val2[f] + " spec: " + str(specAfter) 
								if pop:
									specAfter +=4
									# print "pop \t\t" +  val2[f] + "  spec:" + str(specAfter) 
								if addESP:
									specAddEsp = re.search( r'0x[0-9A-F]*', val2[f], re.M|re.I)
									specAddEsp2 = re.search( r'\d', val2[f], re.M|re.I)
									if (specAddEsp):
										result = specAddEsp.group()
										specAfter = specAfter + int(result,16)
										# print "addesp1: \t" + " spec:" +str(specAfter)
									if specAddEsp2:
										if not specAddEsp:
											result = specAddEsp2.group()
											specAfter = specAfter + int(result)
											# print "addesp12: \t" +" spec:" + str(specAfter)
								if subESP:
									specSubEsp = re.search( r'0x[0-9A-F]*', val2[f], re.M|re.I)
									specSubEsp2 = re.search( r'\d', val2[f], re.M|re.I)
									if (specSubEsp):
										result = specSubEsp.group()
										specAfter = specAfter - int(result,16)
										# print "subesp: \t" + " spec:" + str(specAfter)
									if specSubEsp2:
										if not specSubEsp:
											result = specSubEsp2.group()
											specAfter = specAfter - int(result)
											# print "subesp2: \t" +" spec:" + str(specAfter)


									jmpTEST= re.match( r2t, val2[d], re.M|re.I)
								if jmpTEST:
									# print "FOUND COMPLETE1"
									# print val2
									# print "jmp test!"
									# print val2[d]
									# print "*spec: " + str(specAfter)
									return True, specAfter

								f+=1
					jmpTEST= re.match( r2t, val2[d], re.M|re.I)			
					jmpTEST= re.match( r2t, val2[d], re.M|re.I)
					if jmpTEST:
						# print "FOUND COMPLETE2"
						# print val2
						# print "jmp test!"
						# print val2[d]
						# print "*spec: " + str(specAfter)
						return True, specAfter
					d+=1
			
			temp+=1
	return False, 0
#SPSuccess, spgadget, spbytes



val45 = []
val45.append("pop eax 0")
# val45.append("add esp, 0x234 ")
# val45.append("sub esp, 0x100 ")
val45.append("push ebx")
val45.append("pop eax 0")
val45.append("pop eax 0")
val45.append("xchg edx, eax")

val45.append("ret")

def checkItRet(val2,r1):	
	# print "looking Ret: " + r1 + " "
	# print val2
	for i,e in reversed(list(enumerate(val2))):
		temp = 0
		lim=len(val2)
		#print "lim " + str(lim)
		#print val2[temp]
		#print "lim " + str(lim)
		specAfter=0
		specBefore=0
		popStart = re.match( r'\bpop eax\b|\bpop ebx\b|\bpop ecx\b|\bpop edx\b|\bpop edi\b|\bpop esi\b|\bpop ebp\b|\bpop esp\b', val2[temp], re.M|re.I)
		if (popStart):
			#print "t0: " + str(temp) + " lim: " + str(lim)
			while (temp < lim):
				p ="pop "
				r = "ret"
				pu = "push "
				r1t=p+r1
				r1tPush=pu+r1
				# r2t=j+r2
				popTEST= re.match( r1t, val2[temp], re.M|re.I)
				retTEST= re.match( r, val2[temp], re.M|re.I)

				# jmpDEAX = re.match( r'\bjmp dword ptr [eax]\b', val2[temp], re.M|re.I)
				if popTEST:
					if (temp != 0):
						# print "No needs to be top"
						return False, 0
					# print "t1: " + str(temp) + " lim: " + str(lim)
					# print "pop test! " +val2[temp] + " # " + str(specAfter) 
					d=temp +1
					once = False
					while (d < lim):
						# popEAX = re.match( r'\bpop eax\b', val2[d], re.M|re.I)
						# popEBX = re.match( r'\bpop ebx\b', val2[d], re.M|re.I)
						# popECX = re.match( r'\bpop ecx\b', val2[d], re.M|re.I)
						# popEDX = re.match( r'\bpop edx\b', val2[d], re.M|re.I)
						# popEDI = re.match( r'\bpop edi\b', val2[d], re.M|re.I)
						# popESI = re.match( r'\bpop esi\b', val2[d], re.M|re.I)
						# popEBP = re.match( r'\bpop ebp\b', val2[d], re.M|re.I)
						# popESP = re.match( r'\bpop esp\b', val2[d], re.M|re.I)

						# if popEBP or popEBX:
						# 	specAfter +=4
						# 	print "doh " +  val2[d] + " # " + str(specAfter) 
						
						push= re.match( r'\bpush\b', val2[d], re.M|re.I)
						pop= re.match( r'\bpop\b', val2[d], re.M|re.I)
						addESP = re.match( r'\badd esp\b|\badc esp\b', val2[d], re.M|re.I)
						subESP = re.match( r'\bsub esp\b|\bsbb esp\b', val2[d], re.M|re.I)
						add = re.match( r'\badd\b|\badc\b', val2[d], re.M|re.I)
						sub = re.match( r'\bsub\b|\bsbb\b', val2[d], re.M|re.I)
						mov = re.match( r'\bmov\b', val2[d], re.M|re.I)
						xor = re.match( r'\bxor\b', val2[d], re.M|re.I)
						xchg = re.match( r'\bxchg\b', val2[d], re.M|re.I)
						s2=splitWordrs(val2[d])
						s3=splitWordrs2(val2[d])

						r1Test = re.search( r1, s2, re.M|re.I)
						r1Test2 = re.search( r1, s3, re.M|re.I)

						if add and r1Test:
							return False,0
						if xor and r1Test:
							return False,0
						if sub and r1Test:
							return False,0
						if mov and r1Test:
							return False,0
						if xchg and r1Test:
							return False,0
						if xchg and r1Test2:
							return False,0

						if push or pop or addESP or subESP:	
							# print "\t\tone: "+ val2[d]
							# if pop:
							# 	# print "second pop"
							if not once:
								once = True
								f=d
								while (f < lim):
									push= re.match( r'\bpush\b', val2[f], re.M|re.I)
									pop= re.match( r'\bpop\b', val2[f], re.M|re.I)
									addESP = re.match( r'\badd esp\b|\badc esp\b', val2[f], re.M|re.I)
									subESP = re.match( r'\bsub esp\b|\bsbb esp\b', val2[f], re.M|re.I)
									if push:
										specAfter -=4
										# print "push \t\t" +  val2[f] + " spec: " + str(specAfter) 
									if pop:
										specAfter +=4
										# print "pop \t\t" +  val2[f] + "  spec:" + str(specAfter) 
									if addESP:
										specAddEsp = re.search( r'0x[0-9A-F]*', val2[f], re.M|re.I)
										specAddEsp2 = re.search( r'\d', val2[f], re.M|re.I)
										if (specAddEsp):
											result = specAddEsp.group()
											specAfter = specAfter + int(result,16)
											# print "addesp1: \t" + " spec:" +str(specAfter)
										if specAddEsp2:
											if not specAddEsp:
												result = specAddEsp2.group()
												specAfter = specAfter + int(result)
												# print "addesp12: \t" +" spec:" + str(specAfter)
									if subESP:
										specSubEsp = re.search( r'0x[0-9A-F]*', val2[f], re.M|re.I)
										specSubEsp2 = re.search( r'\d', val2[f], re.M|re.I)
										if (specSubEsp):
											result = specSubEsp.group()
											specAfter = specAfter - int(result,16)
											# print "subesp: \t" + " spec:" + str(specAfter)
										if specSubEsp2:
											if not specSubEsp:
												result = specSubEsp2.group()
												specAfter = specAfter - int(result)
												# print "subesp2: \t" +" spec:" + str(specAfter)


										
									f+=1
						jmpTEST= re.match( r, val2[d], re.M|re.I)
						if jmpTEST:
							# print "FOUND COMPLETE"
							# print val2
							# print "ret test!"
							# #print val2[d]
							# print "*spec: " + str(specAfter)
							return True, specAfter
						d+=1
				
				temp+=1
	return False, 0

val4 = []
val4.append("pop eax 0")
val4.append("pop ebx 2")
val4.append("mov esp, eax ")
val4.append("mov esp, edi ")
val4.append("sub esp, 0x8")
val4.append("jmp edx")


val5=[]
val5.append("pop eax 0")
val5.append("jmp edx")

def checkItJmpPtr(val2,r):
	temp = 0
	lim=len(val2)
	specAfter=0
	specBefore=0
	popStart = re.match( r'\bpop eax\b|\bpop ebx\b|\bpop ecx\b|\bpop edx\b|\bpop edi\b|\bpop esi\b|\bpop ebp\b|\bpop esp\b', val2[temp], re.M|re.I)
	if (popStart):
		while (temp < lim):
			p ="pop "
			j = "jmp "
			pu = "push "
			r1t=p+r1
			r1tPush=pu+r1
			r2t=j+r2
			popTEST= re.match( r1t, val2[temp], re.M|re.I)
			jmpTEST= re.match( r2t, val2[temp], re.M|re.I)
			# print "temp: " + str(temp)
			if popTEST:
				if (temp != 0) or (lim > best):
					pass
					#print "No needs to be top"
					# print lim
					# print "NOOOOO"
					return False, 0
				# print "t1: " + str(temp) + " lim: " + str(lim)
				print "pop test! " +val2[temp] + " # " + str(specAfter) 
				d=temp +1
				once = False
				while (d < lim):
					popad= re.match( r'\bpopad\b|\bpopal\b', val2[d], re.M|re.I)
					popa= re.match( r'\bpopa\b', val2[d], re.M|re.I)
					pushad= re.match( r'\bpushal\b|\bpushad\b', val2[d], re.M|re.I)
					pusha= re.match( r'\bpusha\b', val2[d], re.M|re.I)
					
					push= re.match( r'\bpush\b', val2[d], re.M|re.I)
					pop= re.match( r'\bpop\b', val2[d], re.M|re.I)
					addESP = re.match( r'\badd esp\b|\badc esp\b', val2[d], re.M|re.I)
					subESP = re.match( r'\bsub esp\b|\bsbb esp\b', val2[d], re.M|re.I)

					if push or pop or addESP or subESP or popad or popa or pushad or pusha:
						return False,0
				
					jmpTEST= re.match( r2t, val2[d], re.M|re.I)
					if jmpTEST:
						# print "jmp test!"
						# #print val2[d]
						# print "*spec: " + str(specAfter)
						return True, specAfter
					d+=1
			
			temp+=1
	return False, 0
def checkItBest(val2,r1,r2, best):	
	#for i,e in reversed(list(enumerate(val2))):
	# print "cbest"
	# print r1+r2
	# print val2
	# print "inBESTCheckit POP " + r1 + "  JMP " + r2 

	temp = 0
	lim=len(val2)
	#print "lim " + str(lim)
	#print val2[temp]
	#print "lim " + str(lim)
	specAfter=0
	specBefore=0
	popStart = re.match( r'\bpop eax\b|\bpop ebx\b|\bpop ecx\b|\bpop edx\b|\bpop edi\b|\bpop esi\b|\bpop ebp\b|\bpop esp\b', val2[temp], re.M|re.I)
	if (popStart):
		#print "t0: " + str(temp) + " lim: " + str(lim)
		while (temp < lim):
			p ="pop "
			j = "jmp "
			pu = "push "
			r1t=p+r1
			r1tPush=pu+r1
			r2t=j+r2
			popTEST= re.match( r1t, val2[temp], re.M|re.I)
			jmpTEST= re.match( r2t, val2[temp], re.M|re.I)

			# jmpDEAX = re.match( r'\bjmp dword ptr [eax]\b', val2[temp], re.M|re.I)
			# print "temp: " + str(temp)
			# print r1t
			# print "val2[temp] " + val2[temp]
			if popTEST:
				# print "yes"
				if (temp != 0) or (lim > best):
					#print "No needs to be top"
					# print  "temp " + str(temp) + " lim " + str(lim) + " best " + str(best)
					# print "NOOOOO"
					return False, 0
				# print "t1: " + str(temp) + " lim: " + str(lim)
				# print "pop test! " +val2[temp] + " # " + str(specAfter) 
				d=temp +1
				once = False
				while (d < lim):
					# popEAX = re.match( r'\bpop eax\b', val2[d], re.M|re.I)
					# popEBX = re.match( r'\bpop ebx\b', val2[d], re.M|re.I)
					# popECX = re.match( r'\bpop ecx\b', val2[d], re.M|re.I)
					# popEDX = re.match( r'\bpop edx\b', val2[d], re.M|re.I)
					# popEDI = re.match( r'\bpop edi\b', val2[d], re.M|re.I)
					# popESI = re.match( r'\bpop esi\b', val2[d], re.M|re.I)
					# popEBP = re.match( r'\bpop ebp\b', val2[d], re.M|re.I)
					# popESP = re.match( r'\bpop esp\b', val2[d], re.M|re.I)

					# if popEBP or popEBX:
					# 	specAfter +=4
					# 	print "doh " +  val2[d] + " # " + str(specAfter) 
					popad= re.match( r'\bpopad\b|\bpopal\b', val2[d], re.M|re.I)
					popa= re.match( r'\bpopa\b', val2[d], re.M|re.I)
					pushad= re.match( r'\bpushal\b|\bpushad\b', val2[d], re.M|re.I)
					pusha= re.match( r'\bpusha\b', val2[d], re.M|re.I)
					
					push= re.match( r'\bpush\b', val2[d], re.M|re.I)
					pop= re.match( r'\bpop\b', val2[d], re.M|re.I)
					addESP = re.match( r'\badd esp\b|\badc esp\b', val2[d], re.M|re.I)
					subESP = re.match( r'\bsub esp\b|\bsbb esp\b', val2[d], re.M|re.I)
					add = re.match( r'\badd\b|\badc\b', val2[d], re.M|re.I)
					sub = re.match( r'\bsub\b|\bsbb\b', val2[d], re.M|re.I)
					mov = re.match( r'\bmov\b', val2[d], re.M|re.I)
					xor = re.match( r'\bxor\b', val2[d], re.M|re.I)
					xchg = re.match( r'\bxchg\b', val2[d], re.M|re.I)
					s2=splitWordrs(val2[d])
					s3=splitWordrs2(val2[d])

					r1Test = re.search( r1, s2, re.M|re.I)
					r1Test2 = re.search( r1, s3, re.M|re.I)

					if add and r1Test:
						return False,0
					if xor and r1Test:
						return False,0
					if sub and r1Test:
						return False,0
					if mov and r1Test:
						return False,0
					if xchg and r1Test:
						return False,0
					if xchg and r1Test2:
						return False,0

					if push or pop or addESP or subESP or popad or popa or pushad or pusha:
						# print "reallydumb"
						return False,0
				
					jmpTEST= re.match( r2t, val2[d], re.M|re.I)
					if jmpTEST:
						# print "jmp test!"
						# #print val2[d]
						# print "*spec: " + str(specAfter)
						return True, specAfter
					d+=1
			
			temp+=1
	return False, 0	
#SPSuccess, spgadget, spbytes
# print "\n\nStart checkIt\n\n"

# boolCheckIt, spec = checkIt(val4,"eax", "edx")


boolCheckIt, spec = checkItRet(val45,"eax")

#boolCheckIt, spec = checkItBest(val5,"eax", "edx", 2)
# print boolCheckIt
# print spec
# print "**ignore**"
#print "ans: " + str(doitNew(val3))


lT =[]
outputs = ()

def addlist(a,b,c,d):
	global outputs
	outputs = (a, b, c, d)
	lT.append(outputs)
addlist(1,2,3,4)
addlist(2,3,4,5)
# print outputs
# print lT


# print lT[1]
# print lT[1][0]


val4.append("pop eax 0")
val4.append("pop ebx 2")
val4.append("mov esp, eax ")
val4.append("mov esp, edi ")
val4.append("sub esp, 0x8")
val4.append("jmp edx")
# line="pop esi				0x40105a (offset 0x105a)"
val5=[]
val5.append("add esp, 0x10				0x401054 (offset 0x1054)")
val5.append("pop edi				0x401057 (offset 0x1057)")
val5.append("mov eax, esi				0x401058 (offset 0x1058)")
# val5.append("leave				0x40104c (offset 0x55c)")

val5.append("pop esi				0x40105a (offset 0x105a)")
val5.append("pop ebp				0x40105b (offset 0x105b)")
val5.append("ret				0x40105c (offset 0x105c)")

test="ret 				0x40105c (offset 0x105c)"
def splitter(stringReplace):
	array = stringReplace.split("offset 0x")
	new = ""
	for word in array:
		new =  word
	new2 = new.split(")")
	return new2[0]
def countLines(line):
	# print ("line", line )
	array = line.split("#")
	x=0
	for line in array:
		x+=1
	return( x	-3)
	# new3 = new1.split(",")

def splitterDG(word):
	array = word.split(" # ")
	new2 = []
	# print "splitterdg"

	for word in array:
		# print word
		new2.append(word)
	
	# print new2[2]
	return new2[2]

def giveLineNum(val2, line):
	# print "details"
	# for x in val2:
	# 	print x
	# 	print "\t\t"+splitter(x)
	# print "l: " + line

	
	val2.reverse()
	### WTF! not sure why they keep getting reversed wrong -- sometimes Ret at beginning, others at end--no rhyme or reason i can discern
	start = re.match( r'\bret\b', val2[0], re.M|re.I)
	if not start:
		# print "opps!"
		val2.reverse()

	
	if splitter(val2[0]) < splitter(val2[len(val2)-1]):
		# print "giveLine rev"
		val2.reverse()
	else:
		# print "glno rev"
		pass
	t=0
	TEXTO=splitter(line)
	# print "texto " + TEXTO
	my_regex = r"\b(?=\w)" + re.escape(TEXTO) + r"\b(?!\w)"

	# my_regex = r"\b" + re.escape(TEXTO) + r"\b"
	for x in val2:
		t+=1 # print "ok"
		check= re.match( TEXTO, splitter(x), re.M|re.I)
		# m = re.search('offset(.+?)\)', x)
		# print "c: " + splitter(x) + " ? " + splitter(TEXTO) +  " desired: " + line
		if check:
			# print "ok2"
			# print "returning: " + str(t)
			return t
		# if m:
		# 	found = m.group(1)
		# 	print "found: " + found
		# t+=1
# print "ans " + str(giveLineNum(val5, line))

# print splitter(test)


def stupidPre(val2, num):
	global cutting
	res = []
	bad = 0

	if splitter(val2[0]) < splitter(val2[len(val2)-1]):
		# print "yep"
		pass
	else:
		# print "nah"
		pass

	start = re.match( r'\bret\b', val2[0], re.M|re.I)
	if not start:
		# print "opps1!"
		val2.reverse()
	t=0
	limit=num #len(val2)-(num)
	for x in val2:
	# for i in val2: #   #was +1
	#	print i
		# print "t: " + str(t) 
		matchObj3 = re.compile( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b|\bptr\b')

		
		if matchObj3.search(x):
			bad = bad + 1
			if bad < 2:
				# print "bad2" + str(t) + " x: " + x
				res.append(str(x))
			if bad > 1:
				# print "bad3 "  + str(t) + " x: " + x
				return False
		else:	
			if bad < 2 : 
				res.append(x)
		t+=1
		if limit == t:
			# print "return True" 
			return True
	# print "res: " + str(len(res))
	# for x in res:
	# 	print x
	# print "return True2" 
	return True

def stupidPreJ(val2, num):
	global cutting
	res = []
	bad = 0
	# print "***********PRESTUPIDJ"

	start = re.match( r'\bjmp\b|\bcall\b', val2[0], re.M|re.I)
	if not start:
		# print "opps2!"
		val2.reverse()
	t=0

	if splitter(val2[0]) < splitter(val2[len(val2)-1]):
		# print "jrev"
		val2.reverse()
	else:
		# print "no rev"
		pass


	limit=num#len(val2)-(num)
	# print "limit "  + str(limit) + " num: " + str(num) + " size: " + str(len(val2))
	for x in val2:
	# for i in val2: #   #was +1
	#	print i
		# print "t: " + str(t) + " x: " + x
		# matchObj3 = re.compile( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b|\bptr\b')


		# if matchObj3.search(x):
		matchObj3 = re.search( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b', x, re.M|re.I)

		if matchObj3:
			bad = bad + 1
			if bad < 2:
				# print "bad2 " + str(t) + " x: " + x
				res.append(str(x))
			if bad > 1:   ###### WAS 1 - missing small ones - fixed it - 2 - not sure original logic behind this
				# print "bad3 "  + str(t) + " x: " + x
				# print  matchObj3.search(x)
				return False
		else:	
			if bad < 2 : 
				res.append(x)
		t+=1
		if limit == t:
			# print "return True" 
			return True
	# print "res: " + str(len(res))
	# for x in res:
	# 	print x
	# print "return True2" 
	return True

def stupidPreJk(val2, num):
	global cutting
	res = []
	bad = 0
	# print "***********PRESTUPIDJ"

	start = re.match( r'\bjmp\b|\bcall\b', val2[0], re.M|re.I)
	if not start:
		# print "opps2!"
		val2.reverse()
	t=0

	if splitter(val2[0]) < splitter(val2[len(val2)-1]):
		# print "jrev"
		val2.reverse()
	else:
		# print "no rev"
		pass


	limit=num#len(val2)-(num)
	# print "limit "  + str(limit) + " num: " + str(num) + " size: " + str(len(val2))
	print ("length", len(val2))
	for x in val2:
	# for i in val2: #   #was +1
	#	print i
		# print "t: " + str(t) + " x: " + x
		print x
		print ("Bad",bad)
		# matchObj3 = re.compile( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b|\bptr\b'))


		# matchObj3 =re.search(x)
		matchObj3 = re.search( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b', x, re.M|re.I)

		if matchObj3:
			bad = bad + 1
			print ("adding bad", bad, x)
			if bad < 2:
				# print "bad2 " + str(t) + " x: " + x
				res.append(str(x))
			if bad > 1:

				print ("FALSEY", bad)
				# print "bad3 "  + str(t) + " x: " + x
				# print  matchObj3.search(x)
				return False
		else:	
			if bad < 2 : 
				res.append(x)
		t+=1
		if limit == t:
			# print "return True" 
			return True
	# print "res: " + str(len(res))
	# for x in res:
	# 	print x
	# print "return True2" 
	return True

y =stupidPre(val5, 1)
# for x in val:
# 	print x
# print y

dog = [1, 2, 3,4]

x =5

# if x not in dog:
# 	print "ok"
# 	dog.append(x)


vald1 = []
vald1.append("pop ebx				0x401703 (offset 0x1703)")
vald1.append("xor ebx, ebx				0x401704 (offset 0x1704)")
vald1.append("sub ebx, edx				0x401705 (offset 0x1705)")
# vald1.append("pushad")
vald1.append("ret 				0x401707 (offset 0x1707)")


def checkForBadRegs(main, r1):
	# print main
	for x in main:
		add = re.match( r'\badd\b|\badc\b', x, re.M|re.I)
		sub = re.match( r'\bsub\b|\bsbb\b', x, re.M|re.I)
		mov = re.match( r'\bmov\b', x, re.M|re.I)
		xor = re.match( r'\bxor\b', x, re.M|re.I)
		pop = re.match( r'\bpop\b', x, re.M|re.I)
		xchg = re.match( r'\bxchg\b', x, re.M|re.I)
		popad= re.match( r'\bpopad\b|\bpopal\b', x, re.M|re.I)
		popa= re.match( r'\bpopa\b', x, re.M|re.I)
		pushad= re.match( r'\bpushal\b|\bpushad\b', x, re.M|re.I)
		pusha= re.match( r'\bpusha\b', x, re.M|re.I)
		s2=splitWordrs(x)
		s3=splitWordrs2(x)
		r1Test = re.search( r1, s2, re.M|re.I)
		r1Test2 = re.search( r1, s3, re.M|re.I)


		if popad or popa or pushad or pusha:
			return False
		if add and r1Test:
			return False
		if xor and r1Test:
			return False
		if sub and r1Test:
			return False
		if pop and r1Test:
			return False
		if mov and r1Test:
			return False
		if xchg and r1Test:
			return False
		if xchg and r1Test2:
			return False
	return True


vald = []
vald.append("pop eax				0x401703 (offset 0x1703)")
# vald.append("xor ebx, ebx				0x401704 (offset 0x1704)")
# vald.append("sub ebx, edx				0x401705 (offset 0x1705)")
vald.append("ret 				0x401707 (offset 0x1707)")



def checkItRetBest(val2,r1, best):	
	# print "checkitbest"
	# for x in val2:
	# 	print x
	# print "done"
	r1=r1.lower()
	temp = 0
	lim=len(val2)
	# print val2
	specAfter=0
	specBefore=0
	popStart = re.match( r'\bpop eax\b|\bpop ebx\b|\bpop ecx\b|\bpop edx\b|\bpop edi\b|\bpop esi\b|\bpop ebp\b|\bpop esp\b', val2[temp], re.M|re.I)
	if (popStart):
		# print "t0: " + str(temp) + " lim: " + str(lim)
		while (temp < lim):
			p ="pop "
			ret = "ret"
			pu = "push "
			r1t=p+r1
			r1tPush=pu+r1
			popTEST= re.match( r1t, val2[temp], re.M|re.I)
			retTEST= re.match( ret, val2[temp], re.M|re.I)
			
			if popTEST:
				# print "yes " +  str(best) + " " +  val2[temp]
				if (temp != 0) or (lim > best):
					#print "No needs to be top"
					# print  "temp " + str(temp) + " lim " + str(lim) + " best " + str(best)
					# print "NOOOOO"
					return False, 0
				d=temp+1
				once = False
				while (d < lim):

					# print "while: " + val2[d]
					s2=splitWordrs(val2[d])
					# r1Test = re.search( r1, s2, re.M|re.I)
					# print "s2:" + s2
					popad= re.match( r'\bpopad\b|\bpopal\b', val2[d], re.M|re.I)
					popa= re.match( r'\bpopa\b', val2[d], re.M|re.I)
					pushad= re.match( r'\bpushal\b|\bpushad\b', val2[d], re.M|re.I)
					pusha= re.match( r'\bpusha\b', val2[d], re.M|re.I)
					push= re.match( r'\bpush\b', val2[d], re.M|re.I)
					pop= re.match( r'\bpop\b', val2[d], re.M|re.I)
					addESP = re.match( r'\badd esp\b|\badc esp\b', val2[d], re.M|re.I)
					subESP = re.match( r'\bsub esp\b|\bsbb esp\b', val2[d], re.M|re.I)
				
					add = re.match( r'\badd\b|\badc\b', val2[d], re.M|re.I)
					sub = re.match( r'\bsub\b|\bsbb\b', val2[d], re.M|re.I)
					mov = re.match( r'\bmov\b', val2[d], re.M|re.I)
					xor = re.match( r'\bxor\b', val2[d], re.M|re.I)
					xchg = re.match( r'\bxchg\b', val2[d], re.M|re.I)
					s2=splitWordrs(val2[d])
					s3=splitWordrs2(val2[d])

					r1Test = re.search( r1, s2, re.M|re.I)
					r1Test2 = re.search( r1, s3, re.M|re.I)

					if add and r1Test:
						return False,0
					if xor and r1Test:
						return False,0
					if sub and r1Test:
						return False,0
					if mov and r1Test:
						return False,0
					if xchg and r1Test:
						return False,0
					if xchg and r1Test2:
						return False,0
					if push or pop or addESP or subESP or popad or popa or pushad or pusha:
						# print "reallydumb"
						return False,0
				
					retTEST= re.match( ret, val2[d], re.M|re.I)
					if retTEST:
						# print "jmp test!"
						# #print val2[d]
						# print "*spec: " + str(specAfter)
						return True, specAfter
					d+=1			
			temp+=1
	return False, 0	

# print "final"
# print checkItRetBest (vald,"EAX", 5)

# line = "mov eax, ebx"
# print splitWordrs(line)

def paddingMaker4Bytes(a, num):
	a = a-1
	pad0=num*"\t"
	if (a==0):
		pad =  "\n"+pad0+"0x41414141 "
	elif (a>0):
		pad =  "\n"+pad0+"0x41414141, "
	pad2 = a * "0x41414141, "
	x=(len(pad2))
	pad2=pad2[0:(x-2)] # fix my
	return pad + pad2 + " # padding for dispatch table (" + str(hex((a+1)*4)) + " bytes)\n"
	#		addArray.append(fixHexAddy(add4) + " # " + "(base + " + addb + ") ")


word="add esp, 0x10 # "
def paddingMaker1( a):
	c=a
	text2=""
	text="\t\t"
	if (a>3):
		try:
			b=a/4
		except:
			b=0
			a=0
		try:
			modb= a % 4  # modulo, remainder
		except:
			modb=0
	else:
		b=0
		modb =a %4
	text+=b*"0x42424242, "
	if modb >0:
		text+="0x" + modb*"43" + ","
	# x=(len(text))
	# text=text[0:(x-2)] # fix my
	text3="\t# padding  (" + str(hex((c))) + " bytes)\n"
	text +=text2 + text3

	if a ==0:
		text="\t\t0x41424142, #\t padding for dispatch table ( 0x4 bytes)\n"
		#### Remove do not use
		text = ""
		# a=0
	# text = "\t\tJOP_Pad, # \t padding for dispatch table (" + str(hex((c))) + " bytes)\n"
	# if a ==0:
		# text = "\t\tJOP_Pad, # \t padding for dispatch table\n"
	return text
def paddingMaker1DG( a, dgFound):
	c=a
	text2=""
	text="\t\t"
	if (a>3):
		try:
			b=a/4
		except:
			b=0
			a=0
		try:
			modb= a % 4  # modulo, remainder
		except:
			modb=0
	else:
		b=0
		modb =a %4
	text+=b*"0x42424242, "
	if modb >0:
		text+="0x" + modb*"43" + ","
	# x=(len(text))
	# text=text[0:(x-2)] # fix my
	text3="\t# padding  (" + str(hex((c))) + " bytes)\n"
	text +=text2 + text3

	if a ==0:
		# text="\t\t0x41424142, #\t padding for dispatch table ( 0x4 bytes)\n"
		#### Remove do not use
		text = ""
		# a=0
	# text = "\t\tJOP_Pad, # \t padding for dispatch table (" + str(hex((c))) + " bytes)\n"
	# if a ==0:
		# text = "\t\tJOP_Pad, # \t padding for dispatch table\n"
	if not dgFound:
		text = "\t\t0x45454545, # \t No DG found - placeholder padding (4 bytes)\n"
	return text
def paddingMaker1_var( a, dgFound):
	c=a
	text2=""
	text="\t\t"
	if (a>3):
		try:
			b=a/4
		except:
			b=0
			a=0
		try:
			modb= a % 4  # modulo, remainder
		except:
			modb=0
	else:
		b=0
		modb =a %4
	text+=b*"0x42424242, "
	if modb >0:
		text+="0x" + modb*"43" + ","
	# x=(len(text))
	# text=text[0:(x-2)] # fix my
	text3="\t# padding  (" + str(hex((c))) + " bytes)\n"
	text +=text2 + text3

	# if a ==0:
	# 	text="\t\t0x41424142, #\t padding for dispatch table ( 0x4 bytes)\n"
	# 	#### Remove do not use
	# 	text = ""
	# 	# a=0
	# text = "\t\tJOP_Pad, # \t padding for dispatch table (" + str(hex((c))) + " bytes)\n"
	if a ==0:
		# text = "\t\tskip, # \t padding for dispatch table\n"
		text = ""
	if not dgFound:
		text = "\t\t0x45454545, # \t No DG found - placeholder padding (4 bytes)\n"
	return text

def paddingMaker1_varH( a):
	c=a
	text2=""
	text="\t\t"
	if (a>3):
		try:
			b=a/4
		except:
			b=0
			a=0
		try:
			modb= a % 4  # modulo, remainder
		except:
			modb=0
	else:
		b=0
		modb =a %4
	text+=b*"0x42424242, "
	if modb >0:
		text+="0x" + modb*"43" + ""
	# x=(len(text))
	# text=text[0:(x-2)] # fix my
	# text3="\t# padding  (" + str(hex((c))) + " bytes)\n"
	# text +=text2 + text3

	if a ==0:
		text="\t\t0x41424142 #\t padding for dispatch table ( 0x4 bytes)\n"
		#### Remove do not use
		text = ""
		# a=0
	# text = "\t\tJOP_Pad, # \t padding for dispatch table (" + str(hex((c))) + " bytes)\n"
	# if a ==0:
		# text = "\t\tJOP_Pad, # \t padding for dispatch table\n"
	return text

# print paddingMaker1(6)

# print checkForBadRegs(vald1, "EAX")