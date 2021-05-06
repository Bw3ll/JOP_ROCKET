from checkIt import *
import math
class StackPivotClass:
	def _init_(self): #, name):
		"""Initializes the data."""
		self.best =[]
		self.bestByt=[]
		self.bestBytMultiplier=[]

		self.NeedBest=[]
		self.NeedBestByt=[]

		self.NeedNextBest =[]
		self.NeedNextBestByt =[]
		self.NeedNextBestBytMultiplier =[]
		self.NextBestPerfect=[]

		self.res=0  #multipier - res * mainbyt = total
		self.total=0
		self.mainByt=0
		self.main=""
		self.Perfect = False # if first gadget stack pivot = desired
		self.PerfectHelp=[]
		self.PerfectHelp2=[]
		self.NeedMultiplier =[]
		self.StillNeed=[]
		self.bytCnt=0
		self.bytCnt2=0
		self.bytCnt3=0
		
def stackNew():
	global SPobjs
	SPobj = StackPivotClass()
	SPobj._init_()
	SPobjs.append(SPobj)

SPobjs = []
#stackNew()

main2 = []
byt2 =[]
main2.append("0x401591 # push eax # push ecx # xor eax, eax # jmp edx")
main2.append("0x4015d0 # (base + 0x15d0) add esp, 4 # jmp edx #")
main2.append("0x4015d5 # (base + 0x15d5) add esp, 8 # jmp edx ")
main2.append("0x4016f4 # (base + 0x16f4) add esp, 8 # jmp edx")
main2.append("0x401622 # (base + 0x1622) add esp, 0xc # inc eax # jmp edx")
main2.append("0x4016f9 # (base + 0x16f9) add esp, 0x10 # jmp edx # ")
main2.append("0x4016fe # (base + 0x16fe) add esp, 0x18 # jmp edx # ")
main2.append("0x4015e6 # (base + 0x15e6) add esp, 0x894 # mov ebp, esp # jmp edx")
main2.append("0xdeadc0 # [not real - here for 6 bytes]")
main2.append("0xdeadf3 # [FAKE not real - here for 3 byte]")
main2.append("0xffffff # [FAKE not real - here for 3 byte]")
# main2.append("0xdeaeff #[FAKE not real - here for 5 byte]")
byt2.append(-8)
byt2.append(4)
byt2.append(8)
byt2.append(8)
byt2.append(12)
byt2.append(16)
byt2.append(24)
byt2.append(2196)
byt2.append(6)
byt2.append(3)
byt2.append(3)
byt2.append(5)
byt3=[]
byt3.append(-8)
byt3.append(0)
byt3.append(0)
byt3.append(0)
byt3.append(4)
byt3.append(8)
byt3.append(8)
byt3.append(12)
byt3.append(16)
byt3.append(24)
byt3.append(2196)

#desired

desired=113.0 #113.0   #190
desiredMax=333.0 #337.0
# desired=401.0 #113.0   #190
# desiredMax=2001.0 #337.0    
#######NOTE: perfect max is broken - have an odd number, to ensure imperfect success (padding)


# desired = 0x1120
# desiredMax = 0x1400

truthLimit=3
PerfectOutputs=[]
PerfectHelpOutputs=[]
PerfectHelp2Outputs=[]

v=0
def addtoEsp(main, byt, Reg):

	global v
	global desired
	global desiredMax
	# print "desired:  "  + str(desired) + "  DESIREDMAX " + str(desiredMax)

	y = len(byt)-1
	best =[]
	bestByt=[]
	NeedBest=[]
	NeedBestByt=[]
	NeedNextBest =[]
	NeedNextBestByt =[]

	# print "main2"
	b=0
	# for x in main:
	while (b < len(main)):
		if (len(main)==0):
			# print "cutting"
			break
		# print "main lenght + " +  str(len(main))
		# print "b" + str(b)
		truth=checkForBadRegs(splitterRetval2(main[b]), Reg)
		if not truth:
			
			# print "tis bad " + Reg + "    "   + main[b]
			# print len(main)
			del main[b]
			del byt[b]
			b-=2
			y-=1
			# print len(main)
			# for x in main:
			# 	print x


		b+=1
		# break

	for i in reversed(byt):
		# print "*^*^*^*^**^^*^**^^*^*"
		# print i
		# print main[y]
		#print i
		if (i==0):
			# print "000"
			break
		stackNew()	
		SPobjs[v].mainByt = i
		SPobjs[v].main = main[y]
		y-=1

		if i <= desired:
			#print "vh " + str(v)
			# print "spbojs: " + str( len(SPobjs))
			res=desired/i
			# print res
			# res=math.floor(abs(res))
			res=math.floor(res)

			# print res
			SPobjs[v].res = res
			total = res*i
			SPobjs[v].total=total
			SPobjs[v].StillNeed= desired-total
			# print "SPobjs[v].stillNeed: " + str(SPobjs[v].StillNeed)
			DesiredWiggleRoom=desiredMax-desired
			# print "byt=" + str(i) + " |  desired=" +  str(desired) + " | res=" + str(res) + " | total=" + str(total)
			if (total == desired):   # PERFECT match
				best.append(main[y+1])
				bestByt.append(i)
				#v=0
				SPobjs[v].best.append(main[y+1])
				SPobjs[v].bestByt.append(i)
				SPobjs[v].bestBytMultiplier.append(res)
				SPobjs[v].Perfect = True
				# print "\t\tbest " +  str(main[y+1]) + "   " + str(i)

			if (total < desired):  # NOT PERFECT, but still may be perfect indirectly
				need = desired-total#				need = desired-abs(total)



				# print "\t\tNEED: " +  str(need)
				t=len(byt)-1
				# print "t " + str(t)
				for k in reversed(byt):
					if (k==0):
						break
					# print "k " + str(k) + " need " + str(need)
					if (k < (need+DesiredWiggleRoom)) and (k >0): #if (abs(k) < (need+DesiredWiggleRoom)):
						# if (abs(k) < (need+DesiredWiggleRoom)):
						# print "\t\t\t-k>" + str(abs(k))
						# print "\t\t\t\tindex t:  "+ str(t)
						# print "\t\t\t\t--* " +  main[t] + " "  + str(k)
					
						ans = SPobjs[v].StillNeed /k
						ans=math.floor(ans) #math.floor(abs(ans))
						# print "\t\t\t\tneed multiplier: " + str(ans)
						SPobjs[v].NeedMultiplier.append(ans)
						# print  "\t\t\t\tneed multiplier * bytes= "  + str(ans*k)
						# print "\t\t\t\tstill needed:" + str(SPobjs[v].StillNeed)
						ans2 = SPobjs[v].StillNeed - (ans*k)
						# print "\t\t\t\tstill required?: " + str(ans2)

						DesiredWiggleRoom=desiredMax-desired
						if (ans2 < k):
							# print "\\nadd k? " + str(k)
							# print "left now?  " + str(ans2-k) + "\n"
							# print "DesiredWiggleRoom " + str(DesiredWiggleRoom) + " ans2-k " +  str(abs(ans2-k)) + " ans2 " + str(ans2)
							if ((DesiredWiggleRoom >  (ans2-k)) & (0 != ans2)):# abs(ans2-k)) & (0 != ans2)):

							#if (DesiredWiggleRoom > abs(ans2-k)):
								# print "\nif ((DesiredWiggleRoom > abs(ans2-k)) & (0 != ans2))"
								# print DesiredWiggleRoom
								# print abs(ans2-k)
								# print ans2-k
								# print str(DesiredWiggleRoom - abs(ans2-k)) + " is less than " + str(DesiredWiggleRoom)
								
								val = len(SPobjs[v].NeedNextBestBytMultiplier) -1
								# print val
								try:
									SPobjs[v].NextBestPerfect.append(True)
									# print SPobjs[v].NeedNextBestBytMultiplier[val]
									SPobjs[v].NeedNextBestBytMultiplier[val] = SPobjs[v].NeedNextBestBytMultiplier[val] + 1
									# print SPobjs[v].NeedNextBestBytMultiplier[val]

								except:
									pass
							elif (DesiredWiggleRoom > (ans2-k)) and (0 == ans2): #elif ((DesiredWiggleRoom > abs(ans2-k)) & (0 == ans2)):							elif ((DesiredWiggleRoom > abs(ans2-k)) & (0 == ans2)):

								# print "\nelif ((DesiredWiggleRoom > abs(ans2-k)) & (0 == ans2))"
								# print "3DesiredWiggleRoom  " + str(DesiredWiggleRoom) + " ans2-k " +  str(abs(ans2-k)) + " ans2 " + str(ans2)
								# print "Falsification0    zero"
								SPobjs[v].NextBestPerfect.append(True)
							else: 
								# print "Falsification1"
								SPobjs[v].NextBestPerfect.append(False)
						else: 
							# print "Falsification2"
							SPobjs[v].NextBestPerfect.append(False)
							
						jans = SPobjs[v].StillNeed /k
						jans2 = math.ceil(jans)

						info=""
						info = "\n \tDEBUG: \n\tans2 " + str(ans2) + "   k: " +str(k) + " stillneed "+  str(SPobjs[v].StillNeed) + " jans2 " + str(jans2) + " ans " +str(ans) +"\n\t\t\t\t\t\t\t\t\t "
						jans=0.0

						SPobjs[v].NeedNextBest.append(main[t] )#  + info)
						SPobjs[v].NeedNextBestByt.append(k)
						if ans ==0:
							SPobjs[v].NeedNextBestBytMultiplier.append(ans)
						elif (ans >1) & ((jans2-ans)==1):
							#duh=raw_input()
							SPobjs[v].NeedNextBestBytMultiplier.append(ans)
						else:
							SPobjs[v].NeedNextBestBytMultiplier.append(jans2)
						SPobjs[v].PerfectHelp2.append(True)  ##added perfecthelp2

					if (abs(k) == need):
						# print "\nif (abs(k) == need)\n\t\t\tPerfect match->" + str(abs(k)) +" k:" + str(k)
						# print "\t\t\t\t index: "+ str(t)
						# print "\t\t\t\t." +  main[t] + " "  + str(k)
						SPobjs[v].NeedBest.append(main[t])
						SPobjs[v].NeedBestByt.append(k)
						SPobjs[v].Perfect=True
						SPobjs[v].PerfectHelp.append(True)
						SPobjs[v].StillNeed=0
					t-=1
		v=v+1

		if not (len(byt) == v):  #check to make sure we don't get one too many
			#stackNew()	   #reimplemented it at the top
			pass		

kk=0
def print2():
	global kk
	print "\n\n\n**[print2]**\n"
	for each in SPobjs:
		print "k: " + str(kk) + " desired:  " + str(desired)
		print "res: " + str(SPobjs[kk].res) + " total: " +str(SPobjs[kk].total)
		print "mainByt: " + str(hex(SPobjs[kk].mainByt)) 
		print "main: " + SPobjs[kk].main
		print SPobjs[kk].best
		print SPobjs[kk].bestByt
		print SPobjs[kk].bestBytMultiplier
		print "need best"
		print SPobjs[kk].NeedBest
		print SPobjs[kk].NeedBestByt
		print "need next best"
		print SPobjs[kk].NeedNextBest
		print SPobjs[kk].NeedNextBestByt
		print SPobjs[kk].NeedNextBestBytMultiplier	
		z=0
		print "\nmultipier result"
		for each in SPobjs[kk].NeedNextBestBytMultiplier:
			print "result: " + str(SPobjs[kk].NeedNextBestByt[z] * SPobjs[kk].NeedNextBestBytMultiplier[z]) + "   multipier:  " +str(SPobjs[kk].NeedNextBestBytMultiplier[z])
			z=z+1
		print "still need " + str( SPobjs[kk].StillNeed)
		if SPobjs[kk].Perfect:
			print "yes perfect"
		else:
			print "Not Perfect"
		print SPobjs[kk].Perfect
		z=0
		for each in SPobjs[kk].NeedNextBestByt:
			print "x-total: " + str(desired - (SPobjs[kk].total + (SPobjs[kk].NeedNextBestByt[z] * SPobjs[kk].NeedNextBestBytMultiplier[z]) ))
			try:
				print "NextBestPerfect? " + str(SPobjs[kk].NextBestPerfect[z])
			except:
				pass
			print "desired? " +str(desired)
			print "plus add: " +str((SPobjs[kk].NeedNextBestByt[z] * SPobjs[kk].NeedNextBestBytMultiplier[z]))
			print "**total bytes: " + str( SPobjs[kk].total + (SPobjs[kk].NeedNextBestByt[z] * SPobjs[kk].NeedNextBestBytMultiplier[z])   )
			print "\n"
			z=z+1
		kk=kk+1
		# print "\n****************************\n"

def buildStackPivotOutput():
	PerfectOutputs=[]
	PerfectHelpOutputs=[]
	PerfectHelp2Outputs=[]
	NotPerfect=[]
	Outputs=[]
	kk=0
	truth=0
	# print "\n\n*********************************\n**[building stack pivot output]**\n*********************************\n"
	for each in SPobjs:

		if SPobjs[kk].Perfect:
			SPobjs[kk].bytCnt=0
			# print  "desired: " +str(desired) + " main bytes: " + str(hex(SPobjs[kk].mainByt)) + " \nmain: "
			# print SPobjs[kk].main
			# print "res: " + str(SPobjs[kk].res) + " total: " + str(SPobjs[kk].total) +  " PerfectHelp? " + str(SPobjs[kk].PerfectHelp) + "\n\n"

			out =""
			#SPobjs[kk].bytCnt= 0#SPobjs[kk].mainByt
			#out = str(SPobjs[kk].main) + " [" +str(hex(SPobjs[kk].mainByt)  ) + " bytes] \n"


			intRes = int(SPobjs[kk].res)
			for i in range(intRes):
				SPobjs[kk].bytCnt=SPobjs[kk].mainByt  + SPobjs[kk].bytCnt
				if (i==0):
					out = "\n" + str(SPobjs[kk].main) + " [" +str(hex(SPobjs[kk].mainByt)  ) + " bytes] "  + str(hex(SPobjs[kk].bytCnt)) + "\n"#intRes*out
				else:
					out = out + str(SPobjs[kk].main) + " [" +str(hex(SPobjs[kk].mainByt)  ) + " bytes] "  + str(hex(SPobjs[kk].bytCnt)) + "\n"#intRes*out
			SPobjs[kk].bytCnt2 = SPobjs[kk].bytCnt
			vvv=0
			out2=""
			out3=""
			out5=""
			out4=""
			JustOnce=False
			JustOnce2=False
			FinalBytes =SPobjs[kk].total 
			bestOut=""


			# print "buildStackPivotOutput"
			#####  PERFECT OUTPUT  ##############################################
			if (SPobjs[kk].total==desired):
				SPobjs[kk].bytCnt=0
				for i in range(intRes):
					SPobjs[kk].bytCnt+= SPobjs[kk].bestByt[0]
					if (i==0):
						bestOut = "\n"+ SPobjs[kk].best[0] + " [" +str(hex(SPobjs[kk].bestByt[0])) + " bytes] "  + str(hex(SPobjs[kk].bytCnt)) + " \n"#+ " " +str(kk) + "  Best\n"
					else:
						bestOut = bestOut + SPobjs[kk].best[0] + " [" +str(hex(SPobjs[kk].bestByt[0])) + " bytes] "  + str(hex(SPobjs[kk].bytCnt)) + " \n"#+ " " +str(kk) + "  Best\n"
				bestOut += "\t\t# B----> STACK PIVOT TOTAL: " + str(hex(SPobjs[kk].bytCnt)) + " bytes\n" 
				SPobjs[kk].bytCnt =0
				if bestOut not in PerfectOutputs:
					PerfectOutputs.append(bestOut)

			# print "buildStackPivotOutput2"


			#### temporarily broken, disabled until fixed!!!!!
			
			########## PERFECT , WITH PERFECT HELP 1  #######################
			# for ttt in SPobjs[kk].PerfectHelp:
				# JustOnce=False
				# if SPobjs[kk].PerfectHelp[vvv]: #(5 > 7): #
				# 	# print "vvv " +str(vvv)  + "in PerfectHelp\n"
				# 	test=0
				# 	if (vvv==0):   # Just checks the first one--we only need one. Do not need 100 different permutations
				# 		SPobjs[kk].bytCnt= SPobjs[kk].bytCnt+ SPobjs[kk].NeedBestByt[test]
				# 		if not JustOnce:
				# 			out2 = SPobjs[kk].NeedBest[test] + " [" +str(hex(SPobjs[kk].NeedBestByt[test])) + " bytes] "  + str(hex(SPobjs[kk].bytCnt)) +  " bytes\n"# "+ str(kk) + "$PH)\n"
				# 			#SPobjs[kk].bytCnt= SPobjs[kk].bytCnt+ SPobjs[kk].NeedBestByt[test]
				# 			#out2=out2 + str(hex(SPobjs[kk].bytCnt)) +"\n"
				# 			FinalBytes = FinalBytes + SPobjs[kk].NeedBestByt[test]
				# 		test=test+1
				# 	#done=True
				# 		out3= "\t\t# $----> STACK PIVOT TOTAL: " +str(hex(FinalBytes)) + " bytes   " + str(hex(SPobjs[kk].bytCnt))  +  "***\n"
				# 		SPobjs[kk].bytCnt =0
				# if (vvv >=00):
				# 	if (truth <= truthLimit):
				# 		PerfectHelpOut1 =  out + out2 + out3 
				# 		# print PerfectHelpOut1
				# 		if PerfectHelpOut1 not in PerfectHelpOutputs:
				# 			PerfectHelpOutputs.append(PerfectHelpOut1)
				# vvv=vvv+1

		# print "buildStackPivotOutput3"
###     PERFECT HELP 2 PROLOGUE  ##############################################
		out="\n"
		intRes = int(SPobjs[kk].res)
		FinalBytes =SPobjs[kk].total 
		for i in range(intRes):
			SPobjs[kk].bytCnt3=SPobjs[kk].mainByt  + SPobjs[kk].bytCnt3
			out = out + str(SPobjs[kk].main) + " [" +str(hex(SPobjs[kk].mainByt)  ) + " bytes]** "  + str(hex(SPobjs[kk].bytCnt3)) + "\n"#intRes*out
		SPobjs[kk].bytCnt3 =0
		vvv=0
		truth=0
		if not SPobjs[kk].Perfect:
			# print "In Not Perfect"
			#for ttt in SPobjs[kk].PerfectHelp2:	
			for index, ttt in enumerate(SPobjs[kk].PerfectHelp2):	
				out4=""
				JustOnce2=False
				# print "contents perfecthelp2:"
				# print SPobjs[kk].PerfectHelp2
				# print "index: " + str (index)  + "  vvv: "  + str(vvv)
				if  SPobjs[kk].PerfectHelp2[vvv]:
					# print "vvv " +str(vvv)
					# print "In PerfectHelp2 !!!!"
					#umm=raw_input()
					test=0
					if (index >=0):  # Just checks the first one--we only need one. Do not need 100 different permutations
						multCnt=SPobjs[kk].NeedNextBestBytMultiplier[vvv]
						test2= SPobjs[kk].mainByt * intRes
						SPobjs[kk].bytCnt2= test2+ SPobjs[kk].NeedNextBestByt[vvv]
						
						out4 = SPobjs[kk].NeedNextBest[vvv] + " [" +str(hex(SPobjs[kk].NeedNextBestByt[vvv])) + " bytes] "  + str(hex(SPobjs[kk].bytCnt2)) + "\n" # +str(kk) + " NP*     " +"\n"
						#debug
						#out4+= "     ***debug:   main: " + str(SPobjs[kk].main) + "\tNext Best: " +str(SPobjs[kk].NeedNextBest[vvv])+ " Mult:  " +  str(SPobjs[kk].NeedNextBestBytMultiplier[vvv]) + " \n"
						if not JustOnce2:
							#print "mutlcnt " + str(multCnt)  + "  bytcnt2  " + str(hex(SPobjs[kk].bytCnt2))
							#ok=raw_input()

							while (multCnt>1):
							#	print "mutlcnt " + str(multCnt) + "  bytcnt2  " + str(hex(SPobjs[kk].bytCnt2))
								SPobjs[kk].bytCnt2= SPobjs[kk].bytCnt2+ SPobjs[kk].NeedNextBestByt[vvv]
								#out4=out4 + str(hex(SPobjs[kk].bytCnt)) +"\n"
								if (SPobjs[kk].bytCnt2 < desired):
									FinalBytes = FinalBytes + SPobjs[kk].NeedNextBestByt[vvv]
									if (SPobjs[kk].NextBestPerfect[vvv] == True):
										out4 = out4 + SPobjs[kk].NeedNextBest[vvv] + " [" +str(hex(SPobjs[kk].NeedNextBestByt[vvv])) + " bytes] "  + str(hex(SPobjs[kk].bytCnt2))  +" ** \n"
										FinalBytes = FinalBytes + SPobjs[kk].NeedNextBestByt[vvv]
								else:
									SPobjs[kk].bytCnt2= SPobjs[kk].bytCnt2- SPobjs[kk].NeedNextBestByt[vvv]
								multCnt=multCnt-1
							if (SPobjs[kk].bytCnt2 < desired):
								SPobjs[kk].bytCnt2= SPobjs[kk].bytCnt2+ SPobjs[kk].NeedNextBestByt[vvv]
								out4 = out4 + SPobjs[kk].NeedNextBest[vvv] + " [" +str(hex(SPobjs[kk].NeedNextBestByt[vvv])) + " bytes] "  + str(hex(SPobjs[kk].bytCnt2)) +" **^ \n"
							out5= "\t\t# N----> STACK PIVOT TOTAL: " +str(hex(SPobjs[kk].bytCnt2))  + " bytes\n" #    + " vvv: " +str(vvv)+ "\n"
							SPobjs[kk].bytCnt2 =0
						test=test+1
					if (index !=0):
						#out5=""	
						pass
				vvv=vvv+1
				#out5= "\t\t# 2----> STACK PIVOT TOTAL: " +str(FinalBytes) + " bytes   " + str(hex(SPobjs[kk].bytCnt2))   + "\n"
				# out3= "\t\t# PNB----> STACK PIVOT TOTAL: " +str(FinalBytes) + " bytes   " + str(hex(SPobjs[kk].bytCnt))   + "\n"
				if (index >=0):
					PerfectNextBestOut=""
					PerfectOut=""
				#if not SPobjs[kk].Perfect:
					PerfectNextBestOut=out+out4+out5  #todo use boolean to see which
					if (truth <= truthLimit):
							# print "PerfectNextBestOut"
							# print PerfectNextBestOut
							if PerfectNextBestOut not in PerfectHelp2Outputs:
								PerfectHelp2Outputs.append(PerfectNextBestOut)
					# print "truth: " + str(truth) + " truth limit " +  str(truthLimit)
					truth +=1
			# print "* * *  *  * *  *  * N E W *  n e w"
#####
		
		SPobjs[kk].bytCnt =0
		kk=kk+1
		# print "buildStackPivotOutput4"
	# print "** Stack pivot chains complete **"
	return PerfectHelp2Outputs, PerfectHelpOutputs, PerfectOutputs

testString ="0x4015d0 # (base + 0x15d0) add esp, 4 # jmp edx # [4 bytes] 4 10  \n"+ "0x4015d0 # (base + 0x15d0) add esp, 4 # jmp edx # [4 bytes] 8 10  \n" + "0x4015d0 # (base + 0x15d0) add esp, 4 # jmp edx # [4 bytes] 12 10  \n"+"0x4015d0 # (base + 0x15d0) add esp, 4 # jmp edx # [4 bytes] 16 10  \n"
replaceSP = "\n0xdeadc0de # 4 byte filler \n0x"

def insertFillerString(stringReplace, replaceSP):
	array = stringReplace.split("\n0x")
	new = ""
	for word in array:
		new += replaceSP + word
	return new

def insertFillerSP(ReplacementArray, replaceSP):
	# print "replace"
	# print replaceSP
	ReplacementArray2=[]
	for  s in ReplacementArray:
		array = s.split("\n0x")
		new = ""
		x=0
		for word in array:
			if (x==0):
				#new +=    replaceSP  + "" +word  
				pass
			else:
				new +=  "\n" + replaceSP + "\t\t0x" +word 
			x+=1
		ReplacementArray2.append(new)

	return ReplacementArray2

def printSPArrayOutputs():#PerfectOutputs, PerfectHelpOutputs, PerfectHelp2Outputs):
	print "\n\n\nPerfect Help 2"
	d=1
	for  s in PerfectHelp2Outputs:
		print d
		print s
		d+=1
	print "\nPerfect Help\n"
	d=1
	for  s in PerfectHelpOutputs:
		print d
		print s
		d+=1
	print "\nPerfect Outputs\n"
	d=1
	for  s in PerfectOutputs:
		print d
		print s
		d+=1


# printSPCount=0

# # save =0
# def printSPArrayOutputsRealold(Perfect, PerfectHelp, PerfectHelp2, printSPCount, save):

# 	pCnt=len(Perfect)
# 	phCnt=len(PerfectHelp)
# 	ph2Cnt=len(PerfectHelp2)

# 	# global printSPCount
# 	# printSPCount=0
# 	phend=pCnt + phCnt
# 	ph2end=phend + ph2Cnt
# 	if (printSPCount ==0):
# 		print "debug: counts"	
# 		print pCnt
# 		print phCnt
# 		print ph2Cnt
		
# 	print "printSPCount: " + str(printSPCount)

# 	if (pCnt>0) or (ph2Cnt>0) or (phCnt>0):
# 		try: 
# 			if (save ==0):
# 				print "perfecto "
# 				dumb0 = Perfect[printSPCount]
# 				print dumb0
# 				print "printSPCount p " + str(printSPCount)
# 				printSPCount +=1
# 				save = 0
# 				return Perfect[printSPCount], save
# 			else:
# 				save +=1
# 				print "saving1"
# 				dumb0 = Perfect[99999999999]
				
# 		except:
# 			save +=1
# 			print "saving1b"
# 			print "No Perfect " + str(save)

# 			try:
# 				if (save ==1):
# 					print "try ph"
# 					#if (phCnt>0):
# 					dumb =  PerfectHelp[printSPCount]
# 					printSPCount +=1
# 					print dumb
# 					print "printSPCount ph " + str(printSPCount)
# 					print "Return ph"
# 					save = 1
# 					return  PerfectHelp[printSPCount], save
# 				else:
# 					save +=1
# 					dumb0 = Perfect[99999999999]
# 			except:
# 				save +=1
# 				print "saving2b"
# 				print "No PH" + str(save)
# 				try:
# 					if (save ==2):
# 						print "return ph2 " + str(printSPCount)
# 						print "printSPCount ph2 " + str(printSPCount)
# 						dumb =PerfectHelp2[printSPCount] 
# 						print dumb
# 						printSPCount +=1
# 						save =2
# 						print "saving2"
# 						return dumb, save
# 					else:
# 						save +=1
# 						dumb0 = Perfect[99999999999]
# 				except:
# 					return "# No stack pivots found", save

save1=0
save2 =0
save3=0
printSPCount= 0



def clearSave():
	global save1
	global save2
	global printSPCount
	global save3
	save1 =0
	save2 =0
	save3=0
	printSPCount=0

def printSPArrayOutputsReal(Perfect, PerfectHelp, PerfectHelp2, printSPCount2, sav3333e):
	global save1
	global save2
	global printSPCount
	pCnt=len(Perfect)
	phCnt=len(PerfectHelp)
	ph2Cnt=len(PerfectHelp2)

	# print "counts: p " + str(pCnt) + " ph " + str(phCnt) + " ph2 " + str(ph2Cnt)

	phend=pCnt + phCnt
	ph2end=phend + ph2Cnt
	if (printSPCount ==0):
		# print "debug: counts"	
		# print pCnt
		# print phCnt
		# print ph2Cnt
		pass

	printSPCount=save1
	# print "huh"
	if (pCnt>0):
		if (save2 == 0):
			r, r2, r3=getPprint(Perfect, PerfectHelp, PerfectHelp2)
		# print "how many?"
	else:
		save2=1
	if (phCnt>0) :
		# print "ph save2: " + str(save2)
		if (save2 == 1):
			r, r2, r3=getPHprint(Perfect, PerfectHelp, PerfectHelp2)
		# print "nope"
		# print r
	else:
		save2=2
	# print "moo"
	if (ph2Cnt>0):
		if (save2 == 2):
			r, r2, r3=getPH2print(Perfect, PerfectHelp, PerfectHelp2)
		# print "finalr"
	
	else:
		return "# No stack pivots found???", save1
	return r, r2, r3

def getPprint(Perfect, PerfectHelp, PerfectHelp2):
	global save1
	global save2
	global printSPCount
	try:
		# print "perfecto - printspcount" + str(printSPCount) + " save2 " + str(save2)
		dumb0 = Perfect[printSPCount]
		out= dumb0
		# print "printSPCount p " + str(printSPCount)
		printSPCount +=1
		# print saving1
		save2 = 0
		return Perfect[printSPCount], save1				
	except:
		# print "saving1a"
		save2 +=1
		save1=printSPCount
		# print "saving1b"
		# print "No Perfect " + str(save)
		return "none", save1, False


def getPHprint(Perfect, PerfectHelp, PerfectHelp2):
	# print "getph"
	global save1
	global save2
	global printSPCount
	try:
		# print "ph1 try ph - printspcount " + str(printSPCount) + " save2 " + str(save2)
		dumb =  PerfectHelp[printSPCount]
		printSPCount +=1
		out= dumb
		# print "ph1b printSPCount ph " + str(printSPCount)
		# print "Return ph"
		# print "saving2"
		save2 = 1
		save1 = printSPCount
		return  dumb, save1, True
	except:
		save2 +=1
		# print "saving2b"
		# print "No PH" + str(save)
		return "none", save1, False

def getPH2print(Perfect, PerfectHelp, PerfectHelp2):
	# print "get2"
	global save1
	global save2
	global printSPCount
	try:
		# print "ph2 return ph2 - printspcount " + str(printSPCount) + " save2 " + str(save2) + " save1 " + str(save1)
		# print "ph2b printSPCount ph2 " + str(printSPCount)
		try: 
			dumb =PerfectHelp2[printSPCount] 
		except:
			# print "dumbhaha"
			# printSPCount=0
			# save1=0
			dumb =PerfectHelp2[printSPCount] 
		# print dumb
		printSPCount +=1
		save1 = printSPCount

		save2 =2
		# print "ph2c saving3"
		return dumb, save1, True
	except:
		return "# No stack pivots found!!!!!!!!", save1, False

def doStackPivotTasks(s1,s2, Reg):
	global PerfectOutputs
	global PerfectHelpOutputs
	global PerfectHelp2Outputs
	####################     THIS ONLY WORKS FOR THE JMP REG / CALL REG SPECIFIED BY THE S1, S2
	# print "doStackPivotTasks"
	addtoEsp(s1,s2, Reg)
	# print "doStackPivotTasks2"
	PerfectHelp2Outputs,PerfectHelpOutputs,PerfectOutputs=buildStackPivotOutput()
	# print "doStackPivotTasks3"
def stackPivotInsertFiller(replaceSP):
	global PerfectOutputs
	global PerfectHelpOutputs
	global PerfectHelp2Outputs
	PerfectHelp2Outputs=insertFillerSP(PerfectHelp2Outputs, replaceSP)
	PerfectOutputs=insertFillerSP(PerfectOutputs, replaceSP)
	PerfectHelpOutputs=insertFillerSP(PerfectHelpOutputs,replaceSP)

	# print "showing stack ph2"
	# for each in PerfectHelp2Outputs:
	# 	print each

def checkDistinctOutputs(check):
	pCnt=len(PerfectOutputs)
	phCnt=len(PerfectHelpOutputs)
	ph2Cnt=len(PerfectHelp2Outputs)

	d=pCnt+ph2Cnt+phCnt
	
	# print "totally d " + str(d)

	if check < d:
		return check, True
	else:
		# print "returning d haha"
		return d -1, False

def doVPVAtasks(printSPCount):
	global PerfectOutputs
	global PerfectHelpOutputs
	global PerfectHelp2Outputs

	printSPCount, distinctOutputs = checkDistinctOutputs(printSPCount)
	save=0
	printOut, save2, truth= printSPArrayOutputsReal(PerfectOutputs, PerfectHelpOutputs, PerfectHelp2Outputs, printSPCount, save)
	# print "po: "+ printOut
	# print "po2:" + str(distinctOutputs)
	# print "truth:" + str(truth)
	return printOut, truth

def clearGlobalOutputs():
	global PerfectOutputs
	global PerfectHelpOutputs
	global PerfectHelp2Outputs

	PerfectOutputs [:] = []
	PerfectHelpOutputs [:] = []
	PerfectHelp2Outputs [:] = []

def clearAllSPSpecialArrays():
	t=0
	global v

	# print "Clearing"
	# print len(SPobjs)
	for s in SPobjs:
		SPobjs[t].best[:] = []
		SPobjs[t].bestByt=[]
		SPobjs[t].bestBytMultiplier=[]

		SPobjs[t].NeedBest=[]
		SPobjs[t].NeedBestByt=[]

		SPobjs[t].NeedNextBest[:] = []
		SPobjs[t].NeedNextBestByt[:] = []
		SPobjs[t].NeedNextBestBytMultiplier[:] = []
		SPobjs[t].NextBestPerfect=[]

		SPobjs[t].res=0  #multipier - res * mainbyt = total
		SPobjs[t].total=0
		SPobjs[t].mainByt=0
		SPobjs[t].main=""
		SPobjs[t].Perfect = False # if first gadget stack pivot = desired
		SPobjs[t].PerfectHelp=[]
		SPobjs[t].PerfectHelp2=[]
		SPobjs[t].NeedMultiplier[:] = []
		SPobjs[t].StillNeed=[]
		SPobjs[t].bytCnt=0
		SPobjs[t].bytCnt2=0
		SPobjs[t].bytCnt3=0
		t+=1

	# print len(SPobjs)
	for i in range(len(SPobjs)):
		SPobjs.pop(-1)
	# print "final"
	# print len(SPobjs)
	v=0
def printOutputs():
	print "\nsPerfect Outputs.\n"
	d=1
	for  s in PerfectOutputs:
		print d
		print s
		d+=1


def changeStackPivotNum():
	global desired
	global desiredMax
	# global NumOpsD
	print "Default: 0x70"
	print "Change number of bytes to obtain for stack pivot:" 
	d = raw_input()
	# print d
	try:
		ans=int(d)
		# print "ok3"
	except:
		ans=int(d,16)
		# print "ok1"
	print str(ans)+ " or " +  hex(ans) #str(int(d, 16))
	desired=float(ans)
	# dog = float(ans)
	# print dog
	print "Default: 0x150"
	print "Change max stack pivot value:" 
	d = raw_input()
	# print d
	try:
		ans=int(d)
		# print "ok3"
	except:
		ans=int(d,16)
		# print "ok1"
	print str(ans)+ " or " +  hex(ans) #str(int(d, 16))
	desiredMax=float(ans)
	if int(desired) & 1:   #odd
		pass
	else:			#even
		desired+=1.0
	# print desiredMax
	# print desired
	# testingdesired()
def testingdesired():
	global desiredMax
	global desired
	print desiredMax
	print desired