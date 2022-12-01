![alt text](https://github.com/Bw3ll/JOP_ROCKET/blob/master/jopRocket3.jpg)
# JOP ROCKET

**NOTE: With 2.15, we introduce the two-gadget disaptcher--this significantly expands possibilities with dispatcher gadgets. A lot of optimizations and additional new features have been added with 2.15 on May 26, 2021.**

**Update: November 29, 2021: I have uploaded the slides for @Hack in Ryadh and also a white paper on Shellcodeless JOP. The silent demo videos useed in the talk may be found here: https://www.youtube.com/playlist?list=PLynyJsHgQaJ3AfQGKVkeZJ9cWa7mIqDMV**

**Update: December 1, 2022: I have added a Q & A at the end of this GitHub, which includes links to resources (talks and papers).**

Current version: 2.15 

The Jump-oriented Programming Reversing Open Cyber Knowledge Expert Tool, or JOP ROCKET, is a tool designed to help facilitate JOP gadget discovery in an x86 Windows environment. This tool was released at DEF CON 27, where it was the subject of a talk by Dr. Bramwell Brizendine and Dr. Josh Stroschein. A major update is under development was released this September, 2020, with minor updates planned in the near future.

Please navigate to [https://github.com/Bw3ll/JOP_ROCKET](https://github.com/Bw3ll/JOP_ROCKET/) in order to download this tool. 

A number of major updates have occurred. It is recommended that any version prior to 2.15 be updated, to take advantage of the many updates. These include automatic JOP chain generation, discovering new types of gadgets, new types of dispatcher gadgets, and the two-gadget dispatchers. JOP ROCKET has also undergone many other important chances to enhance and optimize its performance and speed.

JOP ROCKET is a Python program utilizing the Capstone disassembly engine as well as other dependencies. This software exploitation tool is a fully featured artifact designed to facilitate Jump-oriented Programming. It is intended to be run on Windows.

Usage information is not available at this time beyond what is in the help menu. Constructing JOP exploits is not straightforward and is very nuanced, with some parallels but many differences from ROP. Please refer to DEF CON talk to see a brief demo. https://www.youtube.com/watch?v=PMihX693mPE

This tool has been taught at Dakota State University in the doctoral program, as part of CSC 848: Advanced Software Exploitation, the most challenging course in the program. The students completed exploits that included bypassing DEP and ASLR.

Thank you to Austin Babcock for his help with various issues relating to the JOP ROCKET, including his install instructions. He is a master of JOP. 

We have uploaded an archive here, JOP ROCKET challenge - toy binaries.zip, to allow interested parties to test and practice JOP on some sample toy binaries, using the JOP ROCKET. Can you bypass Data Execution Prevention (DEP)? This is good if you want to practice JOP on a binary that you know is guaranteed to be vulnerable and have the right gadgets. There is an easier and a harder version of the same binary. Though JOP likely will be harder the first time, until someone gets the hang of it. Once you master JOP with these binaries, you can try it on some real-world gadgets, assuming they have sufficient gadgets. If you are doing the dispatcher gadget paradigm, keep in mind you do need a dispatcher gadget. JOP is also possible mixed in with ROP, using a jop gadget to point to a RET, so JMP EDX could have EDX point to RET. This is more useful if you need just one or two JOP gadgets to make ROP work. The binaries in the archive should allow you to do use the dispatcher gadget paradigm in a few different ways though! 

With the dispatcher gadget paradigm of JOP, you can 100% eliminate ROP, although it is easiest to start things off with two ROP gadgets, to load the dispatch table and the dispatcher gadget. The pre-built JOP chain will do this for you automatically, assuming they are present. From there, it can be pure JOP, using both indirect jumps and indirect calls (JMP EBX, CALL EDX, etc.).


## Basic install instructions for JOP ROCKET
### Step 1:
Install Python 2.7. The easiest way to do this will be from the website: https://www.python.org/download/releases/2.7/

If you already have Python 3, you will still need to have Python 2.7 as the tool will not work properly with Python 3.

If you have both, you will need to add the special comment: 

**#!python2**

to the top of rocket.py. Then run with "py rocket.py" rather than "python rocket.py". This will ensure the program is run using Python 2.7. Alternatively, you can just do py -2 rocket.py

![alt text](https://github.com/Bw3ll/JOP_ROCKET/blob/master/python.jpg)

### Step 2:
install pip if it isn't already included with Python.

-	https://pip.pypa.io/en/stable/installing/

You will need to save the script provided and run it, as per the instructions on the link. If you run into an error, try using the “alternate” script.

If pip still doesn't work, try adding "C:\python27\Scripts" (or your corresponding directory) to your Path system variable:

-	Start
-	Right click Computer
-	Properties
-	Advanced System Settings
-	Advanced tab
-	Environment Variables

![alt text](https://github.com/Bw3ll/JOP_ROCKET/blob/master/environ.jpg)

### Step 3:
Start installing dependencies with pip!

_Note: Installations with pip should work using the Windows terminal, but may not work in a Cygwin environment. If using Cygwin, you may need to install with source code instead. This can be a more time-consuming endeavor, and you are referred to the latest documentation from the different makers of the dependencies._
-	**pip install capstone**
- **pip install pefile2**

   - You will likely already have pefile installed with Python 2.7, but this version is old.
   - Pefile2 is what you need.

   - You may need to **pip uninstall pefile** to get the program to use pefile2.
-	Etc... A list of dependencies can be found at the bottom of this document. Each must be installed, if they are not already.
-	The two above are likely the only ones you will need to install yourself.

Many of the dependencies already come with Python. To list available modules, open a prompt:


![alt text](https://github.com/Bw3ll/JOP_ROCKET/blob/master/modules.jpg)

Look through the list and see if you have all the dependencies. For those you don't have, install with pip or via source code.

### Dependencies:
-	Capstone
-	pywin32
-	Pefile2
-	Ctypes

Note: pywin32 is used for Win32file and Win32api
### Needed files:
You should have in one directory all five files, rocket.py, lists,py, checkIt.py, ui.py, and stackpivot.py. To begin using the tool, run on command line, python rocket.py filename.exe -- the filename.exe being the program you wish to obtain JOP gadgets or JOP chains for.

### Errors:
If you are getting errors like "SyntaxError: Missing parentheses in call to 'print'", it is likely running with Python 3. Try doing the fix outlined in Step 1 to make the program use Python 2.

Errors related to “lists” or “ui” likely are caused by the location of the **lists.py** and **ui.py** files. Make sure these files are in the same directory as **rocket.py**.

## More advanced install steps

To utilize this in a Cygwin environment, you likely will need to install Capstone from the source. There are varous ways to do so, and Capstone's documentation provides assistance. Cygwin was originally used during the development of the tool, although this is no longer the case. JOP ROCKET v2.0 is untested on Cygwin, and command prompt is the recommended usage of JOP ROCKET. Note: Cygwin usage is no longer explicitly supported, and it is no longer recommended to be used with this program.

## Basic Usage

More detailed usage information is forthcoming. Refer to the DEF CON 27 talk and the help sub-menu for assistance.

To get started though, you want to have the five Python files in the same directory: rocket.py, ui.py, stackpivot.py, checkIt.py, and lists.py. Then run from command line. You can provide a local file in the install directory, but it will not be able to find modules/DLL's. To find these, the program must be installed, and the absolute path to the application can be supplied as input inside a text file that can be provided as an argument on the command line, e.g.

   python rocket.py input.txt
   
Inside input.txt, we would have the absolute path, e.g. C:\rocket2\sample_binary.exe. By providing the absolute path, you will be able to extract the modules to scan as well, if so desired. If you want to use JOP ROCKET with only the program in the local directory, it will only find gadgets for the image executable itself, i.e. no DLLs. To use it in that fashion, use the following syntax:

   python rocket.py sample_binary.exe
   
If the executable is in the same directory, you may use JOP ROCKET in the manner described above

## Making sure you get ALL the modules/DLLs for a binary
When loading an executable or DLL to be analyzed, there are two approaches. The first is to simply place the executable in the same directory and run the program, using that as an argument, e.g. python rocket.py binary.exe. This will enable the user to identify and extract many of the system modules. However, it will not find some of the non-system binaries. For comprehensive coverage, the user must supply the absolute path to the application in a text file and use that as input to ROCKET, e.g. python rocket.py input.txt. This will then allow for ROCKET to locate, extract, and search non-system DLLs associated with the target application. Thus, it is generally recommended to supply the binary as input via a text file, as otherwise some DLLs may be excluded. E.g., python rocket.py binaryToScan.txt. The binaryToScan.txt should contain the path for the binary, C:\Users\CoolPerson\Desktop\Instructions\targetBinary.exe

## Memory Issues with Very Large Binaries
The 32-bit Python will choke on very large binaries. To be able to work with these, you must use 64-bit Python.

Here are some instructions from Austin on going from 32-bit to 64-bit Python: To install the 64-bit version of python2.7, first make sure the old installation has been uninstalled. After installing the 64-bit version, you may get some errors when importing libraries such as "DLL load failed: %1 is not a valid Win32 application". These occur because Python is trying to load the previously installed 32-bit versions. To fix this problem, use pip to uninstall the library. If both Python 2 and 3 are installed, make sure the correct version of pip is used by using it as "py -2 -m pip <command>". 

Fixing the issue for capstone is straightforward:

py -2 -m pip uninstall capstone

py -2 -m pip install capstone

Errors regarding the win32api import are related to pywin32. Uninstalling this is more difficult as pip may not automate the process. It may have to be uninstalled manually by deleting the PyWin32 files within ...\Python27\Lib\site-packages.

Then, run:

py -2 -m pip install pywin32

Afterwards, finish the installation by running ...\Python27\Scripts\pywin32_postinstall.py -install

# Q & A
**Q: What is so special about JOP ROCKET?**

**A:** JOP ROCKET finds all the required gadgets, including the dispatcher gadget. I am not aware of any other tool that searches for dispatcher gadgets. Additionally, it introduces new types of gadgets and innovations to JOP.  JOP ROCKET also can generate a complete JOP chain to bypass DEP using a new variation on the dispatcher gadget paradigm that involves a series of multiple stack pivots. Realistically it would be very difficult to do a JOP exploit using the dispatcher gadget approach without using JOP ROCKET. There are some other ROP tools that may provide more limited JOP gadgets, but they are mostly placeholders for future work, and you could not complete a JOP exploit without some of the gadgets found with JOP ROCKET.

**Q: I think I saw JOP ROCKET at a talk before? Where was it?**

**A:** We have present at several conferences: DEF CON 27 (2019), Wild West Hackin’ Fest (2020), Hack in the Box Amsterdam (2021), Black Hat Asia (2021), and @Hack (2021) (now renamed Black Hat Middle East and Africa). For each of these there is generally a white paper and a video (no video for @Hack). There have been academic conferences as well. Each talk and white paper is different, usually with 60-70% new content at least. They address many different topics on JOP. We have no new talks planned and wouldn’t do another unless we had something new to share, as we don’t like to repeat ourselves. 

Here is a limited listing of some JOP materials. This is not the same talk or paper, as we are constantly evolving and adding new innovations. Each has novel contributions.

DEF CON 27 2019 video: https://www.youtube.com/watch?v=PMihX693mPE

Wild West Hackin’ Fest 2020 video: https://www.youtube.com/watch?v=ZQuxSSBfeHM

Black Hat Asia video: https://www.youtube.com/watch?v=NYgTw-h6GT8

Black Hat Asia paper: https://i.blackhat.com/asia-21/Thursday-Handouts/as-21-Brizendine-Babcock-Prebuilt-Jop-Chains-With-The-Jop-Rocket-wp.pdf

Hack in the Box Amsterdam 2021 video: https://www.youtube.com/watch?v=MxIySXHvKyE

Hack in the Box Amsterdam 2021 paper: http://magazine.hitb.org/wp-content/uploads/2021/06/HITBMag-Issue-12-June-2021-.pdf

High resolution: http://magazine.hitb.org/wp-content/uploads/2021/06/HITBMag-Issue-12-June-2021-Hi-res.pdf

@Hack 2021 (renamed Black Hat Middle East and Africa) paper: https://blackhatmea.com/content-hub/advanced-code-reuse-attacks-jump-oriented-programming

If you are an academic researcher, please cite some of these or our academic papers as well. :-)

**Q: What is an example of a real-world JOP exploit?**

**A:** Austin published one at Exploit DB: https://www.exploit-db.com/exploits/49959

You can see a video of it and him talking about it at the HITB 2021 presentation we did. That real-world JOP exploit presented some special challenges, so it is good to look at and study. While Austin wrote that by hand, actually the automatic JOP chain generation for JOP ROCKET would have done most of the work. (There still would be additional special setup to compensate for some of the challenges.) This is also an example of our novel variation to the dispatcher gadget approach, using a series of multiple stack pivots. This exploit took less than a day to complete.

**Q: Is JOP hard to do?**

**A:** No, it is not, but it is very different from ROP. There are different “rules” in places that may not be immediately apparent. We write about them extensively in different papers or talk about them in different talks we have done. What can sometimes be challenging, however, is having sufficient gadgets. There are different styles of JOP, and if you are attempting to do the dispatcher-gadget approach – which can allow you to do a complete JOP exploit with no ROP – then you must have a dispatcher gadget. 

**Q: Isn’t JOP just ROP by another name?**

**A:** JOP is very fluid. It can be. You could load a RET into a JOP gadget, and thus whenever you do JMP EBX, for instance, that would be equivalent to the RET. In that sense you could use JOP as just a way to extend ROP, and you wouldn’t need a dispatcher gadget. It would seem tedious to have to build an entire exploit that way, although you could if you really wanted to. We write about other styles of JOP as well, although most of our work concentrates on the dispatcher gadget approach. 

**Q: What is a dispatcher gadget? Is it easily found? What is a two-gadget dispatcher?**

**A:** That was a relatively rare gadget and not always easily found; some binaries would have no viable dispatcher gadgets. Notice the past tense is in play here. We have introduced alternative dispatcher gadgets, and more importantly, a two-gadget dispatcher, which we have written about at the HITB paper. This takes two common gadgets and chains them together, so a dispatcher gadget is no longer rare. One of the required gadgets is so common there are usually variations of it for nearly all registers; and the other is very common, but not as common. There can other practical limitations though as if you using a two-gadget dispatcher, that will tie up another register. (It is possible to switch dispatcher gadgets and registers being used during an exploit, if additional flexibility is needed.)

**Q: Is the two-gadget paradigm built into JOP ROCKET’s automatic JOP chain generation?**

**A:** No, it is not. The automatic JOP chain generation was time consuming to create, and I created two-gadget dispatcher concept after I did this.  I may attempt to add it in at some point, but not in the immediate future. More likely it would only be added if I did a complete rewrite of JOP ROCKET. By default, JOP ROCKET will create different variations of JOP chains for all available registers, even if a traditional dispatcher gadget cannot be found. Thus, it would not take too much effort for someone to go and add their own two-gadget dispatcher. Though one would need to pay attention to registers that need to be protected for the two-gadget dispatcher, as the tool would not automatically do that.

**Q: I want to try to make my own JOP chain? Can I do so?**

**A:** Sure, for tutorial purposes, we have a binary available on the GitHub – two forms of it – with artificially created JOP gadgets – both an easy and a hard version. The hard version has null byte limitations. You might try doing one without automatic JOP chain generation, seeing if you can find your own gadgets. You also could try with automatic JOP chain generation. With automatic JOP chain generation, you have to do additional work when contending with null bytes. I suppose that could be an area for additional work in the future – to automate some of that.

**Q: Why does JOP ROCKET use an older style of Python? Are you going to change it to modern Python?**

**A:** It was created first several years ago, and I had no intention at that time of ever sharing it. I only submitted to DEFCON initially as a fluke. Unfortunately, the differences between the modern and older Python are such that it would be very non-trivial to change JOP ROCKET, and there are many complex functions where the differences would come into play. JOP ROCKET is also very large as well, and I do not necessarily recall of hand all the places where changes would be needed. More likely than not, I would do a complete rewrite of JOP ROCKET, also making parts of it much more modular and compact than it currently is. There are several new features I would like to add if I did so, and I could do some very cool things if I did so. I do not have plans in the immediate future, but it could be in the next one to three years. Never say never though, as sometimes I can rewrite code very quickly. I may make other updates to the current JOP ROCKET during that time, as smaller updates are easier than a complete rewrite. 

**Q: Who is “we”?**

**A:** The creator of JOP ROCKET is Dr. Bramwell Brizendine. This was originally the subject of his doctoral dissertation, but it has grown and changed a lot since that time. One of his students, Austin Babcock, got involved in JOP research as an undergraduate and continued along with it through his MS in Computer Science degree. During that time Austin was a co-author for several papers and co-speaker for several events. Austin has made important contributions to the mechanics of how JOP works. He later joined as a contributor to JOP ROCKET, primarily introducing optimizations and code improvements. Austin has made several JOP exploits. One is on ExploitDB. 

**Q: What are the “newest” things in JOP that you guys have done?**

**A:** Well, there is the two-gadget dispatcher, which thereby makes JOP possible with numerous binaries, as the dispatcher-gadget is no longer obscure. That is huge - because in many cases that lack of a valid dispatcher gadget would be limiting--that simply is no longer the case. We also introduced some alternative single dispatcher gadgets, although most do not seem commonplace (Andrew Kramer can be credited for some of those). We also introduced “shellcodeless JOP,” which avoids the need of bypassing DEP and incorporates the functionality of a shellcode directly into a JOP. We do a small bit of that at HITB and more at @Hack 2021 (Black Hat MEA). @Hack was not filmed, although there is a very detailed paper on it. A clip of it in action can be seen in some of soundless demo videos for @Hack 2021: https://www.youtube.com/playlist?list=PLynyJsHgQaJ3AfQGKVkeZJ9cWa7mIqDMV . I have had a few students take up the challenge of shellcodeless JOP - that is something that can demand greater skill and mastery of code-reuse attacks.

**Q: Does JOP ROCKET work with Linux binaries?**

**A:** No, unfortunately it does not. That would be a good project for someone.

**Q: Does JOP ROCKET work with 64-bit binaries?**

**A:** No, not at this time.

**Q: What is the general approach of JOP?**

**A:** Read our papers or watch our talks. We did a tremendous amount of work in expanding what can be done with JOP. There was virtually no documentation on JOP prior to our research, and we created many new practical techniques for JOP.

**Q: I am an academic researcher and want to do something with JOP as in a paper or presentation. Can I contact you?**

**A:** Sure, you may contact us if you are planning to do a paper or some new project. You can reach me at bramwell.brizendine  AT gmail . I can pass along to Austin if he is interested. We potentially may even be interested in collaborating. Please cite us if you use our research in some way for JOP. Probably the most practical approach to research involving JOP would be in introducing some defenses to JOP or mitigations for it. We have been contacted before.

**Q: Have other people done JOP?**

**A:** It is not common, and prior to our first DEFCON talk, it was extremely rare. We have certainly raised awareness of it a great deal. I previously have taught it in a doctoral Advanced Software Exploitation course for three years, so dozens of student have created JOP exploits. I don’t know how many people do it in the wild—certainly people can do it now with JOP ROCKET. I have also had different undergraduate students do JOP exploits. There is no special reason it has to be a Ph.D. student - anyone with strong competency in exploitation and code-reuse attacks. With the number of talks we have done and papers we have written – coupled with innovations such as the two-gadget dispatcher – there is no reason why anyone skilled with ROP couldn’t pick it up.

**Q: Why was JOP ROCKET necessary?**

**A:** Without JOP ROCKET, you would only discover a fraction of JOP gadgets, and they would be disorganized, so finding something would be like finding a needle in a haystack. Many real-world JOP gadgets are unintended gadgets that are not naturally occurring, so unless you were some kind of very dedicated savant and created your own tooling or scripts, you would miss out on a lot, if you were trying to do a complete JOP exploit free of ROP gadgets. There are also things like dispatcher gadgets, which you would somehow have to magically find on your own, even unintended forms. There is a good reason why JOP was very rare and seldom talked about prior to our work. That is not imply it is commonplace now. Before JOP ROCKET, you would have several significant problems to overcome to write an exploit. Now with JOP ROCKET those problems are overcome and you can build your own with JOP gadgets or maybe adapt a JOP chain created via automatic JOP chain generation.

**Q: Can JOP be easier than ROP?**

**A:** Actually, I have heard from some students that JOP is easier than ROP – and it can be – with he right gadget and using our novel approach to the dispatcher gadget with multiple stack pivots. Notice the keyword here is “can be.” This is true only under special circumstances, such as no null byte restrictions and plentiful stack pivot gadgets, and assuming there is a valid dispatcher gadget. 

**Q: Who is JOP for?**

**A:** I think primarily it is for people who are skilled at code-reuse attacks and want to push themselves, attempting something cutting-edge – although not all JOP necessarily needs to be “difficult.” If you can do JOP, that is a badge of honor to wear. If you create a JOP exploit, go post it on ExploitDB and link to JOP ROCKET to help raise awareness. JOP can also be for people who simply want to avoid usage of ROP – there could be a mitigation in place to detect ROP gadgets. JOP is not ROP, and you can do a complete JOP exploit without a single ROP gadget.

**Q: I did automatic JOP chain generation, and it made many different chains for VirtualAlloc and VirtualAlloc. Why are there so many?**

**A:** I approach JOP from the standpoint that certain registers will hold a pointer to the dispatcher gadget and a pointer to the dispatch table, so those registers are tied up. Functional gadgets (more similar to normal ROP gadgets) will call the dispatcher gadget, which then advances the position in the dispatch table. JOP ROCKET thus creates different chains using different combinations of registers. Some registers will be "reserved" for the dispatcher gadget and the dispatch table, although if you want, you can switch back and forth as much as you like. Some registers will have more desirable JOP chains - in the sense that it maybe has gadgets that are "easier" to use. So we like to provide options. By default, JOP ROCKET will generate five for each, so if there is a problem with one, you perhaps have others to look at. Additonally, JOP ROCKET will generate these even if a desirable dispatcher gadget is not found, as there can always be alternatives or two-gadgets dispatchers. (JOP ROCKET finds two-gadget dispatchers, but it does not currently incorporate them into JOP chain generation.) Thus, getting back to the question, JOP ROCKET will try to provide a lot of options, and it is up to the user to evaluate them and determine which is most desirable or easiest to work with.

**Q: JOP ROCKET is not giving me good results for automatic JOP chain generation. Why is that?**

**A:** In some cases, there could be some bugs, but it is also important to remember that automatic JOP chain generation works on the that you are using multiple stack pivots (see talks, papers). You must supply the desired pivot amount, as it will only generate results based on the default. There could be an outstanding stack pivot that is very large, and you might miss it, because it is outside your range. So you absolutely should calculate the range of acceptable stack pivots, supplying the minimum and maximum. You can always adjust things later with padding- it does not need to be precise.

**Q: Are there any "vulnerabilities" with JOP in compilers?**

**A:** Actually, yes, with VisualStudio 2015,  all of that we found compiled with Developer Prompt had a couple highly desirable dispatcher gadgets! I was going to include that in one talk, but it got cut for time. I may include that separately at a later time. The bad news is we evaluated all binaries made by Visual Studio for other years, up until about a year ago, and we did not see this repeat. While it can be nice to have excellent dispatcher gadgets, those are not necessary, as described elsewhere, with the novel two-gadget dispatcher we introduced.






