#!/usr/bin/python
#[S] SCRIPT:> HASHme
#[V] Version: 1.0
#[J] JOP: CHECK HASHES OF FILE
#[B] CodeBy:> J0kEr11[OseidAldary]
#-----------------------------------#
## IMPORTS LIBRARIES
#--==--==--==--==--==--==--==--==--==
import hashlib
import optparse
from random import randint
from time import sleep as se

## COLORS
#--==--==
cor = ["\033[1;31m","\033[1;32m","\033[1;33m","\033[1;34m","\033[1;35m","\033[1;36m","\033[1;37m"]
colors = cor[randint(0,6)]

## HASHme Function
#--==--==--==--==#
def HASHme(fname,hashname):
 try:
    test = open(fname, "r")
 except:
       print("\n"+cor[0]+"["+cor[2]+"!"+cor[0]+"][ERROR] "+cor[2]+"! File["+cor[1]+fname+cor[2]+"] Is Not Found "+cor[0]+"!!!")
       print(cor[0]+"["+cor[2]+"!"+cor[0]+"]"+cor[1]+" Please Check Your File Location "+cor[4]+"And Try Again "+cor[1]+":)")
       exit(1)
 hashs = ["md5","sha1","sha224","sha256","sha384","sha512"]
 if hashname in hashs:
  try:
    if hashname =="md5":
     hash_md5 = hashlib.md5()
     with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
     return hash_md5.hexdigest()
    elif hashname =="sha1":
     hash_sha1 = hashlib.sha1()
     with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
     return hash_sha1.hexdigest()
    elif hashname =="sha224":
     hash_sha224 = hashlib.sha224()
     with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha224.update(chunk)
     return hash_sha224.hexdigest()
    elif hashname =="sha256":
     hash_sha256 = hashlib.sha256()
     with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
     return hash_sha256.hexdigest()
    elif hashname =="sha384":
     hash_sha384 = hashlib.sha384()
     with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha384.update(chunk)
     return hash_sha384.hexdigest()
    elif hashname =="sha512":
     hash_sha512 = hashlib.sha512()
     with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha512.update(chunk)
     return hash_sha512.hexdigest()
  except:
        print("\n"+cor[2]+"["+cor[0]+"!"+cor[2]+"] Something Went Wrong "+cor[0]+"!!!")
        exit(1)
 else:
	print("\n"+cor[0]+"[!][ERROR]"+cor[2]+"! Unknown HASH["+cor[1]+hashname+cor[2]+"]"+cor[0]+" !!!")
	exit(1)

## Tool Banner
#--==--==--==#
banner = colors + """
 / \ / \ / \ / \ / \ / \  
( H | A | S | H | m | e ) 
 \_/ \_/ \_/ \_/ \_/ \_/  

"""

## Tool Options
#--==--==--==--
parse = optparse.OptionParser(banner+cor[6]+"""\
Usage: python ./HASHme.py [OPTIONS..]

OPTIONS:
========
       -H --hashsum  << Hash Name >>   Set Hash Name:[ md5,sha1,sha224,sha256,sha384,sha512 ]
       -F --file     << Set File >>    Set File Location.
EXAMPLES:
=========

python HASHme.py -H md5 -F /root/Desktop/file.txt
python HASHme.py -H sha1 -F /root/Desktop/file.txt

python HASHme.py -H sha224 -F /root/Desktop/file.txt
python HASHme.py -H sha256 -F /root/Desktop/file.txt
python HASHme.py -H sha384 -F /root/Desktop/file.txt
python HASHme.py -H sha512 -F /root/Desktop/file.txt

""")
## Main Function
#--==--==--==--#
def main():
 # Add Options&args
 parse.add_option("-H","--hashsum",dest="hashname",type="string")
 parse.add_option("-F","--file",dest="filename",type="string")
 (options,args) = parse.parse_args()

 if options.hashname !=None and options.filename !=None:

     hashname = options.hashname
     fname = options.filename
     se(0.10)
     print("\n"+cor[2]+"["+cor[0]+"*"+cor[2]+"]"+cor[4]+" Hash: "+cor[1]+hashname)
     se(0.10)
     print(cor[2]+"["+cor[0]+"*"+cor[2]+"]"+cor[4]+" File: "+cor[1]+fname)
     se(0.10)
     print("\n"+cor[1]+"["+cor[2]+"*"+cor[1]+"] "+cor[1]+hashname+cor[0]+"sum: "+cor[5]+HASHme(fname,hashname))

 else:
     print(parse.usage)
     exit(1)

if __name__=="__main__":
  main()


##############################################################
##################### 		     #########################
#####################   END OF TOOL  #########################
#####################                #########################
##############################################################
#This Tool by Oseid Aldary
#Have a nice day :)
#GoodBye


