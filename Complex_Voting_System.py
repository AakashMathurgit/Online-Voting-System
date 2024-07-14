import random
from Crypto.Hash import SHA256
from random import SystemRandom
import hashlib
#required libraries
def gcd(a, b):
while b != 0:
a, b = b, a % b
return a
# modulo exponentiation function return (x^y)%p
def power(x, y, p) :
res = 1
x = x % p
if (x == 0) :
return 0
while (y > 0) :
if ((y & 1) == 1) :
res = (res * x) % p
y = y >> 1
x = (x * x) % p
return res
# returns (a^-1)%m
def multiplicative_inverse(a, m):
m0 = m
y = 0
x = 1
if (m == 1) :
return 0
while (a > 1) :
q = a // m
t = m
m = a % m
a = t
t = y
y = x - q * y
x = t
if (x < 0) :
x = x + m0
return x
#checks if the number is prime
def is_prime(num):
if num == 2:
return True
if num < 2 or num % 2 == 0:
return False
for n in range(3, int(num**0.5)+2, 2):
if num % n == 0:
return False
return True
# create a array of all the primes between 200 to 700 for use in key generation
primes = [i for i in range(200,700) if is_prime(i)]
# returns the keys by taking 2 primes as input
def generate_keypair(p, q):
n = p * q# n is our base of modulo
phi = (p-1) * (q-1)#totient function
e = random.randrange(2, phi)

g = gcd(e, phi)
while g != 1:
e = random.randrange(2, phi)
g = gcd(e, phi)
d = multiplicative_inverse(e, phi)
# returns two tandom keys such that the (e,d) are coprime to phi
return ((e, n), (d, n))
no_of_blinds=10
CTR = dict()
pubkeymap = dict()# a key table which will be broadcaseted for pubkey refernce
prikeymap=dict()# a kay table only for the reference of the user in case he doesn't no the
private key
gtidset=set()# gtid = global transaction id . Each vote set has one and gtidset contains gtid
that the server has used till now
partyname =[]
partyname.append("BJP")
partyname.append("MJP")
partyname.append("JSR")
partyname.append("Default")
# this contains the pubkey and privates of the users .
#pubkeymap is braodcasted privatekeymak only for user reference
pubkeymap["one"],prikeymap["one"]=generate_keypair(241,263)
pubkeymap["two"],prikeymap["two"]=generate_keypair(307,337)
pubkeymap["three"],prikeymap["three"]=generate_keypair(419,433)
pubkeymap["four"],prikeymap["four"]=generate_keypair(577,599)
#CTR knows who has generated blind or not (only this)
CTR["one"]="bmnotcreated"
CTR["two"]="bmnotcreated"
CTR["three"]="bmnotcreated"
CTR["four"]="bmnotcreated"
CTR["five"]="bmnotcreated"
# server keys for enryption adn decryption (Confidentiallity)
ser_pub,ser_pri = generate_keypair(3307,3313)
# server key for blinding and unblinding
ser_bkpub,ser_bkpri=generate_keypair(47,53)
#*******both sets are different because of the problems the modulo propety was
bringing .ps they still act the same
N = ser_pub[1]
n= ser_bkpub[1]
print(CTR)# contains the list of voters and status of blind generation
#print(prikeymap)
votemap=dict()#contains votes
votemap["trash"]=0
# we set the vote count of each party =0
for p in partyname:
votemap[p]=0
# this function encrypt a list (plaintext) using key(pk)
def encrypt(pk, plaintext):
key, n = pk
cipher=[]
for i in plaintext :
cipher.append(power(i, key, n))
return cipher
# this function decrypt a list (ciphertext) using key(pk)
def decrypt(pk, ciphertext):
key, n = pk
plain=[]
for i in ciphertext :
plain.append(power(i, key, n))
return plain
# converts a string to array of interget for mathematical calculations
def hstintarray(hexstring):
s=[]
for char in hexstring:
if (char>='a')&(char<='f'):
s.append(ord(char)-ord('a')+10)
else:
s.append(ord(char)-ord('0'))
return s
# performs the reverse of above operation
def hsfintarray(ls):
s=""
for i in ls:
if(i>9):
#s=''.join(('','s',(chr(ord('a')-10+i))))
s=s+(chr(ord('a')-10+i))
else:
#s=''.join(('','s',(chr(ord('0')+i))))
s=s+(chr(ord('0')+i))
return s
# this functoin takes a list and blind it using r factor (m*(r^e))%n
def blindalist(msg,r,key):
e,m = key
rpow = power(r,e,m)
bl=[]
for i in msg:
x=(i*rpow)%m
bl.append(x)
# performs the blind operation simple to understand
return bl
# takes in a list of text (contains the expected partynames) and convert each into a
corresponding hash value
# and adds gtid to a vote also blinds this list
#for refernce("BJP",gitd) ("MJP",gtid) these votes are hashed anf then blinded
# made into a set of these votes(blind) msgset
def blindgenerator(gtid,r,text):
msgset=[]
for i in text:
msg = hashlib.sha256(i.encode())
msg = msg.hexdigest()
msg= hstintarray(msg)
msg.append(gtid)
bl=blindalist(msg,r,ser_bkpub)
msgset.append(bl)
return msgset
#takes the messages and values sign them with voters private key followed by encryption
for
#authentication and confidentiallity of blinds
# also does the same with r values as they are also set to CTR
def signencrypter(blindsets,rset,private):
siblindsets=[]#voter signed blind sets
for i in blindsets:
simsgset=[]
for l in i:
temp=encrypt(private,l)
simsgset.append(temp)
siblindsets.append(simsgset)
sirset=encrypt(private,rset)#voter signed r values
ensiblindsets=[]#encrypted signed blindvotes
enblindsets=[]#encrypted non signed blind votes
enrset=[]# encrypted r values
ensirset=[]#encrypted signed r values
for i in blindsets:
enmsgset=[]
for l in i:
temp=encrypt(ser_pub,l)
enmsgset.append(temp)
enblindsets.append(enmsgset)
for i in siblindsets:
ensimsgset=[]
for l in i:
temp=encrypt(ser_pub,l)
ensimsgset.append(temp)
ensiblindsets.append(ensimsgset)
enrset=encrypt(ser_pub,rset)
ensirset=encrypt(ser_pub,sirset)
return (ensiblindsets,enblindsets,enrset,ensirset)# returns the channel msg which is
encrypted and signed
# this function takes in blindvotes and r values to check there formats
def blindchecking(msgset,r):
rin=multiplicative_inverse(r,n)
unblimsgset=[]#contains the unblinded message
for i in msgset:
temp2 = blindalist(i,rin,ser_bkpub)
gtidset.add(temp2[-1])# the corressponding gtid is stored in the server
temp2.pop()
unblimsgset.append(temp2)
c=0
phash=dict()
for p in partyname:
msg = hashlib.sha256(p.encode())
msg = msg.hexdigest()
hp= hstintarray(msg)
phash[p]=hp
if hp in unblimsgset:
c=c+1
# checks if all the messages are in correct format
if c==4:
return 1
else:
return 0
def serverside(channelpack,nam):
if(nam not in CTR) or (CTR[nam]!="bmnotcreated"):#checks if the name is in list and
blinds are not created already
temp=[]
print("Either you have already create blinds or your name is not in list")
return temp,0
CTR[nam]="blindsalreadycreated"
ensiblindsets,enblindsets,enrset,ensirset=channelpack
#******************this part decrypts the message and then chech the
authentication**********
#decryption using server private key
siblindsets=[]
blindsets=[]
rset=[]
sirset=[]
for i in enblindsets:
msgset=[]
for l in i:
temp=decrypt(ser_pri,l)
msgset.append(temp)
blindsets.append(msgset)
for i in ensiblindsets:
simsgset=[]
for l in i:
temp=decrypt(ser_pri,l)
simsgset.append(temp)
siblindsets.append(simsgset)
rset=decrypt(ser_pri,enrset)
sirset=decrypt(ser_pri,ensirset)
print("decryption done")
#sign is checked for authentication
unsiblindsets=[]
unsirset=[]
for i in siblindsets:
unsimsgset=[]
for l in i:
temp=decrypt(pubkeymap[nam],l)
unsimsgset.append(temp)
unsiblindsets.append(unsimsgset)
unsirset=decrypt(pubkeymap[nam],sirset)
temp=[]
retr=0
if unsirset==rset and unsiblindsets==blindsets:
# if blinds are authentic
print("User verified")
print("now we will open nine blinds")
no=random.randrange(0,no_of_blinds)
# a random blind is not opened while other are opened
print("we will not open this index")
print(no)
j=0
c=0
retmsgset=[]
for i in blindsets:
if(j!=no):
c=c+blindchecking(i,rset[j])
#checks if other blinds are correct in format
else :
retmsgset=i
retr=rset[no]
j=j+1
if(c==no_of_blinds-1):
#if the number of correct blinds c = one less than total blinds
# we assume format is correct
# the selected message is now signed by server private key
for i in retmsgset:
tm= encrypt(ser_bkpri,i)
temp.append(tm)
retr=rset[no]
# *************message is signed above************
else :
print("you tried to send an incorrect message query failed please check format")
retr=0
else:
print("verification failed ")
retr=0
return temp,retr
def sendvote(vote):
# this function takes one vote message and encrypts it with server pub key for
confidentiality of vote
# note the user name is not given
check=encrypt(ser_pub,vote)
#print("the second channel vote encryped")
#print(check)
return check
def servervotecount(channelvote):
# this function recieves the vote and then counts if it is a valid vote also adds the gtid to
gtid set for future refernce
vote =decrypt(ser_pri,channelvote)
#print("reciveed and decryted")
#print(vote)
print("now we will reading the vote")
#decrypts the message vote
read=decrypt(ser_bkpub,vote)
print(read)
if(read[-1] in gtidset):
# if the gtid is already used the server ignore it
print("blind message set already used")
else:
#else counts a valid vote
gtidset.add(read[-1])
read.pop()
f=0
for p in votemap:
msg = hashlib.sha256(p.encode())
msg = msg.hexdigest()
hp= hstintarray(msg)
if(hp==read):
votemap[p]=votemap[p]+1
f=1
if(f==0):
votemap["trash"]=votemap["trash"]+1
if __name__ == '__main__':
q=input("Input the numbers of query")
blind = dict()
q= int(q)
while(q>0):
q=q-1
f=input("Do you want to create vote y/n")
if(f=="y"):
nam = input("Enter your voter id name")
# if the voter has not created keys we create it for him
if(nam not in pubkeymap):
pn = random.choice(primes)
qn= random.choice(primes)
while(qn==pn):
qn=randomChoices(primes)
pubkeymap[nam],prikeymap[nam]=generate_keypair(pn,qn)
print("we created keys for you and your private key is")
print(prikeymap[nam])
# we create some blinds sets of the expected format that is the votes are correct in
them
print("we will first create blind votes for you")
blindsets=[]# contains the 10 sets of blind votes(each set has 4 votes)
rset=[]
for i in range(0,no_of_blinds):
gtid = random.randrange(1,n)
r = random.randrange(2,n)
g = gcd(r, n)
while g != 1:
r = random.randrange(1, n)
g = gcd(r, n)
# we create random gtid and r value for a set of messages
msgset=blindgenerator(gtid,r,partyname)
# create a blinded set of messages with correct format using partynames
blindsets.append(msgset)
rset.append(r)
# if our hacker wants to change some votese he can change them
fr=input("if you want to create your own message enter number n<10")
fr = int(fr)
for i in range(0,fr):
gtid = random.randrange(1,n)
r = random.randrange(2,n)
g = gcd(r, n)
while g != 1:
r = random.randrange(1, n)
g = gcd(r, n)
print("please input 4 votes of a set")
text=[]
for qm in range(0,4):
inpy=input("enter vote text")
text.append(inpy)
msgset=blindgenerator(gtid,r,text)
# create a blinded set of messages with format as per user request
blindsets[i]=msgset
rset[i]=r
#print("the blind sets created")
#print(blindsets)
print("your blinds are created ")
print("now we will sign your messages")
print("Input your private key to continue first enter d then n")
#privd=input()
#privd = int(privd)
#privn=input()
#privn=int(privn)
#private=(privd,privn)
channelpack=signencrypter(blindsets,rset,prikeymap[nam])
# above function create a signed and encrypted copy of blinds for channel use
print("now we are sending your message to server with your name")
# we send the message through channe; with name
blisiset,re=serverside(channelpack,nam)
# the serve checks for confidentiality ,authentication,random blinds are open
# if the votes are of correct format the remaining blind vote set is signed and
returned to the voter
if(re):
# if the vote is returned
rin = multiplicative_inverse(re,n)
votec=input("number of votes you want to send we expect n=1")
votec=int(votec)
# this allows to send multiple votes
for vc in range(0,votec):
print("now give the index of the vote you want to pass")
inp=input()
inp=int(inp)
tmp=blisiset[inp]
arr=[]
for i in tmp:
arr.append((i*rin)%n)
# the vote is selected and its r factor is removed and then send to the server
#print("lets print the m^d")
#print(arr)
vote =arr
print("now we will send owr hidden vote to server")
# the vote is send to the server vote = ((m)^d)log n i.e it is blindly singed by
server
# the below function encrypts it with server public key for confidentiality
channelvote=sendvote(vote)
# the server then checks the vote
servervotecount(channelvote)
else:
print("query failed for some reason")
print("printing votemap for better reach to process")
print(votemap)
print("the final result is printed")
print(votemap)