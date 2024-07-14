import random
from Crypto.Hash import SHA256
from random import SystemRandom
import copy
import hashlib
def gcd(a, b):
#simple gcd code using euclidean therom
while b != 0:
a, b = b, a % b
return a
def power(x, y, p) :
# modulo exponentiation function return (x^y)mod p
res = 1
x = x % p
if (x == 0) :
return 0
while (y > 0) :
# If y is odd, multiply
# x with result
if ((y & 1) == 1) :
res = (res * x) % p
# y must be even now
y = y >> 1 # y = y/2
x = (x * x) % p
return res
def multiplicative_inverse(a, m):
#multiplicative inverse of a in m field (a^(-1))mod m
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
def is_prime(num):
if num == 2:
return True
if num < 2 or num % 2 == 0:
return False
for n in range(3, int(num**0.5)+2, 2):
if num % n == 0:
return False
return True
primes = [i for i in range(10,100) if is_prime(i)]
# above is a list of prime numbers from 10 to 100 will be used in creation of key
def generate_keypair(p, q):
# this function is used to generate key pair that is private and public for the pair of prime numbers
n = p * q
phi = (p-1) * (q-1)
# totient function
e = random.randrange(1, phi)
g = gcd(e, phi)
while g != 1:
e = random.randrange(1, phi)
g = gcd(e, phi)
# above code is used to find a number e coprime to phi
d = multiplicative_inverse(e, phi)
# d is inverse of e
return ((e, n), (d, n))
def encrypt(pk, plaintext):
# this function takes input a list of numbers and encrypt each element with the key
key, n = pk
cipher=[]
for i in plaintext :
cipher.append(power(i, key, n))
return cipher
def decrypt(pk, ciphertext):
# this function takes input a list of numbers and decrypt each element with the key
key, n = pk
plain=[]
for i in ciphertext :
plain.append(power(i, key, n))
return plain
def hstintarray(hexstring):
# the hash function create a string of 256 bits which is converted into a hexstring
# the hexstring is digit by digit converted into a list of numbers
# example if the hash value of M is "ff0110ffabcd1234" thus 256 bit value is converted into
# [15,15,0,1,1,0,15,15,10,11,12,13,1,2,3,4]
# so that we have numbers which can be processed
s=[]
for char in hexstring:
if (char>='a')&(char<='f'):
s.append(ord(char)-ord('a')+10)
else:
s.append(ord(char)-ord('0'))
return s
CTR = dict()
# ctr is the serverside dictionary of counting and verifing vote it contains the allowed voters name
VB = dict()
# vote bank VB for counting votes and keeping them
pubkeymap = dict()
prikeymap=dict()
# maps to store pybkey and privkey *imp the public key map will be shared where as prikeymap is
just for the voter to get
#his private key (it is not shared)
pubkeymap["one"],prikeymap["one"]=generate_keypair(23,29)
pubkeymap["two"],prikeymap["two"]=generate_keypair(31,37)
pubkeymap["three"],prikeymap["three"]=generate_keypair(41,43)
pubkeymap["four"],prikeymap["four"]=generate_keypair(47,53)
# some voters have thier keys already created while others can manually create in program
CTR["one"]="NV"
CTR["two"]="NV"
CTR["three"]="NV"
CTR["four"]="NV"
CTR["five"]="NV"
# list of authentic voters
ser_pub,ser_pri = generate_keypair(71,73)
# servers key created will remain constant
print(CTR)
print(prikeymap)
# just printed for execution sake
#you might not know your private key you can look into it this will be offcourse from others
def sendvote(vot,private,nam):
# 'this function create a message packed signed and encrypted ready to share in channel
msg = hashlib.sha256(vot.encode())
msg = msg.hexdigest()
# msg is the hash value of the choosen vote
hexary =hstintarray(msg)
# we convert it into a list of numbers which can be mathematically operated
hexarysign = encrypt(private, hexary)
# we sign the hash value for authentication with voters private key
hexaryen=encrypt(ser_pub,hexary)
# we encrypt the hash value unsigned this value will be also send for later verification of the user
# in general method we send the message that is vote here but here we are sending the hashvalue of
easy of working
hexarysignen=encrypt(ser_pub,hexarysign)
# we also encrypt the signed msg for confidentiality
# encrypting done using servers public key
channelmsg=(hexarysignen,hexaryen)
# a message ready to pass throught the channel and meet the hackers
return channelmsg,nam
def serversideporcessing(channelmsg,nam):
# this is the only function which occurs at the server side
# voters name is also transferred to CTR
hexarysignen,hexaryen = channelmsg
# the encrypted hash value signed and unsigned both are recieved
hexarysign=decrypt(ser_pri,hexarysignen)
hexary = decrypt(ser_pri,hexaryen)
# the values are decrypted to get the signed and unsigned hash values using servers private key
hexaryunsign=decrypt(pubkeymap[nam],hexarysign)
# the singed value is unsinged for checking using voters public key
if(hexaryunsign!=hexary):
# if the values that is singed(later unsinged ) and the original doesnot match authentication failed
print("signature is incorrect")
print(hexary)
print(hexaryunsign)
else:
# singature verified
print("signature verifed")
if nam in CTR:
# if the voter is in CTR list then only it can vote
if CTR[nam]=="NV":
# if the voters has not voted before then only it can vote
CTR[nam]="V"
VB[nam]=hexary
# the vote is registered and the CTR notes the name also
print("vote successfully added")
else:
print("you have already voted")
else:
print("your name is not in list ")
return
def votecount(VB):
# this function is used to count the votes
# the voters name are known to the vote bank / CTR
vot ="BJP"
msg = hashlib.sha256(vot.encode())
msg = msg.hexdigest()
bjphexary =hstintarray(msg)
vot ="Trump"
msg = hashlib.sha256(vot.encode())
msg = msg.hexdigest()
Trumphexary =hstintarray(msg)
vot ="JSR"
msg = hashlib.sha256(vot.encode())
msg = msg.hexdigest()
jsrhexary =hstintarray(msg)
vot ="NOTA"
msg = hashlib.sha256(vot.encode())
msg = msg.hexdigest()
dhexary =hstintarray(msg)
dvb = dict()
count = dict()
count["BJP"]=0
count["Trump"]=0
count["JSR"]=0
count["NOTA"]=0
count["trash"]=0
for i in VB:
if(VB[i]==bjphexary):
dvb[i]="BJP"
count["BJP"]=count["BJP"]+1
elif (VB[i]==Trumphexary):
dvb[i]="Trump"
count["Trump"]=count["Trump"]+1
elif (VB[i]==jsrhexary):
dvb[i]="JSR"
count["JSR"]=count["JSR"]+1
elif (VB[i]==dhexary):
dvb[i]="NOTA"
count["NOTA"]=count["NOTA"]+1
else :
count["trash"]=count["trash"]+0
print(count)
#print(dvb)
return
if __name__ == '__main__':
j = input("How many queries ")
# we enter the number of queries we want to perform
j =int(j)
while(j>0):
j=j-1
bo =input("Do you want to cast a vote:y/n ")
if bo == "y":
nam = input("Enter your voter id name")
# if user want to vote he input his voter id here it is its name.# in real cases it could be voter id
number
if(nam not in pubkeymap):
# if the voter has not create his keys these lines of code creates for him and uploads the
pubkey to the
# common map
pn = random.choice(primes)
qn= random.choice(primes)
while(qn==pn):
qn=randomChoices(primes)
pubkeymap[nam],prikeymap[nam]=generate_keypair(pn,qn)
print("we created keys for you and your private key is")
print(prikeymap[nam])
# it also outputs the prikey for the voter only known to him
# the voter selects the party name he want to vote this is our base message
vot =input("enter your vote party name from 1.BJP 2.Trump 3.JSR 4.NOTA(Modiji)")
print("your vote is taken input your private key to continue first enter d then n")
privd=input()
privd = int(privd)
privn=input()
privn=int(privn)
# voter inputs its private key
private=(privd,privn)
print("now we are creating a portable encrypted message 'your name' will be send to the server")
# all the above part of code runs on the voters computer only
channelmsg,nam=sendvote(vot,private,nam)
# a encrypted and signed message for the channel is created
# this passes through the channel and reaches the server/CTF a hacker can get it if the network
is compromissed
serversideporcessing(channelmsg,nam)
# above code runs on CTR it decrpt the message checks the signature also
# this function doesnot allow unregisted to vote also it doesnot allow fake votes
else:
print("why are you here than you dont want to vote so get lost and let others come")
votecount(VB)
# this function count the votes for you