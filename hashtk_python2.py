#---------------------------------------------------------#
#        _____   __________    __  ______  ___________    #
#       /  _/ | / / ____/ /   / / / / __ \/ ____/ ___/    #
#       / //  |/ / /   / /   / / / / / / / __/  \__ \     #
#     _/ // /|  / /___/ /___/ /_/ / /_/ / /___ ___/ /     #
#    /___/_/ |_/\____/_____/\____/_____/_____//____/      #
#                                                         #
#---------------------------------------------------------#
                                                 
import os
import time
import random
import hashlib
import base64



#---------------------------------------------------------------#
#        ________  ___   ______________________  _   _______    #
#       / ____/ / / / | / / ____/_  __/  _/ __ \/ | / / ___/    #
#      / /_  / / / /  |/ / /     / /  / // / / /  |/ /\__ \     #
#     / __/ / /_/ / /|  / /___  / / _/ // /_/ / /|  /___/ /     #
#    /_/    \____/_/ |_/\____/ /_/ /___/\____/_/ |_//____/      #
#                                                               #
#---------------------------------------------------------------#

def clearScreen():
	try:
		os.system('clear')
	except KeyboardInterrupt:
		os.system('exit')

class mainRun():
	def __init__(self):
		clearScreen()
		mainLogo()
		hashOrEncodeElse = raw_input("[1] for encoding, [2] for hashing, [3] for hash cracking: ")
		if hashOrEncodeElse == '2':
			hashEncode()
		elif hashOrEncodeElse == '1':
			encodeOrDecode = raw_input("Would you like to encode or decode your data: ")
			if encodeOrDecode == 'encode' or encodeOrDecode == 'Encode':
				encode()
			elif encodeOrDecode == 'decode' or encodeOrDecode == 'Decode':
				decode()
			else:
				print("Invalid choice, restarting...")
				time.sleep(0.90)
				clearScreen()
				self.__init__()
		elif hashOrEncodeElse == '3':
			hashCrackFunction()
		else:
			print("Invalid choice, restarting...")
			time.sleep(0.90)
			clearScreen()
			self.__init__()

def encode():
	clearScreen()
	encodingHelpMenu()
	encodeMethod = raw_input("Which method would you like to encode your data into: ")
	if encodeMethod == 'base64' or encodeMethod == 'Base64':
		clearScreen()
		BASE64_Logo()
		data = raw_input("Input your data to encoded into Base64: ")
		result = "Result: " + base64.b64encode(data)
		print(result)
	elif encodeMethod == 'base32' or encodeMethod == 'Base32':
		clearScreen()
		BASE32_Logo()
		data = raw_input("Input your data to be encoded into Base32: ")
		result = "Result: " + base64.b32encode(data)
		print(result)
	elif encodeMethod == 'base16' or encodeMethod == 'Base16':
		clearScreen()
		BASE16_Logo()
		data = raw_input("Input your data to be encoded into Base16: ")
		result = "Result: " + base64.b16encode(data)
		print(result)
	else:
		print("Invalid choice... try again.")
		time.sleep(0.50)
		clearScreen()
		encode()

def decode():
	clearScreen()
	decodingHelpMenu()
	decodeMethod = raw_input("Which method would you like to decode your data from: ")
	if decodeMethod == 'base64' or decodeMethod == 'Base64':	
		try:
			clearScreen()
			BASE64_Logo()	
			data = raw_input("Input your data to be decoded: ")
			result = "Result: " + base64.b64decode(data)
			print(result)
		except TypeError:
			print("Invalid character entered for Base64 decoding, please try again.")
			time.sleep(0.75)
			decode()

	elif decodeMethod == 'base32' or decodeMethod == 'base32':
		try:
			clearScreen()
			BASE32_Logo()
			data = raw_input("Input your data to be decoded: ")
			result = "Result: " + base64.b32decode(data)
			print(result)
		except TypeError:
			print("Invalid character entered for Base32 decoding, please try again.")
			time.sleep(0.75)
			decode()

	elif decodeMethod == 'base16' or decodeMethod == 'Base16':	
		try:
			clearScreen()
			BASE16_Logo()
			data = raw_input("Input your data to be decoded: ")
			result = "Result: " + base64.b16decode(data)
			print(result)
		except TypeError:
			print("Invalid character entered for Base16 decoding, please try again.")
			time.sleep(0.75)
			decode()

	else:
		print("Invalid choice, please try again.")
		time.sleep(0.25)
		decode()

def saltFunction(saltChars, saltLength, result):
	salted = ''.join([random.choice(saltChars) for c in range(saltLength)])
	print("Result: " + str(result) + str(salted))

def hashCrackFunction(): # <- kinda like HashCat, but let's call it "Diet Coke HashCat" ;)
	clearScreen()
	hashCrackLogo()
	hash = raw_input("Input the data of your hash you wish to parse: ")
	filePath = raw_input("Input the full path to your hashlist to parse here: ")
	showParses = raw_input("Would you like to show the progress of parsing on your file? [Y/n]: ")
	if showParses == 'Y' or showParses == 'y':
		print("Showing parse progress...")
		try:
			with open(filePath) as f:
				lines = f.readlines()
				lineCount = 1
				for line in lines:
					if hash in line and hash != "":
						print("FOUND! -> " + line) 
						break
					print("Line " + str(lineCount) + ": " + str(line))
					time.sleep(0.001)
					lineCount = lineCount + 1
		except IOError:
			print("Invalid filepath, try again...")
			time.sleep(0.50)
			clearScreen()
			hashCrackFunction()
	elif showParses == 'N' or showParses == 'n':
		try: 
			with open(filePath) as f:
				lines = f.readlines()
				for line in lines:
					if hash in line and hash != "":
						print("FOUND! -> " + line)
						break
		except IOError:
			print("Invalid filepath, try again...")
			time.sleep(0.50)
			clearScreen()
			hashCrackFunction()
	else:
		print("Invalid input, not showing parses.")
		try: 
			with open(filePath) as f:
				lines = f.readlines()
				for line in lines:
					if hash in line and hash != "":
						print("FOUND! -> " + line)
						break
		except IOError:
			print("Invalid filepath, try again...")
			time.sleep(0.50)
			clearScreen()
			hashCrackFunction()

def hashEncode():
	clearScreen()
	hashHelpMenu()
	hashEncodeMethod = raw_input("Which hash algorithm would you like to use: ")
	if hashEncodeMethod == 'MD5' or hashEncodeMethod == 'md5' or hashEncodeMethod == 'Md5':
		clearScreen()
		MD5_Logo()
		saltOption = raw_input("Do you wish to add salt to your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			saltHelpMenu()
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into MD5 here: ")
			hashNonDigest = hashlib.md5(data)
			hashResult = hashNonDigest.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			data = raw_input("Input your data to hash into MD5 here: ")
			hashNonDigest = hashlib.md5(data)
			hashResult = hashNonDigest.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'SHA1' or hashEncodeMethod == 'Sha1' or hashEncodeMethod == 'sha1' or hashEncodeMethod == 'SHA-1' or hashEncodeMethod == 'sha-1' or hashEncodeMethod == 'Sha-1':
		clearScreen()
		SHA1_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash to SHA1 here: ")
			hashNonDigest = hashlib.sha1(data)
			hashResult = hashNonDigest.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			data = raw_input("Input your data to hash into SHA1 here: ")
			hashNonDigest = hashlib.sha1(data)
			hashResult = hashNonDigest.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'SHA224' or hashEncodeMethod == 'Sha224' or hashEncodeMethod == 'sha224' or hashEncodeMethod == 'SHA-224' or hashEncodeMethod == 'Sha-224' or hashEncodeMethod == 'sha-224':
		clearScreen()
		SHA224_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into SHA224 here: ")
			hashNonDigest = hashlib.sha224(data)
			hashResult = hashNonDigest.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			data = raw_input("Input your data to hash into SHA224 here: ")
			hashNonDigest = hashlib.sha224(data)
			hashResult = hashNonDigest.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'SHA256' or hashEncodeMethod == 'Sha256' or  hashEncodeMethod == 'sha256' or hashEncodeMethod == 'SHA-256' or hashEncodeMethod == 'Sha-256' or hashEncodeMethod == 'sha-256':
		clearScreen()
		SHA256_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into SHA256 here: ")
			hashNonDigest = hashlib.sha256(data)
			hashResult = hashNonDigest.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			data = raw_input("input your data to hash into SHA256 here: ")
			hashNonDigest = hashlib.sha256(data)
			hashResult = hashNonDigest.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'SHA384' or hashEncodeMethod == 'Sha384' or hashEncodeMethod == 'sha384' or hashEncodeMethod == 'SHA-384' or hashEncodeMethod == 'Sha-384' or hashEncodeMethod == 'sha-384':
		clearScreen()
		SHA384_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			newHash = hashlib.new('SHA384')
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into SHA384 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			newHash = hashlib.new('SHA384')
			data = raw_input("Input your data to hash into SHA384 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'SHA512' or hashEncodeMethod == 'Sha512' or hashEncodeMethod == 'sha512' or hashEncodeMethod == 'SHA-512' or hashEncodeMethod == 'Sha-512' or hashEncodeMethod == 'sha-512':
		clearScreen()
		SHA512_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into SHA512 here: ")
			hashNonDigest = hashlib.sha512(data)
			hashResult = hashNonDigest.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			data = raw_input("Input your data to hash into SHA512 here: ")
			hashNonDigest = hashlib.sha512(data)
			hashResult = hashNonDigest.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'MD4' or  hashEncodeMethod == 'Md4' or hashEncodeMethod == 'md4':
		clearScreen()
		MD4_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			newHash = hashlib.new('MD4')
			saltChars = "abcdef0123456789"
			saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
			try:
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into MD4 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			newHash = hashlib.new('MD4')
			data = raw_input("Input your data to hash into MD4 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'MD5-SHA1' or hashEncodeMethod == 'Md5-Sha1' or hashEncodeMethod == 'md5-sha1' or hashEncodeMethod == 'Md5-sha1':
		clearScreen()
		MD5SHA1_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or  saltOption == 'Y':
			newHash = hashlib.new('MD5-SHA1')
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into MD5-SHA1 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else: 
			newHash = hashlib.new('MD5-SHA1')
			data = raw_input("Input your data to hash into MD5-SHA1 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'Whirlpool' or hashEncodeMethod == 'whirlpool' or hashEncodeMethod == 'WHIRLPOOL':
		clearScreen()
		Whirlpool_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of you hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			newHash = hashlib.new('whirlpool')
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into Whirlpool here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			newHash = hashlib.new('whirlpool')
			data = raw_input("Input your data to hash into Whirlpool here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'ripemd160' or hashEncodeMethod == 'RIPEMD160' or hashEncodeMethod == 'Ripemd160':
		clearScreen()
		RIPEMD160()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			newHash = hashlib.new('RIPEMD160')
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into RIPEMD160 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			newHash = hashlib.new("RIPEMD160")
			data = raw_input("Input your data to hash into RIPEMD160 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'BLAKE2s256' or hashEncodeMethod == 'Blake2s256' or hashEncodeMethod == 'blake2s256':
		clearScreen()
		BLAKE2s256_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			newHash = hashlib.new('BLAKE2s256')
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into BLAKE2s256 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)			
		else:
			newHash = hashlib.new('BLAKE2s256')
			data = raw_input("Input your data to hash into BLAKE2s256 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			print("Result: " + hashResult)

	elif hashEncodeMethod == 'BLAKE2b512' or hashEncodeMethod == 'Blake2b512' or hashEncodeMethod == 'blake2b512':
		clearScreen()
		BLAKE2b512_Logo()
		saltOption = raw_input("Do you wish to add salt to the end of your hash? [Y/n]: ")
		if saltOption == 'y' or saltOption == 'Y':
			newHash = hashlib.new('BLAKE2b512')
			saltChars = "abcdef0123456789"
			try:
				saltLength = int(raw_input("How long do you wish the salt to be [MAX 12]: "))
				if saltLength > 12:
					saltLength = 12
				elif saltLength < 0:	
					saltLength = 0
			except ValueError:
				print("Invalid choice... defaulting to 0.")
				saltLength = 0
				os.system('exit')
			data = raw_input("Input your data to hash into BLAKE2b512 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			saltFunction(saltChars, saltLength, hashResult)
		else:
			newHash = hashlib.new('BLAKE2b512')
			data = raw_input("Input your data to hash into BLAKE2b512 here: ")
			newHash.update(data)
			hashResult = newHash.hexdigest()
			print("Result: " + hashResult)

	else:
		print("Invalid option, try again...")
		time.sleep(0.50)
		clearScreen()
		hashEncode()


#---------------------------------------------------------------------------------#
#        __  __________    ____     ____  ____  ____  __  _______  ___________    #
#       / / / / ____/ /   / __ \   / __ \/ __ \/ __ \/  |/  / __ \/_  __/ ___/    #
#      / /_/ / __/ / /   / /_/ /  / /_/ / /_/ / / / / /|_/ / /_/ / / /  \__ \     #
#     / __  / /___/ /___/ ____/  / ____/ _, _/ /_/ / /  / / ____/ / /  ___/ /     #
#    /_/ /_/_____/_____/_/      /_/   /_/ |_|\____/_/  /_/_/     /_/  /____/      #
#                                                                                 #
#---------------------------------------------------------------------------------#

def encodingHelpMenu():
	print('''
	     Encoding Methods:
	[=========================]
		- Base64
		- Base32
		- Base16
	[=========================]
	''')

def decodingHelpMenu():
	print('''
	     Decoding Methods:
	[=========================]
		- Base64
		- Base32
		- Base16
	[=========================]
	''')

def saltHelpMenu():
	print('''\033[33m
Salt is used in hashing algorithms to further decrease the chances of cracking the hash via comparison. Hash salting is a common additive in database software applications now, and should be used as much as possible for extra security!
		''')

def hashHelpMenu():
		print('''
	    Hashing Algorithms:
	[=========================]
	   - *MD5-SHA1
	   - MD5
	   - *MD4
	   - SHA-1
	   - SHA-224
	   - SHA-256
	   - SHA-384            
	   - SHA-512
	   - *Whirlpool 
	   - *RIPEMD160
	   - *BLAKE2s256        *use depends on your OpenSSL Version         
	   - *BLAKE2b512                
	[=========================]
	''')



#-----------------------------------------#
#        __    ____  __________  _____    #
#       / /   / __ \/ ____/ __ \/ ___/    #
#      / /   / / / / / __/ / / /\__ \     #
#     / /___/ /_/ / /_/ / /_/ /___/ /     #
#    /_____/\____/\____/\____//____/      #
#                                         #
#-----------------------------------------#

def MD5SHA1_Logo():
	print(''' __  __ _____  _____       _____ _    _         __ 
|  \/  |  __ \| ____|     / ____| |  | |   /\  /_ |
| \  / | |  | | |__ _____| (___ | |__| |  /  \  | |
| |\/| | |  | |___ \______\___ \|  __  | / /\ \ | |
| |  | | |__| |___) |     ____) | |  | |/ ____ \| |
|_|  |_|_____/|____/     |_____/|_|  |_/_/    \_\_|
''')

def MD5_Logo():
	print(''' __  __ _____  _____ 
|  \/  |  __ \| ____|
| \  / | |  | | |__  
| |\/| | |  | |___ \ 
| |  | | |__| |___) |
|_|  |_|_____/|____/ 
''')

def MD4_Logo():
	print(''' __  __ _____  _  _   
|  \/  |  __ \| || |  
| \  / | |  | | || |_ 
| |\/| | |  | |__   _|
| |  | | |__| |  | |  
|_|  |_|_____/   |_|
''')

def SHA1_Logo():
	print('''   _____ _    _              __ 
 / ____| |  | |   /\       /_ |
| (___ | |__| |  /  \ ______| |
 \___ \|  __  | / /\ \______| |
 ____) | |  | |/ ____ \     | |
|_____/|_|  |_/_/    \_\    |_|
''')

def SHA224_Logo():
	print('''  _____ _    _             ___  ___  _  _   
 / ____| |  | |   /\      |__ \|__ \| || |  
| (___ | |__| |  /  \ ______ ) |  ) | || |_ 
 \___ \|  __  | / /\ \______/ /  / /|__   _|
 ____) | |  | |/ ____ \    / /_ / /_   | |  
|_____/|_|  |_/_/    \_\  |____|____|  |_|  
''')

def SHA256_Logo():
	print('''  _____ _    _             ___  _____   __  
 / ____| |  | |   /\      |__ \| ____| / /  
| (___ | |__| |  /  \ ______ ) | |__  / /_  
 \___ \|  __  | / /\ \______/ /|___ \| '_ \ 
 ____) | |  | |/ ____ \    / /_ ___) | (_) |
|_____/|_|  |_/_/    \_\  |____|____/ \___/ 
''')

def SHA384_Logo():
	print('''  _____ _    _              ____   ___  _  _   
 / ____| |  | |   /\       |___ \ / _ \| || |  
| (___ | |__| |  /  \ ______ __) | (_) | || |_ 
 \___ \|  __  | / /\ \______|__ < > _ <|__   _|
 ____) | |  | |/ ____ \     ___) | (_) |  | |  
|_____/|_|  |_/_/    \_\   |____/ \___/   |_|  
''')

def SHA512_Logo():
	print('''  _____ _    _               _____ __ ___  
 / ____| |  | |   /\        | ____/_ |__ \ 
| (___ | |__| |  /  \ ______| |__  | |  ) |
 \___ \|  __  | / /\ \______|___ \ | | / / 
 ____) | |  | |/ ____ \      ___) || |/ /_ 
|_____/|_|  |_/_/    \_\    |____/ |_|____|
''')

def Whirlpool_Logo():
	print('''__          ___     _      _                   _ 
\ \        / / |   (_)    | |                 | |
 \ \  /\  / /| |__  _ _ __| |_ __   ___   ___ | |
  \ \/  \/ / | '_ \| | '__| | '_ \ / _ \ / _ \| |
   \  /\  /  | | | | | |  | | |_) | (_) | (_) | |
    \/  \/   |_| |_|_|_|  |_| .__/ \___/ \___/|_|
                            | |                  
                            |_|                  
''')

def RIPEMD160():
	print(''' _____  _____ _____  ______ __  __ _____  __   __   ___  
|  __ \|_   _|  __ \|  ____|  \/  |  __ \/_ | / /  / _ \ 
| |__) | | | | |__) | |__  | \  / | |  | || |/ /_ | | | |
|  _  /  | | |  ___/|  __| | |\/| | |  | || | '_ \| | | |
| | \ \ _| |_| |    | |____| |  | | |__| || | (_) | |_| |
|_|  \_\_____|_|    |______|_|  |_|_____/ |_|\___/ \___/ 
''')

def BLAKE2s256_Logo():
	print(''' ____  _               _  ________ ___      ___  _____   __  
|  _ \| |        /\   | |/ /  ____|__ \    |__ \| ____| / /  
| |_) | |       /  \  | ' /| |__     ) |___   ) | |__  / /_  
|  _ <| |      / /\ \ |  < |  __|   / // __| / /|___ \| '_ \ 
| |_) | |____ / ____ \| . \| |____ / /_\__ \/ /_ ___) | (_) |
|____/|______/_/    \_\_|\_\______|____|___/____|____/ \___/ 
''')

def BLAKE2b512_Logo():
	print(''' ____  _               _  ________ ___  _    _____ __ ___  
|  _ \| |        /\   | |/ /  ____|__ \| |  | ____/_ |__ \ 
| |_) | |       /  \  | ' /| |__     ) | |__| |__  | |  ) |
|  _ <| |      / /\ \ |  < |  __|   / /| '_ \___ \ | | / / 
| |_) | |____ / ____ \| . \| |____ / /_| |_) |__) || |/ /_ 
|____/|______/_/    \_\_|\_\______|____|_.__/____/ |_|____|
''')

def BASE64_Logo():
	print(''' ____           _____ ______  __ _  _   
|  _ \   /\    / ____|  ____|/ /| || |  
| |_) | /  \  | (___ | |__  / /_| || |_ 
|  _ < / /\ \  \___ \|  __|| '_ \__   _|
| |_) / ____ \ ____) | |___| (_) | | |  
|____/_/    \_\_____/|______\___/  |_|  
''')

def BASE32_Logo():
	print(''' ____           _____ ______ ____ ___  
|  _ \   /\    / ____|  ____|___ \__ \ 
| |_) | /  \  | (___ | |__    __) | ) |
|  _ < / /\ \  \___ \|  __|  |__ < / / 
| |_) / ____ \ ____) | |____ ___) / /_ 
|____/_/    \_\_____/|______|____/____|
''')

def BASE16_Logo():
	print(''' ____           _____ ______ __   __  
|  _ \   /\    / ____|  ____/_ | / /  
| |_) | /  \  | (___ | |__   | |/ /_  
|  _ < / /\ \  \___ \|  __|  | | '_ \ 
| |_) / ____ \ ____) | |____ | | (_) |
|____/_/    \_\_____/|______||_|\___/ 
''')

def hashCrackLogo():
	print('''                 _       ___               _    
  /\\  /\\__ _ ___| |__   / __\\ __ __ _  ___| | __
 / /_/ / _` / __| '_ \\ / / | '__/ _` |/ __| |/ /
/ __  / (_| \\__ \\ | | / /__| | | (_| | (__|   < 
\\/ /_/ \\__,_|___/_| |_\\____/_|  \\__,_|\\___|_|\\_\\
''')

def mainLogo():
	print('''================================================================================
 |                   __   ___  _________  ___  __                             |
 |                   |\  \|\  \|\___   ___\\  \|\  \                           |
 |                   \ \  \\\  \|___ \  \_\ \  \/  /|_                         |
 |                    \ \   __  \   \ \  \ \ \   ___  \                       |
 |                     \ \  \ \  \   \ \  \ \ \  \\ \  \                       |
 |                      \ \__\ \__\   \ \__\ \ \__\\ \__\                      |
 |                       \|__|\|__|    \|__|  \|__| \|__|                     |
 |                                                                            |\n================================================================================''')



#----------------------------------------------------------------------------------------#
#        _____   ___________________    __    _________   ___  ______________  _   __    #
#       /  _/ | / /  _/_  __/  _/   |  / /   /  _/__  /  /   |/_  __/  _/ __ \/ | / /    #
#       / //  |/ // /  / /  / // /| | / /    / /   / /  / /| | / /  / // / / /  |/ /     #
#     _/ // /|  // /  / / _/ // ___ |/ /____/ /   / /__/ ___ |/ / _/ // /_/ / /|  /      #
#    /___/_/ |_/___/ /_/ /___/_/  |_/_____/___/  /____/_/  |_/_/ /___/\____/_/ |_/       #
#                                                                                        #
#----------------------------------------------------------------------------------------#

# Hook main function when filename is "main" and not imported (god knows why it would be)
if __name__ == "__main__":
	try:
		mainRun()
	except KeyboardInterrupt:
		print("\nExiting...")
		try:
			time.sleep(0.10)
		except KeyboardInterrupt:
			os.system('exit')
		clearScreen()
		os.system('exit')
