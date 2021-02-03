# Made for CIS 433 by Benjamin Massey

from tkinter import *
from cryptography.fernet import Fernet


## Caesar Functions
secret_number = 4 # keep small: caesar VERY dumb rn

def caesar(s1, sign):
    global secret_number
    s2 = ""
    for c1 in s1:
        s2 += str(chr(ord(c1) + (secret_number * sign)))
    return s2

def caesar_encrypt(s):
    global caesar
    return caesar(s, 1)

def caesar_decrypt(s):
    global caesar
    return caesar(s, -1)


## Fernet Functions
# The following encryption functions are from here:
# https://devqa.io/encrypt-decrypt-data-python/
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(message):
    key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

generate_key()


## GUI Setup
window = Tk()
window.title("Voting Machine")
window.geometry('1150x600')


## Here is the top section, used to vote
# Title label
infoLabel = Label(window, text="President of the United States")
infoLabel.config(font=("Courier", 16, "bold"))
infoLabel.grid(row=0, column=1)

# Number value corresponding to the vote
radioValue = IntVar()
radioValue.set(-1)

# Dynamic list of voting options: always leave last  as write-in
candidates = ["Alex Jones", "Obummer", "Ligma", "WRITE-IN"]

# Create radio option for each voting option
i = 1
for candidate in candidates:
    radio = Radiobutton(window, 
               text=candidate,
               variable=radioValue, 
               value=i)
    radio.config(font=("Courier",12))
    radio.grid(row=i, column=1)
    i += 1

# How we will read our write-in
writeIn = StringVar()
writeIn.set("")

writeInEntry = Entry(window, textvariable=writeIn)
writeInEntry.config(font=("Courier",12))
writeInEntry.grid(row=i, column=1)

# Helper function, only global since it could be useful later
# Takes radio variable and converts it via our string list
def getCandidate(radio_id):
    return candidates[radio_id - 1]

# Handle the voting process
def process():
    global writeIn, voteText
    candidates[len(candidates)-1] = writeIn.get()
    rv = radioValue.get()
    if rv == -1:
        voteText.set("Please vote :)")
    else:
        result = getCandidate(radioValue.get())
        voteText.set(result)

submitButton = Button(window, text="Submit", command=process)
submitButton.config(font=("Courier", 12))
submitButton.grid(row=i+1, column=1)

Label(window,text="").grid(row=i+2, column=1)

resultLabel = Label(window, text="Result:")
resultLabel.config(font=("Courier", 12))
resultLabel.grid(row=i+3, column=1)

voteText = StringVar()
voteText.set("---")
voteLabel = Label(window, textvariable=voteText)
voteLabel.config(font=("Courier", 16))
voteLabel.grid(row=i+4, column=1, padx=100)

Label(window,text="").grid(row=i+5, column=1)


## End of top section, now the left encryption version
firstSectionLabel = Label(window, text="Caesar Cipher")
firstSectionLabel.config(font=("Courier", 16, "bold"))
firstSectionLabel.grid(row=i+6, column=0)

caesar_result = None

def encrypt1():
    global caesar_encrypt, voteText, encryptText1, caesar_result
    votedCandidate = voteText.get()
    if votedCandidate == "Please vote :)" or votedCandidate == "---":
        return
    encryptedCandidate = caesar_encrypt(votedCandidate)
    encryptText1.set(encryptedCandidate)
    caesar_result = encryptedCandidate

encryptButton1 = Button(window, text="Encrypt", command=encrypt1)
encryptButton1.config(font=("Courier", 12))
encryptButton1.grid(row=i+7, column=0, padx=100)

encryptText1 = StringVar()
encryptText1.set("---")
encryptLabel1 = Label(window, textvariable=encryptText1, wraplength=300)
encryptLabel1.config(font=("Courier", 16))
encryptLabel1.grid(row=i+8, column=0, padx=100)

def decrypt1():
    global decryptText1, caesar_result
    if caesar_result == None:
        return
    decrypted = caesar_decrypt(caesar_result)
    decryptText1.set(decrypted)

decryptButton1 = Button(window, text="Decrypt", command=decrypt1)
decryptButton1.config(font=("Courier", 12))
decryptButton1.grid(row=i+9, column=0, padx=100)

decryptText1 = StringVar()
decryptText1.set("---")
decryptLabel1 = Label(window, textvariable=decryptText1)
decryptLabel1.config(font=("Courier", 16))
decryptLabel1.grid(row=i+10, column=0, padx=100)


## End of the left encyrption, now the middle encryption version
secondSectionLabel = Label(window, text="Fernet Encryption")
secondSectionLabel.config(font=("Courier", 16, "bold"))
secondSectionLabel.grid(row=i+6, column=1)

# Here we will store our encrypted bytestring
# Tried to avoid this, but encoding got weird
fernet_result = None

# Look at our voted candidate, then encrypt it
def encrypt2():
    global voteText, encryptText2, fernet_result
    votedCandidate = voteText.get()
    if votedCandidate == "Please vote :)" or votedCandidate == "---":
        return
    encryptedCandidate = encrypt_message(votedCandidate)
    encryptText2.set(encryptedCandidate)
    fernet_result = encryptedCandidate

encryptButton2 = Button(window, text="Encrypt", command=encrypt2)
encryptButton2.config(font=("Courier", 12))
encryptButton2.grid(row=i+7, column=1, padx=100)

encryptText2 = StringVar()
encryptText2.set("-"*100)
encryptLabel2 = Label(window, textvariable=encryptText2, wraplength=300)
encryptLabel2.config(font=("Courier", 16))
encryptLabel2.grid(row=i+8, column=1, padx=100)

# Look at our encrypted candidate variable and decrypt it
def decrypt2():
    global decryptText2, fernet_result
    if fernet_result == None:
        return
    decryptedCandidate = decrypt_message(fernet_result)
    decryptText2.set(decryptedCandidate)

decryptButton2 = Button(window, text="Decrypt", command=decrypt2)
decryptButton2.config(font=("Courier", 12))
decryptButton2.grid(row=i+9, column=1, padx=100)

decryptText2 = StringVar()
decryptText2.set("---")
decryptLabel2 = Label(window, textvariable=decryptText2)
decryptLabel2.config(font=("Courier", 16))
decryptLabel2.grid(row=i+10, column=1, padx=100)


## End of middle encryption, now the right encryption version
thirdSectionLabel = Label(window, text="Bestest Coolest Version")
thirdSectionLabel.config(font=("Courier", 16, "bold"))
thirdSectionLabel.grid(row=i+6, column=2)

mystery_result = None

def encrypt3():
    global voteText, encryptText3, caesar_result
    votedCandidate = voteText.get()
    if votedCandidate == "Please vote :)" or votedCandidate == "---":
        return
    encryptText3.set("Place")
    mystery_result = "Place"

encryptButton3 = Button(window, text="Encrypt", command=encrypt3)
encryptButton3.config(font=("Courier", 12))
encryptButton3.grid(row=i+7, column=2, padx=100)

encryptText3 = StringVar()
encryptText3.set("---")
encryptLabel3 = Label(window, textvariable=encryptText3, wraplength=300)
encryptLabel3.config(font=("Courier", 16))
encryptLabel3.grid(row=i+8, column=2, padx=100)

def decrypt3():
    global decryptText3, mystery_result
    if mystery_result == None:
        return
    #mystery_result
    decryptText3.set("Holder")

decryptButton3 = Button(window, text="Decrypt", command=decrypt3)
decryptButton3.config(font=("Courier", 12))
decryptButton3.grid(row=i+9, column=2, padx=100)

decryptText3 = StringVar()
decryptText3.set("---")
decryptLabel3 = Label(window, textvariable=decryptText3)
decryptLabel3.config(font=("Courier", 16))
decryptLabel3.grid(row=i+10, column=2, padx=100)

window.mainloop()
