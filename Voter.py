# CIS 433 Winter Term 2021
# Project by Ben Massey, Michael Welch and Alex Bichler

from tkinter import *
from cryptography.fernet import Fernet

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.utils.encoding import force_bytes, force_text

## Caesar Functions
secret_number = 4 # keep small: no looping check

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


## ECB AES Functions
# These functions were taken directly from here:
# https://gist.github.com/tcitry/df5ee377ad112d7637fe7b9211e6bc83

SECRET_KEY = "abcdefghijklmnopq"
value = force_bytes("12345678901234567890")

backend = default_backend()
key = force_bytes(base64.urlsafe_b64encode(force_bytes(SECRET_KEY))[:32])

class Crypto:

    def __init__(self):
        self.encryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).encryptor()
        self.decryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).decryptor()

    def encrypt(self):
        padder = padding.PKCS7(algorithms.AES(key).block_size).padder()
        padded_data = padder.update(value) + padder.finalize()
        encrypted_text = self.encryptor.update(padded_data) + self.encryptor.finalize()
        return encrypted_text

    def decrypt(self, value):
        padder = padding.PKCS7(algorithms.AES(key).block_size).unpadder()
        decrypted_data = self.decryptor.update(value)
        unpadded = padder.update(decrypted_data) + padder.finalize()
        return unpadded

## CBC AES Functions
# The following encryption functions are from here:
# https://devqa.io/encrypt-decrypt-data-python/
fernet_key = Fernet.generate_key()

def encrypt_message(message):
    global fernet_key
    encoded_message = message.encode()
    f = Fernet(fernet_key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

def decrypt_message(encrypted_message):
    global fernet_key
    f = Fernet(fernet_key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()


## RSA Encryption Functions
# All of this is taken nearly directly from the following link:
# https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as apad

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

def rsa_encrypt(original_text):
    global public_key
    message = force_bytes(original_text)
    encrypted = public_key.encrypt(
        message,
        apad.OAEP(
            mgf=apad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def rsa_decrypt(encrypted_text):
    global private_key
    original_text = private_key.decrypt(
        encrypted_text,
        apad.OAEP(
            mgf=apad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return force_text(original_text)


## GUI Setup
window = Tk()
window.title("Voting Machine")
window.geometry('1300x950')


## Here is the top section, used to vote
# Title label
infoLabel = Label(window, text="President of the United States")
infoLabel.config(font=("Courier", 16, "bold"))
infoLabel.grid(row=0, columnspan=4)

# Number value corresponding to the vote
radioValue = IntVar()
radioValue.set(-1)

# Dynamic list of voting options: always leave last  as write-in
candidates = ["Trump", "Biden", "Jorgensen", "WRITE-IN"]

# Create radio option for each voting option
i = 1
for candidate in candidates:
    radio = Radiobutton(window, 
               text=candidate,
               variable=radioValue, 
               value=i)
    radio.config(font=("Courier",12))
    radio.grid(row=i, columnspan=4)
    i += 1

# How we will read our write-in
writeIn = StringVar()
writeIn.set("")

writeInEntry = Entry(window, textvariable=writeIn)
writeInEntry.config(font=("Courier",12))
writeInEntry.grid(row=i, columnspan=4)

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
submitButton.grid(row=i+1, columnspan=4)

Label(window,text="").grid(row=i+2, column=1)

resultLabel = Label(window, text="Result:")
resultLabel.config(font=("Courier", 12))
resultLabel.grid(row=i+3, columnspan=4)

voteText = StringVar()
voteText.set("---")
voteLabel = Label(window, textvariable=voteText)
voteLabel.config(font=("Courier", 16))
voteLabel.grid(row=i+4, columnspan=4, padx=10)

Label(window,text="").grid(row=i+5, columnspan=4)


## End of top section, now the first encryption version

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
encryptButton1.grid(row=i+7, column=0, padx=10)

encryptText1 = StringVar()
encryptText1.set("---")
encryptLabel1 = Label(window, textvariable=encryptText1, wraplength=300, width=23)
encryptLabel1.config(font=("Courier", 16))
encryptLabel1.grid(row=i+8, column=0, padx=10)

def decrypt1():
    global decryptText1, caesar_result
    if caesar_result == None:
        return
    decrypted = caesar_decrypt(caesar_result)
    decryptText1.set(decrypted)

decryptButton1 = Button(window, text="Decrypt", command=decrypt1)
decryptButton1.config(font=("Courier", 12))
decryptButton1.grid(row=i+9, column=0, padx=10)

decryptText1 = StringVar()
decryptText1.set("---")
decryptLabel1 = Label(window, textvariable=decryptText1)
decryptLabel1.config(font=("Courier", 16))
decryptLabel1.grid(row=i+10, column=0, padx=10)


## End of the first encyrption, now the second encryption version

secondSectionLabel = Label(window, text="ECB AES")
secondSectionLabel.config(font=("Courier", 16, "bold"))
secondSectionLabel.grid(row=i+6, column=1)

ecb_result = None

def encrypt2():
    global value, ecb_aes, voteText, encryptText2, ecb_result
    votedCandidate = voteText.get()
    if votedCandidate == "Please vote :)" or votedCandidate == "---":
        return
    ecb_aes = Crypto()
    value = force_bytes(votedCandidate)
    ecb_result = force_text(base64.urlsafe_b64encode(ecb_aes.encrypt()))
    encryptText2.set(str(ecb_result))

encryptButton2 = Button(window, text="Encrypt", command=encrypt2)
encryptButton2.config(font=("Courier", 12))
encryptButton2.grid(row=i+7, column=1, padx=10)

encryptText2 = StringVar()
encryptText2.set("---")
encryptLabel2 = Label(window, textvariable=encryptText2, wraplength=300, width=23)
encryptLabel2.config(font=("Courier", 16))
encryptLabel2.grid(row=i+8, column=1, padx=10)

def decrypt2():
    global ecb_aes, decryptText2, ecb_result
    if ecb_result == None:
        return
    result = force_text(ecb_aes.decrypt(base64.urlsafe_b64decode(ecb_result)))
    decryptText2.set(str(result))

decryptButton2 = Button(window, text="Decrypt", command=decrypt2)
decryptButton2.config(font=("Courier", 12))
decryptButton2.grid(row=i+9, column=1, padx=10)

decryptText2 = StringVar()
decryptText2.set("---")
decryptLabel2 = Label(window, textvariable=decryptText2)
decryptLabel2.config(font=("Courier", 16))
decryptLabel2.grid(row=i+10, column=1, padx=10)


## End of second encryption, now the third encryption version

thirdSectionLabel = Label(window, text="CBC AES")
thirdSectionLabel.config(font=("Courier", 16, "bold"))
thirdSectionLabel.grid(row=i+6, column=2)

fernet_result = None

def encrypt3():
    global voteText, encryptText3, fernet_result
    votedCandidate = voteText.get()
    if votedCandidate == "Please vote :)" or votedCandidate == "---":
        return
    encryptedCandidate = encrypt_message(votedCandidate)
    encryptText3.set(encryptedCandidate)
    fernet_result = encryptedCandidate

encryptButton3 = Button(window, text="Encrypt", command=encrypt3)
encryptButton3.config(font=("Courier", 12))
encryptButton3.grid(row=i+7, column=2, padx=10)

encryptText3 = StringVar()
encryptText3.set("---")
encryptLabel3 = Label(window, textvariable=encryptText3, wraplength=300, width=23, height=5)
encryptLabel3.config(font=("Courier", 16))
encryptLabel3.grid(row=i+8, column=2, padx=10)

def decrypt3():
    global decryptText3, fernet_result
    if fernet_result == None:
        return
    decryptedCandidate = decrypt_message(fernet_result)
    decryptText3.set(decryptedCandidate)

decryptButton3 = Button(window, text="Decrypt", command=decrypt3)
decryptButton3.config(font=("Courier", 12))
decryptButton3.grid(row=i+9, column=2, padx=10)

decryptText3 = StringVar()
decryptText3.set("---")
decryptLabel3 = Label(window, textvariable=decryptText3)
decryptLabel3.config(font=("Courier", 16))
decryptLabel3.grid(row=i+10, column=2, padx=10)

## End of third encryption, now the fourth encryption version

fourthSectionLabel = Label(window, text="RSA")
fourthSectionLabel.config(font=("Courier", 16, "bold"))
fourthSectionLabel.grid(row=i+6, column=3)

rsa_result = None

def encrypt4():
    global rsa_result, voteText, encryptText4
    votedCandidate = voteText.get()
    if votedCandidate == "Please vote :)" or votedCandidate == "---":
        return
    encryptedCandidate = rsa_encrypt(votedCandidate)
    rsa_result = encryptedCandidate
    encryptText4.set(encryptedCandidate)

encryptButton4 = Button(window, text="Encrypt", command=encrypt4)
encryptButton4.config(font=("Courier", 12))
encryptButton4.grid(row=i+7, column=3, padx=10)

encryptText4 = StringVar()
encryptText4.set("---")
encryptLabel4 = Label(window, textvariable=encryptText4, wraplength=300, width=23, height=15)
encryptLabel4.config(font=("Courier", 16))
encryptLabel4.grid(row=i+8, column=3, padx=10)

def decrypt4():
    global rsa_result, decryptText4
    if rsa_result == None:
        return
    decryptedCandidate = rsa_decrypt(rsa_result)
    decryptText4.set(decryptedCandidate)

decryptButton4 = Button(window, text="Decrypt", command=decrypt4)
decryptButton4.config(font=("Courier", 12))
decryptButton4.grid(row=i+9, column=3, padx=10)

decryptText4 = StringVar()
decryptText4.set("---")
decryptLabel4 = Label(window, textvariable=decryptText4)
decryptLabel4.config(font=("Courier", 16))
decryptLabel4.grid(row=i+10, column=3, padx=10)


## Clear button, for demonstration purposes

def clearGUI():
    global encryptText1, decryptText1, caesar_result, \
           encryptText2, decryptText2, ecb_result, \
           encryptText3, decryptText3, fernet_result, \
           encryptText4, decryptText4, rsa_result, \
           radioValue, voteText

    encryptText1.set("---")
    encryptText2.set("---")
    encryptText3.set("---")
    encryptText4.set("---")
    decryptText1.set("---")
    decryptText2.set("---")
    decryptText3.set("---")
    decryptText4.set("---")

    caesar_result = None
    ecb_result = None
    fernet_result = None
    rsa_result = None

    radioValue.set(-1)
    voteText.set("---")

clearButton = Button(window, text="Clear", command=clearGUI)
clearButton.config(font=("Courier",12))
clearButton.grid(row=i+11,columnspan=4,pady=100)

## Let 'er rip!

window.mainloop()
