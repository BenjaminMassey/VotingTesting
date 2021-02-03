# Made for CIS 433 by Benjamin Massey

from tkinter import *
from cryptography.fernet import Fernet

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

# GUI Setup
window = Tk()

window.title("Voting Machine")
window.geometry('1280x720')

# Title label
infoLabel = Label(window, text="President of the United States")
infoLabel.config(font=("Courier", 16))
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

#Label(window,text="").pack() # Spacing

submitButton = Button(window, text="Submit", command=process)
submitButton.config(font=("Courier", 12))
submitButton.grid(row=i+1, column=1)

voteText = StringVar()
voteText.set("---")
voteLabel = Label(window, textvariable=voteText)
voteLabel.config(font=("Courier", 16))
voteLabel.grid(row=i+2, column=0, padx=175)

#Label(window,text="").pack() # Spacing

# Here we will store our encrypted bytestring
# Tried to avoid this, but encoding got weird
encrypted_result = None

# Look at our voted candidate, then encrypt it
def encrypt():
    global voteText, encryptText, encrypted_result
    votedCandidate = voteText.get()
    if votedCandidate == "Please vote :)" or votedCandidate == "---":
        return
    encryptedCandidate = encrypt_message(votedCandidate)
    encryptText.set(encryptedCandidate)
    encrypted_result = encryptedCandidate

encryptButton = Button(window, text="Encrypt", command=encrypt)
encryptButton.config(font=("Courier", 12))
encryptButton.grid(row=i+3, column=0, padx=175)

encryptText = StringVar()
encryptText.set("---")
encryptLabel = Label(window, textvariable=encryptText, wraplength=300)
encryptLabel.config(font=("Courier", 16))
encryptLabel.grid(row=i+4, column=0, padx=175)

#Label(window,text="").pack() # Spacing

# Look at our encrypted candidate variable and decrypt it
def decrypt():
    global decryptText, encrypted_result
    if encrypted_result == None:
        return
    decryptedCandidate = decrypt_message(encrypted_result)
    decryptText.set(decryptedCandidate)

decryptButton = Button(window, text="Decrypt", command=decrypt)
decryptButton.config(font=("Courier", 12))
decryptButton.grid(row=i+5, column=0, padx=175)

decryptText = StringVar()
decryptText.set("---")
decryptLabel = Label(window, textvariable=decryptText)
decryptLabel.config(font=("Courier", 16))
decryptLabel.grid(row=i+6, column=0, padx=175)

window.mainloop()
