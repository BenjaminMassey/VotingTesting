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

window = Tk()

window.title("Voting Machine")
window.geometry('400x600')

infoLabel = Label(window, text="President of the United States")
infoLabel.config(font=("Courier", 16))
infoLabel.pack()

radioValue = IntVar()
radioValue.set(-1)

candidates = ["Alex Jones", "Obummer", "Ligma", "WRITE-IN"]

i = 1
for candidate in candidates:
    radio = Radiobutton(window, 
               text=candidate,
               variable=radioValue, 
               value=i)
    radio.config(font=("Courier",12))
    radio.pack()
    i += 1

writeIn = StringVar()
writeIn.set("")

writeInEntry = Entry(window, textvariable=writeIn)
writeInEntry.config(font=("Courier",12))
writeInEntry.pack()

def getCandidate(radio_id):
    return candidates[radio_id - 1]

def process():
    global writeIn, voteText
    candidates[len(candidates)-1] = writeIn.get()
    rv = radioValue.get()
    if rv == -1:
        voteText.set("Please vote :)")
    else:
        result = getCandidate(radioValue.get())
        voteText.set(result)

Label(window,text="").pack()

submitButton = Button(window, text="Submit", command=process)
submitButton.config(font=("Courier", 12))
submitButton.pack()

voteText = StringVar()
voteText.set("---")
voteLabel = Label(window, textvariable=voteText)
voteLabel.config(font=("Courier", 16))
voteLabel.pack()

Label(window,text="").pack()

encrypted_result = None

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
encryptButton.pack()

encryptText = StringVar()
encryptText.set("---")
encryptLabel = Label(window, textvariable=encryptText, wraplength=300)
encryptLabel.config(font=("Courier", 16))
encryptLabel.pack()

Label(window,text="").pack()

def decrypt():
    global decryptText, encrypted_result
    if encrypted_result == None:
        return
    decryptedCandidate = decrypt_message(encrypted_result)
    decryptText.set(decryptedCandidate)

decryptButton = Button(window, text="Decrypt", command=decrypt)
decryptButton.config(font=("Courier", 12))
decryptButton.pack()

decryptText = StringVar()
decryptText.set("---")
decryptLabel = Label(window, textvariable=decryptText)
decryptLabel.config(font=("Courier", 16))
decryptLabel.pack()

window.mainloop()
