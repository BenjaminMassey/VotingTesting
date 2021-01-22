from tkinter import *

window = Tk()

window.title("Voting Machine")
window.geometry('500x200')

infoLabel = Label(window, text="President of the United States")
infoLabel.config(font=("Courier", 16))
infoLabel.pack()

debugText = StringVar()
debugText.set("---")

debugLabel = Label(window, textvariable=debugText)
debugLabel.config(font=("Courier", 16))
# Pack later, since want last

radioValue = IntVar()
radioValue.set(-1)

candidates = ["Alex Jones", "Obummer", "Ligma"]

i = 1
for candidate in candidates:
    radio = Radiobutton(window, 
               text=candidate,
               variable=radioValue, 
               value=i)
    radio.config(font=("Courier",12))
    radio.pack()
    i += 1

def getCandidate(radio_id):
    return candidates[radio_id - 1]

def process():
    global debugText
    rv = radioValue.get()
    if rv == -1:
        debugText.set("Bad lib, didn't vote")
    else:
        result = "Woo! Voted " + getCandidate(radioValue.get())
        debugText.set(result)

submitButton = Button(window, text="Submit", command=process)
submitButton.config(font=("Courier", 12))
submitButton.pack()

Label(window,text="").pack()

debugLabel.pack()

window.mainloop()
