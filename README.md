# Voting Testing

## Domain

This is the coding part of a class project for CIS 433 during Winter Term 2021.
The Project is done by Ben Massey, Michael Welch, and Alex Bichler.

## Purpose

The purpose of this program is to demonstrate different encryption methods in
the context of voting security. It provides a pseudo-voting system along with
different methods to encrypt and decrypt said vote. We use this in our project
to explore what is important when it comes to encryption concerns in voting security.

## Screenshot

Here is a screenshot of our application, for the purpose of quickly understanding
it and generally having a preview. 

![Screenshot](https://i.imgur.com/7KqbF1Y.png)

## Installation

The only required library to download is cryptography, which can be installed
via the following command in a command prompt:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;pip install cryptography

## Usage

The program is intended to be fairly simple to use.
It should be run the same as any other Python script,
so running "python Voter.py" in your command
prompt / terminal, or via an auxillary program like IDLE.
Once started, the user enters the vote for their preferred
candidate at the top center of the screen, which involves 
clicking the corresponding radio button and pressing the submit
button. This then allows one to try out the four encryption
methods on the bottom half of the window. First, one may click an "Encrypt"
button, which displays the encrytped version. Then, the user can
click the related "Decrypt" button which converts it into the decrypted
text. If the user ever wants to reset this whole process, they can click
the "Clear" button in the bottom middle.

## Sources

The encrytpion methods (aside from Caesar Cipher) were not written by us, but
instead were taken from online -- seeing as the creation of encryption code
was not the point of this project. Here are the different sources (as also
outlined in the code comments):

ECB AES: https://gist.github.com/tcitry/df5ee377ad112d7637fe7b9211e6bc83

CBC AES: https://devqa.io/encrypt-decrypt-data-python/

RSA: https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

Without such useful resources, this section of the project would have not been
worth the time investment in comparison to other research, so please check out
these sources as they were extremely helpful in allowing us to pursue our project
as best we could.

## Contact

Feel free to email benjamin.w.massey@gmail.com for any questions/contact.
