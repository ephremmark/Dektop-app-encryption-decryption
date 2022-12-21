from tkinter import *
from tkinter import ttk
from otp import *
from Triple_des import triple_des,base64
import aes


ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
root = Tk()
root.resizable(0,0)

root.title("Encryiption and decryption call")
Ciphered = ""
decipher = ""
Algorithm = IntVar()


encryptedframe = LabelFrame(text="Encryption call",width=45, height= 15)
encryptedframe.grid(row=0,column=0, padx=18, pady=0)
title_frame = Label(encryptedframe, text="Type the message to encrypt")
title_frame.pack(side=TOP)
messagebox = Text(encryptedframe, width=45, height=15,)
messagebox.pack()

encryptedkey_frame = LabelFrame(width=400, height= 10)
encryptedkey_frame.grid(row=1,column=0, padx=0, pady=0)
label = Label(encryptedkey_frame, text="Enter The Encryption Key", fg="Blue")
label.grid(row=0,column=0)
Encryptedkey = Entry(encryptedkey_frame,width=32)
Encryptedkey.grid(row=0,column=1, padx=20)


Encrypt_text = LabelFrame(borderwidth=0,width=35, height= 10)
Encrypt_text.grid(row=2,column=0, padx=20, pady=0)
Ciphered_text = Text(Encrypt_text, width=40, height=10)
Ciphered_text.pack()


decryptedframe = LabelFrame(text="Decryption call", borderwidth=0,width=45, height= 15)
decryptedframe.grid(row=0,column=1, padx=18, pady=0)
label = Label(decryptedframe, text="Type the message to Decrypt")
label.pack(side=TOP)
message_to_decrypt = Text(decryptedframe, width=45, height=15)
message_to_decrypt.pack()


decryptedkey_frame = ttk.LabelFrame(width=400, height= 10)
decryptedkey_frame.grid(row=1,column=1, padx=2, pady=0)
label = Label(decryptedkey_frame, text="Enter The Decryption Key", fg="Blue",borderwidth=0)
label.grid(row=0,column=0)
Decryptedkey = Entry(decryptedkey_frame,width=32)
Decryptedkey.grid(row=0,column=1, padx=20)


Decrypt_text = LabelFrame(borderwidth=0,width=35, height= 10)
Decrypt_text.grid(row=2,column=1, padx=20, pady=0)
Deciphered_message = Text(Decrypt_text, width=40, height=10)
Deciphered_message.pack()


algorithm_frame = ttk.LabelFrame(width=400, height= 10)
algorithm_frame.grid(row=3,column=0, padx=20, pady=0)
label = Label(algorithm_frame, text="Choose Algorithms")
label.grid(row=0,column=0)
Radiobutton(algorithm_frame ,text="OTP",variable=Algorithm,value=0).grid(row=6,column=0)
Radiobutton(algorithm_frame  ,text="3DES",variable=Algorithm,value=1).grid(row=6,column=1)
Radiobutton(algorithm_frame  ,text="AES",variable=Algorithm,value=2).grid(row=6,column=2)



def copy():
        pass



def encrypt():


    plain_text = messagebox.get(1.0,END)
    plain_text = plain_text.strip()
    key = Encryptedkey.get()
    Ciphered_text.config(state=NORMAL)
    message_to_decrypt.config(state=NORMAL)
    Ciphered_text.delete(1.0, 'end-1c')
    ciphered = ''

    if Algorithm.get() == 0:
        Ciphered_text.delete(1.0, END)
        ciphered = OTP_encrypt(plain_text,key)
    elif Algorithm.get() == 1:
        data = bytes(plain_text,"utf-8")
        CBC = 0
        try:
            k = triple_des(key, CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=2)
            ciphered =base64.b64encode(k.encrypt(data))
        except Exception as e:
            Ciphered_text.insert(END,e)
            pass
    elif Algorithm.get() == 2:
        try:
            key = bytes(key, 'utf-8')
            iv = b'\xbe\xa9Q\x18\x9a}\xcf\xd0tH\xc7+~\xe1\xc5\xac'
            encrypted = aes.AES(key).encrypt(bytes(plain_text,"utf-8"),iv)
            ciphered = base64.b64encode(encrypted)
        except Exception as e:
            Ciphered_text.insert(END,e)
        pass

    Ciphered_text.insert(INSERT, ciphered)

def deycrypt():
        plain_text = ''
        ciphered = message_to_decrypt.get(1.0, 'end-1c')
        ciphered = ciphered.strip()
        key = Encryptedkey.get()
        Deciphered_message.delete(1.0, 'end-1c')
        if Algorithm.get() == 0:

            plain_text = OTP_decrypt(ciphered,key)
        elif Algorithm.get() == 1:
            try:
                data =base64.b64decode(ciphered)
                CBC = 0
                k = triple_des(key, CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=2)
                plain_text = k.decrypt(data)
            except Exception as e:
                Deciphered_message.insert(END,e)
                pass
        elif Algorithm.get() == 2:
                try:
                    data =base64.b64decode(ciphered)
                    key = bytes(key, 'utf-8')
                    iv = b'\xbe\xa9Q\x18\x9a}\xcf\xd0tH\xc7+~\xe1\xc5\xac'
                    plain_text = aes.AES(key).decrypt_ctr(data, iv)
                except Exception as e:
                    Deciphered_message.insert(END,e)
                pass

        Deciphered_message.insert(INSERT,plain_text)

encryption_button = Button(encryptedkey_frame,text="Encrypt", fg="white", bg="Green", command=encrypt)
encryption_button.grid(row=2, column=0, padx= 0, pady= 20)
Copyencrypt_btn = Button(encryptedkey_frame,text="Copy Encryption", fg="white", bg="Red", command=copy)
Copyencrypt_btn.grid(row=2, column=1, padx= 0, pady= 20)

decrypt_btn = Button(decryptedkey_frame,text="Decrypt", fg="white", bg="Green", command=deycrypt)
decrypt_btn.grid(row=2, column=0, padx= 0, pady= 20)
Copydecrypt_btn = Button(decryptedkey_frame,text="Copy Decryption", fg="white", bg="Red", command=copy)
Copydecrypt_btn.grid(row=2, column=1, padx= 0, pady= 20)

root.mainloop()
