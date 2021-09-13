import pandas as pd



def generateKey(string, key): 
    key = list(key) 
    if len(string) == len(key): 
        return(key) 
    else: 
        for i in range(len(string) - 
                       len(key)): 
            key.append(key[i % len(key)]) 
    return("" . join(key))

def decrypter(cipher_text, key): 
    orig_text = [] 
    for i in range(len(cipher_text)): 
        x = (ord(cipher_text[i]) - 
             ord(key[i]) + 26) % 26
        x += ord('A') 
        orig_text.append(chr(x)) 
    return("" . join(orig_text)) 

def ic(strng):
    x = []
    total = 0
    alphabet =['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
    for letter in alphabet:
        fi = strng.count(letter)
        total += 26*(fi*(fi-1))/((len(strng))*(len(strng)-1)) 
    return total

def columns(input,n=1):
    column={}
    for i in range(n):
        column[i] = input[i::n]
    return column

def letter_frequency(string):                              #calculates the relative frequency of letter in string
    somedict={}
    cipher_alphabet = []
    for letter in string:
        if letter not in cipher_alphabet:
            cipher_alphabet.append(letter)
        else:
            pass
    for letter in cipher_alphabet:
        count = string.count(letter)
        somedict.setdefault(letter, count/len(string))
    return somedict

def k_shift(string,k):                  #Basically the encryption algorithm, used to "shift" input string over potential k's
    shifted_string =[]
    for i in range(len(string)):
        x = (ord(string[i]) + ord(k))%26
        x += ord('A') 
        shifted_string.append(chr(x))
    return shifted_string

def chi_score(string):
    val = 0
    for letter in alphabet_list:
        if letter in letter_frequency(string):
            a = letter_frequency(string)[letter]
            b = alphabet_freq_dict[letter]
            val += a*b
        else:
            pass
    return val


def chi2(string):
    val = 0
    for letter in alphabet_list:
        if letter in letter_frequency(string):
            a = letter_frequency(string)[letter]
            b = alphabet_freq_dict[letter]
            val += ((a-b)**2)/(b**2)
            #print(letter,a,b,val)
        else:
            pass
    return val

def find_max_k(string):
    shifted = 0
    out1 =[]
    out2 =[]
    for j in alphabet_list:
        shifted = k_shift(string,j)
        score1 = chi_score(shifted)
        score2 = chi2(shifted)
        k = chr(ord('A')+(26 + ord('A')-ord(j))%26) #(k + j)%26 = A%26, calculate key of cipher.  
        out1.append((score1,k))
        out2.append((score2,k))
    return (max(out1),min(out2))



if __name__ == '__main__':

    alpha_freq = pd.read_csv('Alphabet_freq.txt')
    encrypted = open('Task_1_Encrypted_OLD.txt', 'r').read()

    key = generateKey(encrypted, 'BDLAEKCY') 
    enc = encrypted.replace(" ", "")

    decrypted =decrypter(enc, key)
    print(decrypted)

    english_vector = alpha_freq.iloc[:,1].values #Vector of alphabet and frequency of letter in english text 

    ic_english = 0
    for i in english_vector:
        ic_english += 26*((i/100)**2)

    scores = []
    for i in range(1,10):
        col = columns(enc,i)
        score = ic(col[i-1])
        scores.append(score)
    
    col_8 = columns(enc,8)

    print(scores)
    alphabet_list =['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']

    alphabet_freq_dict ={}
    for i in range(0,26):
        alphabet_freq_dict.update({alpha_freq.iloc[i,0]:(alpha_freq.iloc[i,1])/100})
    #print(alphabet_freq_dict)


    for i in range(0,8):
         print(find_max_k(col_8[i]))
 
    
        #T?????RU