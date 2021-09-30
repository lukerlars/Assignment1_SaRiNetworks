import csv
from tqdm import tqdm
import re


with open('Most_common_words.txt') as file:
    reader = csv.reader(file, delimiter = '\n')
    common_words =[word[0].upper() for word in reader]

with open('trigram_from_text.txt', encoding='UTF8') as f:
    reader = csv.reader(f)
    common_trigrams = [gram for gram in reader][0]


ciphertext= 'FRRUU OIIYE AMIRN QLQVR BOKGK NSNQQ IUTTY IIYEA WIJTG LVILA ZWZKT ZCJQH IFNYI WQZXH RWZQW OHUTI KWNNQ YDLKA EOTUV XELMT SOSIX JSKPR BUXTI TBUXV BLNSX FJKNC HBLUK PDGUI IYEAM OJCXW FMJVM MAXYT XFLOL RRLAA JZAXT YYWFY NBIVH VYQIO SLPXH ZGYLH WGFSX LPSND UKVTR XPKSS VKOWM QKVCR TUUPR WQMWY XTYLQ XYYTR TJJGO OLMXV CPPSL KBSEI PMEGC RWZRI YDBGE BTMFP ZXVMF MGPVO OKZXX IGGFE SIBRX SEWTY OOOKS PKYFC ZIEYF DAXKG ARBIW KFWUA SLGLF NMIVH VVPTY IJNSX FJKNC HBLUK PDGUI IYEAM HVFDY CULJS EHHMX LRXBN OLVMR'
ciphertext = ciphertext.replace(' ','')


ciphertext_task3 = 'IRKZV  ONZPY  UAQZL  ULCDI OEVWF ETBAW SHLGOYQSXT UQRRK LRQUT  FHUSE  ZBFPR BEPHY DYEKFZSPPT  VYQSY GKUHJ GNHXN UMWFF XIZFN  NLWTJCKYHZ YDPDX KCOUO JEOMU AKVAU EGUEX RKHFCSNHGG WRABW RASXJ  IFJHO  JRLLJ  KOQLO  UQRITYHVFV GZGRM TLRQJ  ZGNNP  NYJAE  DFLQI  SLYSVRVKLE  AJUNL MHDGE  IFFQN  FKEKT NJGQN OPOXMVVRRC JGHEH  FEVGB  QDAEI  FDHTA AWFYG ZLLVOAUXFV JRPGV DYOYK BFMQA TWFMS WUQEB PQHXCWWEUP LGSGL NYMTM RXOWK FZFOE  FUBFG  QFNVIOVLHZ  NETBS  AIBBT  PEIHQ  DRTAU EGUEX RKHFCSNHGG PDDHY OBGOV CJBXG  DVEIZ  LWMJS'
ciphertext_task3 = ciphertext_task3.replace(' ','')


#-------------- Decoding tools -------------------------------

def vigenere_decode(ciphertext, keyword):
    """Takes keyword and ciphertext, returns deciphered rawtext """
    ciphertext = ciphertext.replace(' ','')
    decrypted = ''
    for i in range(len(ciphertext)):
        keychar = keyword[i % len(keyword)]
        dec_ord =(ord(ciphertext[i])- ord(keychar))%26 + ord('A')
        decrypted += chr(dec_ord)
    return decrypted

def autokey_decode(ciphertext, keyword):
    plaintext = ''
    key = keyword
    for i in range(0, len(ciphertext),len(keyword)):
        plaintext += vigenere_decode(ciphertext[i:i+len(keyword)],key[-len(keyword):])
        key += plaintext
    return plaintext


def rotate(word):
    return ''.join([w for w in (word[-1] + word[:(len(word)-1)])])



class Autokey_cryptanalysis: 
    def __init__(self, ciphertext, double = False):
        self.ciphertext = ciphertext
        self.plaintext = '-'*len(ciphertext)
        self.keystream = '-'*len(ciphertext)
        
        self.matches = {}        

    def plaintext_update(self):
        """Updates the plaintext field from changes to keystream field """
        plaintext = ''
        for i in range(len(self.keystream)):
            if self.keystream[i] != '-':
                dec_ord =chr((ord(self.ciphertext[i])- ord(self.keystream[i]))%26 + ord('A'))
            else:
                dec_ord = '-'
            plaintext += dec_ord
        self.plaintext = plaintext
        

    def keystream_insert(self, gram, position):
        """Update keystream with letters 
        in the right position (posiotion: (idx_start, idx_end)) """ 
        self.keystream = self.keystream[:position[0]] + gram + self.keystream[position[1]:]
    
    def keystream_get_loc(self, gram):
        return re.search(gram, self.keystream).span()
    
    def keyword_searching(self, searchword, vocab = common_words):
        """Running window decoding of searchword over ciphertext,
        if decode yields a likely n-gram, then runs again with the decoded  word,
        ïf this yields a likely n-gram then store original keyword, position and distance to next keyword."""
        key_len =0
        pos = 0
        for i in range(len(self.ciphertext)):
            dec = vigenere_decode(self.ciphertext[i:i+len(searchword)], searchword)
            if dec in vocab:
                for j in range(i+1, len(self.ciphertext)):
                    next_dec = vigenere_decode(self.ciphertext[j:j+len(searchword)],dec)
                    if next_dec in vocab:
                        key_len = j-i
                        pos = i
                        if searchword in self.matches.keys():  # Keeping search which minimizes key length
                            val = sorted([self.matches[searchword],((pos, pos+len(searchword)), key_len)], key = lambda x: x[1])[0]
                            self.matches[searchword] = val
                        else:
                            self.matches[searchword]= ((pos, pos+len(searchword)), key_len)

    def get_keystream_suggestion(self, vocab1 = common_words, vocab2= common_words):
        """Keyword searching for keywords in vocab """
        for gram in tqdm(vocab1):
            self.keyword_searching(gram, vocab2)
    


    def unfolding(self, gram, gram_loc, offset):
        """Places ngram suggestion at specified position in the keystream,
        decodes every ngram  m offsets away in both direcitons """
        
        self.keystream_insert(gram, gram_loc)
        
        right_len = len(self.ciphertext[gram_loc[0]:])
        left_len = len(self.ciphertext[:gram_loc[0]])

        next_r_gram = next_l_gram = gram

        for i in range(0, right_len, offset):
            next_r_gram = vigenere_decode(self.ciphertext[gram_loc[0] + i : gram_loc[1] + i], next_r_gram)
            self.keystream_insert(next_r_gram, (gram_loc[0]+i + offset, gram_loc[1]+ i+ offset))
            self.keystream = self.keystream[:len(self.ciphertext)]
        

        for i in range(0, left_len-offset, offset):
            next_l_gram = vigenere_decode(self.ciphertext[gram_loc[0] -i -offset :gram_loc[1] - i-offset], next_l_gram)
            self.keystream_insert(next_l_gram, (gram_loc[0]- i -offset, gram_loc[1]-i- offset))
        
        self.plaintext_update()
        

    def disp(self,width = 100):
        for i in range(0,len(self.ciphertext), width):
            print(f'\n {self.ciphertext[i: i+ width]} \n {self.keystream[i:i+width]}\n {self.plaintext[i: i +width]}')
    


if __name__ == '__main__':


    inst = Autokey_cryptanalysis(ciphertext)
    
    print('The ciphertext is: \n' + ciphertext)
    print('\n We will first search for potential keywords, which decrypts ciphertext into likely strings\n')
    inst.get_keystream_suggestion(vocab1=common_trigrams[:50],vocab2=common_trigrams[:50])
    print(inst.matches)
    
    print('\n A suggestion is AND appearing at location (75,78) in the ciphertext\n we can insert this into a tabula and see what we get')

    inst.unfolding('AND',(75,78), 6)
    inst.plaintext_update()
    inst.disp()

    print('\n We can se the word cryptology appearing, lets add the remaining n-grams:\n')
    cip_loc = inst.keystream_get_loc('CIP')
    inst.unfolding('HER', (cip_loc[0]+ 3,cip_loc[1] +3), 6)    
    inst.disp()
    print('\n Implementation is a bit wonky, but we can find the keyword\n' )
    print('The keyword is: ' + vigenere_decode('FRRUUO', 'CRYPTO') + '\n')

    # KEY = DATFBA

    print('The decoded text is: \n')
    print(autokey_decode(ciphertext, 'DATFBA'))

    print('\n for task 3 we can decode the new plaintext with the same key: \n' )
    print(autokey_decode(ciphertext_task3, 'DATFBA'))
    print('\n we can see that this is the same ciphertext as in task 1 ')

  