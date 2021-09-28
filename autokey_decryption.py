import re
import csv

with open('Most_common_words.txt') as file:
    reader = csv.reader(file, delimiter = '\n')
    common_words =[word[0].upper() for word in reader]





## -----------------------------------------------------------

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

def word_looping(ciphertext, keyword):
    """ """
    decrypts =[]
    kw_variants = []
    for i in range(len(keyword)):
        dec = vigenere_decode(ciphertext, keyword)
        decrypts.append(dec)
        kw_variants.append(keyword)
        keyword = rotate(keyword)
    return decrypts, kw_variants
  
def vocab_search(ciphertext, keyword, searc_vocab = common_words):
    if keyword in searc_vocab:
        search_words = searc_vocab
    else:
        search_words = searc_vocab +[keyword]
    
    decrypts, sw_variants = word_looping(ciphertext, keyword)
    reg_search = [[re.search(word, dec) for word in search_words] for dec in decrypts ]   
    
    matches ={}
    count = 0
    for search in reg_search:
        if any(search):
            matches[sw_variants[count]]= [sc for sc in search if sc != None]
        count+=1
    return matches


def key_forcing(ciphertext, suggestions):
    """Process for finding key, takes in ciphertext and suggestion for word in 
    plaintext of the format dict[permuted 'word'] = array(matchobjects)
    yields ..."""

    searches = {}
    for sg_word in suggestions.keys():
        match_objs_list = suggestions[sg_word]
        for mtc in match_objs_list:
            prev_decode = vigenere_decode(ciphertext, sg_word)[mtc.span()[0]: mtc.span()[1]]
            next_decode = vigenere_decode(ciphertext, mtc.group())[mtc.span()[1] : mtc.span()[1] +20]
            searches[sg_word + '->' + mtc.group()] = prev_decode +next_decode

    return searches



class Autokey_cryptanalysis: 

    def __init__(self, ciphertext):
        self.ciphertext = ciphertext
        self.plaintext = '-'*len(ciphertext)
        self.keystream = '-'*len(ciphertext)

    def plaintext_reset(self):
        self.plaintext = '-'*len(ciphertext)
    def keystream_reset(self):
        self.keystream = '-'*len(ciphertext)

    def plaintext_update(self):
        self.plaintext = ''
        for i in range(len(self.keystream)):
            if self.keystream[i] != '-':
                dec_ord =chr((ord(self.ciphertext[i])- ord(self.keystream[i]))%26 + ord('A'))
            else:
                dec_ord = '-'
            self.plaintext += dec_ord
        
    def keystream_generate_loop(self, keyword, offset = 0):
        for _ in range(offset):
            keyword = rotate(keyword)
        self.keystream = keyword*(len(self.ciphertext)//len(keyword)) + keyword[:len(self.keystream)%len(keyword)]
    

    def keystream_insert(self, gram, position):
        """Update keystream with letters 
        in the right position (posiotion: (idx_start, idx_end)) """ 
        self.keystream = self.keystream[:position[0]] + gram + self.keystream[position[1]:]



    def unfolding(self, gram, gram_pos, offset):
        #self.keystream = '-'*len(self.ciphertext)
        self.keystream_insert(gram, gram_pos)
        #self.plaintext_update()

        right_len = len(self.ciphertext[gram_pos[0]:])
        left_len = len(self.ciphertext[:gram_pos[0]])

        next_r_gram = next_l_gram = gram

        for i in range(0, right_len, offset):
            next_r_gram = vigenere_decode(self.ciphertext[gram_pos[0] + i : gram_pos[1] + i], next_r_gram)
            self.keystream_insert(next_r_gram, (gram_pos[0]+i + offset, gram_pos[1]+ i+ offset))
            self.keystream = self.keystream[:len(self.ciphertext)]
        

        for i in range(0, left_len-offset, offset):
            next_l_gram = vigenere_decode(self.ciphertext[gram_pos[0] -i -offset :gram_pos[1] - i-offset], next_l_gram)
            self.keystream_insert(next_l_gram, (gram_pos[0]- i -offset, gram_pos[1]-i- offset))
        
        
        self.plaintext_update()
        

    def disp(self,width = 100):
        for i in range(0,len(self.ciphertext), width):
            print(f'\n {self.ciphertext[i: i+ width]} \n {self.keystream[i:i+width]}\n {self.plaintext[i: i +width]}')
        
        
            



if __name__ == '__main__':
    ciphertext= 'FRRUU OIIYE AMIRN QLQVR BOKGK NSNQQ IUTTY IIYEA WIJTG LVILA ZWZKT ZCJQH IFNYI WQZXH RWZQW OHUTI KWNNQ YDLKA EOTUV XELMT SOSIX JSKPR BUXTI TBUXV BLNSX FJKNC HBLUK PDGUI IYEAM OJCXW FMJVM MAXYT XFLOL RRLAA JZAXT YYWFY NBIVH VYQIO SLPXH ZGYLH WGFSX LPSND UKVTR XPKSS VKOWM QKVCR TUUPR WQMWY XTYLQ XYYTR TJJGO OLMXV CPPSL KBSEI PMEGC RWZRI YDBGE BTMFP ZXVMF MGPVO OKZXX IGGFE SIBRX SEWTY OOOKS PKYFC ZIEYF DAXKG ARBIW KFWUA SLGLF NMIVH VVPTY IJNSX FJKNC HBLUK PDGUI IYEAM HVFDY CULJS EHHMX LRXBN OLVMR'
    ciphertext = ciphertext.replace(' ','')

    ciphertext_task3 = 'IRKZV  ONZPY  UAQZL  ULCDI OEVWF ETBAW SHLGOYQSXT UQRRK LRQUT  FHUSE  ZBFPR BEPHY DYEKFZSPPT  VYQSY GKUHJ GNHXN UMWFF XIZFN  NLWTJCKYHZ YDPDX KCOUO JEOMU AKVAU EGUEX RKHFCSNHGG WRABW RASXJ  IFJHO  JRLLJ  KOQLO  UQRITYHVFV GZGRM TLRQJ  ZGNNP  NYJAE  DFLQI  SLYSVRVKLE  AJUNL MHDGE  IFFQN  FKEKT NJGQN OPOXMVVRRC JGHEH  FEVGB  QDAEI  FDHTA AWFYG ZLLVOAUXFV JRPGV DYOYK BFMQA TWFMS WUQEB PQHXCWWEUP LGSGL NYMTM RXOWK FZFOE  FUBFG  QFNVIOVLHZ  NETBS  AIBBT  PEIHQ  DRTAU EGUEX RKHFCSNHGG PDDHY OBGOV CJBXG  DVEIZ  LWMJS'
    ciphertext_task3 = ciphertext_task3.replace(' ','')
    
    common_quadrigrams = ['THAT', 'THER', 'WITH', 'TION', 'HERE', 'OULD', 'IGHT', 'HAVE', 'HICH', 'WHIC', 'THIS', 'THIN', 'THEY', 'ATIO', 'EVER', 'FROM', 'OUGH', 'WERE', 'HING', 'MENT']

    # suggestions =[]
    # for word in common_words:
    #      search = vocab_search(ciphertext, word, searc_vocab=common_words)
    #      if len(search) != 0:
    #          suggestions.append(search)
    
    
    # for sug in suggestions:
    #     print(sug,key_forcing(ciphertext, sug))
    

    
    diff = 6
    inst = Autokey_cryptanalysis(ciphertext)
    inst.unfolding('HET',(69, 72), diff)
    inst.plaintext_update()
    inst.unfolding('OGR', (re.search('YPT', inst.keystream).span()[0]+ 3,re.search('YPT', inst.keystream).span()[1]+3), diff)    
    inst.disp()
    
    #print(vigenere_decode('FRRUUO', 'CRYPTO'))
    ### KEY = DATFBA

    #print(autokey_decode(ciphertext, 'DATFBA'))
    #print(autokey_decode(ciphertext_task3, 'DATFBA'))


    
    
    
    
    
    

    
