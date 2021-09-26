import csv

with open('Most_common_words.txt') as file:
    reader = csv.reader(file, delimiter = '\n')
    common_words =[word[0].upper() for word in reader]


en_letter_freqs = {'A':8.2,'B':1.5,'C':2.8,'D':4.3,'E':13,'F':2.2,
'G':2,'H':6.1,'I':7,'J':0.15,'K':0.77,'L':4,'M':2.4,'N':6.7,
'O':7.5,'P':1.9,'Q':0.095,'R':6,'S':6.3,'T':9.1,'U':2.8,
'V':0.98,'W':2.4,'X':0.15,'Y':2,'Z':0.074}



def decipher(ciphertext, keyword):
    """Takes keyword and ciphertext, returns deciphered rawtext """
    ciphertext = ciphertext.replace(' ','')
    decrypted = ''
    for i in range(len(ciphertext)):
        keychar = keyword[i % len(keyword)]
        dec_ord =(ord(ciphertext[i])- ord(keychar))%26 + ord('A')
        decrypted += chr(dec_ord)
    return decrypted

def partition(rawtext, n):
    """Partitions every nth char in plaintext into nth bucket"""
    buckets = ['']*n
    for i in range(len(rawtext)):
        buckets[i % n] += rawtext[i]
    return buckets

def sample_freqs(rawtext):
    """Returns relative frequency of characters in text"""
    return{char: 100*(rawtext.count(char)/len(rawtext)) for char in rawtext}

def io_coincidence(freqdict):
    """Calculates expected index of coincidence
    https://en.wikipedia.org/wiki/Index_of_coincidence
    for dict of letters and frequencies"""
    
    ic = 0
    c = len(freqdict.keys()) #26 
    for freq in freqdict.values():
        ic += freq**2
    return c*(ic/10**4)


def key_length_analysis1(ciphertext, max_key_length):
    """Bucket ciphertext into n partitions, and calculates avg ic for all buckets.
    n which yields score closest to the ic score of english text is returned"""

    ic_english = io_coincidence(en_letter_freqs)
    length_scores=[]
    for n in range(1,max_key_length):
        buckets =partition(ciphertext, n)
        bucket_freqs = [sample_freqs(bc) for bc in buckets]
        length_scores.append(sum([io_coincidence(freq_ds) for freq_ds in bucket_freqs])/len(bucket_freqs))
    
    out_scores = [(ls-ic_english)**2 for ls in length_scores]

    return length_scores, f'Probable length of key is {1 +out_scores.index(min(out_scores))}'

def freq_dict_comparison(subject_dict,optimum_dict =en_letter_freqs):
    """Distance score between subject- and reference frequency dictionaries"""
    sub_freqs = [freq for freq in sorted(subject_dict.values(),reverse=True)]
    opt_freqs = [freq for freq in sorted(optimum_dict.values(),reverse=True)]
    score = 0
    for i in range(len(sub_freqs)):
        score += (opt_freqs[i]- sub_freqs[i])**2
    return score



def key_length_analysis2(ciphertext, max_key_length):
    """Buckets ciphertexts into n partitons, counts letter frequencies compares with english
    text frequencies and returns optimal n """
    
    length_scores=[]
    for n in range(1,max_key_length):
        buckets =partition(ciphertext, n)
        bucket_freqs = [sample_freqs(bc) for bc in buckets]
        length_scores.append(sum([freq_dict_comparison(bcd, en_letter_freqs) for bcd in bucket_freqs])/n)
    
    return length_scores, f'Probable length of key is {1 +length_scores.index(min(length_scores))}'



def e_decrypter(ciphertext, keylength):
    """Takes lenght of key, and ciphertext, returns likely key given that
    e is the most frequent letter in the decoded ciphertext """
    
    buckets =partition(ciphertext, keylength)
    bucket_freqs = [sample_freqs(bc) for bc in buckets]

    likely_an_e_dict ={}
    for i in range(keylength):
        val = sorted(bucket_freqs[i].items(), key= lambda x: x[1], reverse=True)[0]
        likely_an_e_dict[i] = val[0]
    
    keyword =[]
    for letter in likely_an_e_dict.values():
        e_diff = (ord('E') - ord(letter))%26
        keyword.append(chr((26 - e_diff)%26 + ord('A')))
    return ''.join(keyword)

def cword_decrypter(ciphertext,keylength,check_words =common_words):
    """Looks for common words in partially decrypted strings"""
    pass


def columnize(rawtext, n):
    """Returns text as string of n columns """
    list =[rawtext[i:i+n] for i in range(0,len(rawtext), n)]
    return '\n'.join(list)

def key_modifier(orig_key, ciphertext, suspected_word):
    """Modify key from almost decrypted words, Note: words must be same length as key"""
    assert len(orig_key) == len(ciphertext) == len(suspected_word)
    diffs = [ord(i) - ord(j) for i,j in zip(ciphertext,suspected_word)]
    
    new_key = [] 

    for keyletter, diff in zip(orig_key, diffs):
        key_diff = (ord(keyletter) - ord('A') + diff)%26
        new_key.append(chr(ord('A') + key_diff))
    return ''.join(new_key)



 


if __name__ =='__main__':
    keyword_old ='BDLAEKCY'

    ciphertext_new = 'FRRUU OIIYE AMIRN QLQVR BOKGK NSNQQ IUTTY IIYEA WIJTG LVILA ZWZKT ZCJQH IFNYI WQZXH RWZQW OHUTI KWNNQ YDLKA EOTUV XELMT SOSIX JSKPR BUXTI TBUXV BLNSX FJKNC HBLUK PDGUI IYEAM OJCXW FMJVM MAXYT XFLOL RRLAA JZAXT YYWFY NBIVH VYQIO SLPXH ZGYLH WGFSX LPSND UKVTR XPKSS VKOWM QKVCR TUUPR WQMWY XTYLQ XYYTR TJJGO OLMXV CPPSL KBSEI PMEGC RWZRI YDBGE BTMFP ZXVMF MGPVO OKZXX IGGFE SIBRX SEWTY OOOKS PKYFC ZIEYF DAXKG ARBIW KFWUA SLGLF NMIVH VVPTY IJNSX FJKNC HBLUK PDGUI IYEAM HVFDY CULJS EHHMX LRXBN OLVMR'
    ciphertext_old = 'BQZRMQ KLBOXE WCCEFL DKRYYL BVEHIZ NYJQEE BDYFJO PTLOEM EHOMIC UYHHTS GKNJFG EHIMK NIHCTI HVRIHA RSMGQT RQCSXX CSWTNK PTMNSW AMXVCY WEOGSR FFUEEB DKQLQZ WRKUCO FTPLOT GOJZRI XEPZSE ISXTCT WZRMXI RIHALE SPRFAE FVYORI HNITRG PUHITM CFCDLA HIBKLH RCDIMT WQWTOR DJCNDY YWMJCN HDUWOF DPUPNG BANULZ NGYPQU LEUXOV FFDCEE YHQUXO YOXQUO DDCVIR RPJCAT RAQVFS AWMJCN HTSOXQ UODDAG BANURR REZJGD VJSXOO MSDNIT RGPUHN HRSSSF VFSINH MSGPCM ZJCSLY GEWGQT DREASV FPXEAR IMLPZW EHQGMG WSEIXE GQKPRM XIBFWL IPCHYM OTNXYV FFDCEE YHASBA TEXCJZ VTSGBA NUDYAP IUGTLD WLKVRI HWACZG PTRYCE VNQCUP AOSPEU KPCSNG RIHLRI KUMGFC YTDQES DAHCKP BDUJPX KPYMBD IWDQEF WSEVKT CDDWLI NEPZSE OPYIW'
    
    ciphertext_old = ciphertext_old.replace(' ', '')
    ciphertext_new = ciphertext_new.replace(' ', '')

    testtring= 'This is a sentence that i will use to test a funtion which buckets characters in a string'

    ## Find length of keyword: 
    #print(key_length_analysis1(ciphertext_new, 11))
    #print(key_length_analysis2(ciphertext_new, 11))
    
    #Key length == 7

    print(ciphertext_new)
    
     
  



    



    

    
