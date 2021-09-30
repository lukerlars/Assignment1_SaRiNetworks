
# Implementation of SDES and Triple SDES---
# -----
# -----
#### Note on format: Use arrays of binary ints to denote bytes  eks: [1,0,1,0,0,0,1,1]

from tqdm import tqdm 

with open('ctx1.txt', 'r') as f:
    ctx1 = f.read()

with open('ctx2.txt', 'r') as f:
    ctx2 = f.read()


#S-boxes
s0 = [[1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]]

s1 = [[0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]]


#-----------------

def bitlist_to_num(bitlist):
    return int(''.join(str(x) for x in bitlist), base = 2)

def num_to_bitlist(number, size):
    return [int(bit) for bit in bin(number)[2:].zfill(size)]

#Permutation and shift functions

def p10(bitlist10):
    assert(len(bitlist10) == 10)
    order = [3, 5, 2, 7, 4, 10,1, 9, 8, 6]
    return[bitlist10[idx -1] for idx in order]

def p8(bitlist10):
    assert(len(bitlist10) == 10)
    order = [6, 3, 7, 4, 8, 5, 10, 9]
    return[bitlist10[idx -1] for idx in order]

def ip(bitlist8):
    assert(len(bitlist8)== 8)
    order =[2, 6, 3, 1, 4, 8, 5, 7]
    return[bitlist8[idx-1] for idx in order]

def ip_inv(bitlist8):
    assert(len(bitlist8) == 8)
    order =[4, 1, 3, 5, 7, 2 ,8, 6]
    return[bitlist8[idx-1] for idx in order]

def shift(bitlist5, step):
    """Left-shifts/rotates bitlist of 5 binary values"""
    assert(len(bitlist5)==5)
    return[bitlist5[(step + idx) %5] for idx in range(len(bitlist5))]

def exp_perm(bitlist4):
    """Expansion and permutation function. 
    input: bitlist with 4 entries
    out: bitllist of 8 entries  """
    order = [4,1,2,3,2,3,4,1]
    return[bitlist4[idx -1] for idx in order]

def switch(bitlist8):
    """Switch left half with right half in bitlist of length 8 """
    order =[4,5,6,7,0,1,2,3]
    return[bitlist8[idx] for idx in order]

#### Key generation
def get_subkeys(key):
    """Function that retrieves subkeys from key"""
    assert(len(key) == 10)
    key_p10 = p10(key)
    
    left_key_shift_1 = shift(key_p10[:5],1)
    right_key_shift_1 = shift(key_p10[5:],1)
    
    key1 = p8(left_key_shift_1 + right_key_shift_1)
    
    left_key_shift_2 = shift(left_key_shift_1, 2)
    right_key_shift_2 = shift(right_key_shift_1,2)
    key2 = p8(left_key_shift_2 + right_key_shift_2)
    
    return key1, key2



# The fk function
def fk(bitlist8, subkey):
    assert(len(bitlist8)== 8 and len(subkey)==8)
    l_bitlist4, r_bitlist4 = bitlist8[:4], bitlist8[4:]

    expp = exp_perm(r_bitlist4)
    k1_xor = [n^k for n,k in zip(expp, subkey)]

    s0_row_idx, s0_col_idx = bitlist_to_num([k1_xor[0],k1_xor[3]]), bitlist_to_num([k1_xor[1], k1_xor[2]]) 
    s1_row_idx, s1_col_idx = bitlist_to_num([k1_xor[4],k1_xor[7]]), bitlist_to_num([k1_xor[5], k1_xor[6]])

    s0_out = num_to_bitlist(s0[s0_row_idx][s0_col_idx],2)
    s1_out = num_to_bitlist(s1[s1_row_idx][s1_col_idx],2)

    s0s1 = s0_out + s1_out
    p4 =[s0s1[1], s0s1[3],s0s1[2],s0s1[0]]

    return [n^k for n,k in zip(l_bitlist4, p4)] + r_bitlist4


#### SDES ----------------Encryption and decryption functions -------------

def des_encrypt(plain_bitlist, key):
    subkey1, subkey2 = get_subkeys(key)
    return ip_inv(fk(switch(fk(ip(plain_bitlist),subkey1)) ,subkey2))

def des_decrypt(cipher_bitlist, key):
    subkey1, subkey2 = get_subkeys(key)
    return ip_inv(fk(switch(fk(ip(cipher_bitlist),subkey2)) ,subkey1))

#### ---------------------- Triple des -------------------------------------

def tripledes_encode(plainbits, key1, key2):
    return(des_encrypt(des_decrypt(des_encrypt(plainbits,key1),key2),key1))

def tripledes_decode(cipherbits, key1, key2):
    return(des_decrypt(des_encrypt(des_decrypt(cipherbits,key1),key2),key1))


 ###### Tables for encryption and decryption tasks  
## Testcase --------------------------------------------------------------

testcases = [[[0,0,0,0,0,0,0,0,0,0], [1,0,1,0,1,0,1,0], [0,0,0,1,0,0,0,1]],
    [[1,1,1,0,0,0,1,1,1,0], [1,0,1,0,1,0,1,0],[1,1,0,0,1,0,1,0]],
    [[1,1,1,0,0,0,1,1,1,0], [0,1,0,1,0,1,0,1], [0,1,1,1,0,0,0,0]],
    [[1,1,1,1,1,1,1,1,1,1], [1,0,1,0,1,0,1,0], [0,0,0,0,0,1,0,0]]]

## Task 1 -----------------------------------------------------------------
task1_encryption_table = [[[0,0,0,0,0,0,0,0,0,0], [0,0,0,0,0,0,0,0]], 
[[0,0,0,0,0,1,1,1,1,1], [1,1,1,1,1,1,1,1]],
[[0,0,1,0,0,1,1,1,1,1], [1,1,1,1,1,1,0,0]], 
[[0,0,1,0,0,1,1,1,1,1], [1,0,1,0,0,1,0,1]]]

task1_decryption_table = [[[1,1,1,1,1,1,1,1,1,1],[0,0,0,0,1,1,1,1]],
[[0,0,0,0,0,1,1,1,1,1],  [0,1,0,0,0,0,1,1]],
[[1,0,0,0,1,0,1,1,1,0],  [0,0,0,1,1,1,0,0]],
[[1,0,0,0,1,0,1,1,1,0],  [1,1,0,0,0,0,1,0]]]

## Task 2 ---------------------------------------

task2_encryption_table = [[[1,0,0,0,1,0,1,1,1,0], [0,1,1,0,1,0,1,1,1,0], [1,1,0,1,0,1,1,1,]], 
[[1,0,0,0,1,0,1,1,1,0], [0,1,1,0,1,0,1,1,1,0], [1,0,1,0,1,0,1,0]],
[[1,1,1,1,1,1,1,1,1,1], [1,1,1,1,1,1,1,1,1,1], [0,0,0,0,0,0,0,0]], 
[[0,0,0,0,0,0,0,0,0,0], [0,0,0,0,0,0,0,0,0,0], [0,1,0,1,0,0,1,0,]]] 

task2_decryption_table =[[[1,0,0,0,1,0,1,1,1,0], [0,1,1,0,1,0,1,1,1,0],  [1,1,1,0,0,1,1,0]],
[[1,0,1,1,1,0,1,1,1,1], [0,1,1,0,1,0,1,1,1,0],  [0,1,0,1,0,0,0,0]],
[[1,1,1,1,1,1,1,1,1,1], [1,1,1,1,1,1,1,1,1,1],  [0,0,0,0,0,1,0,0]],
[[0,0,0,0,0,0,0,0,0,0], [0,0,0,0,0,0,0,0,0,0],  [1,1,1,1,0,0,0,0]]]

#### -----------------------Top execution functions-------------

def task1_encryption(table):
    return([des_encrypt(case[1],case[0])for case in table])

def task1_decryption(table):
    return([des_decrypt(case[1],case[0]) for case in table])

def task2_encryption(table):
    return([tripledes_encode(case[2], case[0], case[1])for case in table])

def task2_decryption(table):
    return([tripledes_decode(case[2], case[0], case[1])for case in table])


### Task 3 tools
def bitlist_to_ascii(bitlist8):
    return chr(int( ''.join(str(bit) for bit in bitlist8),2))


ctx1_bitlist = [int(bit) for bit in ctx1] 
ctx1_bitlist = [ctx1_bitlist[n:(n+8)] for n in range(0, len(ctx1_bitlist),8)]

ctx2_bitlist = [int(bit) for bit in ctx2] 
ctx2_bitlist = [ctx2_bitlist[n:(n+8)] for n in range(0, len(ctx2_bitlist),8)]

def bruteforce_des(ctx_bitlist, searchword):
    for key in tqdm(range(1024)):
        plaintext =''
        key =[int(bit) for bit in bin(key)[2:].zfill(10)]
        for bitslist in ctx_bitlist:
            char = bitlist_to_ascii(des_decrypt(bitslist, key))
            plaintext += char
        if plaintext.find(searchword) != -1:
            return plaintext, key
    return 'Did not work'


def bruteforce_tripledes(ctx_bitlist, searchword):
    for key in tqdm(range(1024**2-1,0, -1)):
        key = [int(bit) for bit in bin(key)[2:].zfill(20)]
        key1 = key[:10]
        key2 = key[10:]
        plaintext =''
        for bitlist in ctx_bitlist:
            char = bitlist_to_ascii(tripledes_decode(bitlist, key1, key2))
            plaintext += char
        if plaintext.find(searchword) != -1:
            return plaintext, key1, key2
    return 'Did not work'


if __name__ =='__main__':
    
    print('Solving task 1 \n')
    print('Task 1 encrypted bits\n')
    print(task1_encryption(task1_encryption_table))
    print('\n')
    print('task 1 decrypted bits \n')
    print(task1_decryption(task1_decryption_table))
    print('\n')
    print('task 2 encrypted bits ')
    print(task2_encryption(task2_encryption_table))
    print('\n')
    print('task 2 decrypted bits \n')
    print(task2_decryption(task2_decryption_table))

    attempt, key = bruteforce_des(ctx1_bitlist, searchword= 'des')
    print(attempt, key)

    print('\n Answerkey bruteforce des = [1, 1, 1, 1, 1, 0, 1, 0, 1, 0]')
    print(bruteforce_des(ctx1_bitlist, 'des'))


    #attempt2, key1, key2 = bruteforce_tripledes(ctx2_bitlist,searchword= 'des')
    #print(attempt2, key1, key2)

    print('\n Answerkeys bruteforce tripledes =[[1,1,1,1,1,0,1,0,1,0], [0,1,0,1,0,1,1,1,1,1]]' )

    
    
    

    
    


    
    

