
# Five functions:
# IP inital permuation, Fk a complex function (invovlves both permuation and substitution),
# SW simple permutation taht switches two havles of the data, aFk again, and then ivnerse 
# of the intital permuataion. 

# as composition of functions: ciphertext = IP^-1 Fk2 SW fk1 IP (plaintext)
# where k1 = P8(shift(P10(key)))
# k2 = P8(shift(shift(P10(key))))

from multiprocessing import Array


with open('ctx1.txt', 'r') as f:
    ctx1 = f.read()

with open('ctx2.txt', 'r') as f:
    ctx2 = f.read()



#### Note on format: Use arrays of binary ints to denote bytes  eks: [1,0,1,0,0,0,1,1]

#S-boxes
s0 = [[1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]]

s1 = [[0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]]

def bitlist_to_num(bitlist):
    return int(''.join(str(x) for x in bitlist),base = 2)

def num_to_bitlist(number, size):
    [int(bit) for bit in bin(number)[2:].zfill(size)]

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

#### Key generation
def get_subkeys(key):
    """Function that retrieves subkeys from key"""
    assert(len(key) == 10)
    key_p10 = p10(key)
    
    left_key_shift_1 = shift(key_p10[:5],1)
    right_key_shift_1 = shift(key_p10[:5],1)
    key1 = p8(left_key_shift_1 + right_key_shift_1)
    
    left_key_shift_2 = shift(left_key_shift_1, 2)
    right_key_shift_2 = shift(right_key_shift_1,2)
    key2 = p8(left_key_shift_1 + left_key_shift_2)
    
    return key1, key2



# The fk function
def mapping_F(bitlist4, key):
    assert(len(bitlist4)== 4)

    key1,key2 = get_subkeys(key)

    expp = exp_perm(bitlist4)
    k1_xor = [n^k for n,k in zip(expp, key1)]

    s0_row_idx, s0_col_idx = bitlist_to_num(k1_xor[0]+k1_xor[3]), bitlist_to_num(k1_xor[2] + k1_xor[3]) 
    s1_row_idx, s1_col_idx = bitlist_to_num(k1_xor[4]+k1_xor[7]), bitlist_to_num(k1_xor[5] + k1_xor[6])

    s0_out = s0[s0_row_idx][s0_col_idx]
    s1_out = s1[s1_row_idx][s1_col_idx]




def fk(l_bitlist4, r_bitlist4, key):
    pass
    





if __name__ =='__main__':
    test_10 = [1,0,0,0,1,1,1,0,1,0]
    test_8 = [1,0,0,0,1,1,1,0]
    test_5=[0,1,1,0,0]

    num = 8
    format_string = str(num) +':0' + str(num) +'b'
    
   