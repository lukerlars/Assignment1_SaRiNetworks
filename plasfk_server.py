from flask import Flask           
from sdes import tripledes_decode, bitlist_to_ascii
app = Flask(__name__)             

@app.route("/")                  
def hello():                      
    return "Hello World!"  

@app.route('/<ciphertext>')  
def out(ciphertext):
    bitlist = [int(bit) for bit in ciphertext]
    keys = [[1,1,1,1,1,0,1,0,1,0], [0,1,0,1,0,1,1,1,1,1]]
    out =''
    for i in range(0, len(bitlist), 8):
        out+= bitlist_to_ascii(tripledes_decode(bitlist[i:i+8], keys[0], keys[1]))
    return out

if __name__ == "__main__":        
    app.run()                     
    
    