import sys
sys.path.append('../')
from PRF.PRF import PRF

class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int, mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key: k
        :type key: int
        :param mode: Block-Cipher mode of operation
            - CTR
            - OFB
            - CBC
        :type mode: str
        """
        
        self.n = int(security_parameter)
        self.p = int(prime_field)
        self.g = int(generator)
        self.key = int(key)
        self.prf = PRF( self.n, self.g , self.p, self.key)
        pass

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack using randomized ctr mode
        :param message: m
        :type message: int
        :param random_seed: ctr
        :type random_seed: int
        """
        # message = bin(message)[2:]
        m_blocks = len(message) // self.n
        ctr = bin(random_seed)[2:].zfill(self.n)
        for i in range(m_blocks):
            random_seed = random_seed + 1
            prf_fun = self.prf.evaluate(random_seed)
            block = message[(i)*self.n : (i+1)*self.n]
            c = int(block,2) ^ prf_fun
            ctr += bin(c)[2:].zfill(self.n)
        return ctr
        pass
     

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        cipher_len = len(cipher)
        ##removing initial random seed
        
        #first block of random seed is of len n
        rndm_seed = cipher[:self.n ]
        required_cipher = cipher[self.n :]
        
        message = ""
        
        random_seed = int(rndm_seed , 2)
        m_blocks = len(required_cipher) // self.n
        for i in range(m_blocks):
            random_seed = random_seed + 1
            prf_fun = self.prf.evaluate(random_seed)
            block = required_cipher[(i)*self.n : (i+1)*self.n]
            c = int(block,2) ^ prf_fun
            message += bin(c)[2:].zfill(self.n)
        return message
        
        
        pass

# import csv

# with open('cpa.csv') as file_obj:
#     heading = next(file_obj)
#     reader_obj = csv.reader(file_obj)
#     ciphers = []
#     messages = []
#     for row in reader_obj:
#         cpa = CPA(security_parameter=row[0], prime_field=row[1], generator=row[2],key= row[3])
#         ciphertext = cpa.enc(message = row[4], random_seed=int(row[5]))
#         ciphers.append(ciphertext)
#         print(ciphertext)
#         # exit(0)
#         mes = cpa.dec(ciphertext)
#         messages.append(mes)
#         print(mes)
#         print(row[4])
        
    # print("\nget back to message :")
    # for i in range(len(ciphers)):
    #     print(ciphers[i])
    #     print(messages[i])
        # print()
    