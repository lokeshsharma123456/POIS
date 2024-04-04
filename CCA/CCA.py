import sys
sys.path.append('../')
from CPA.CPA import CPA
from CBC_MAC.CBC_MAC import CBC_MAC

class CCA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key_cpa: int, key_mac: list[int],
                 cpa_mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key_cpa: k1
        :type key_cpa: int
        :param key_mac: k2
        :type key_mac: list[int]
        :param cpa_mode: Block-Cipher mode of operation for CPA
            - CTR
            - OFB
            - CBC
        :type cpa_mode: str
        """
        self.n = int(security_parameter)
        self.p = int(prime_field)
        self.g = int(generator)
        self.key_cpa = int(key_cpa)
        self.key_mac = key_mac
        self.cpa = CPA( self.n, self.p , self.g,  self.key_cpa)
        self.cbc_mac = CBC_MAC( self.n, self.g , self.p, 2*self.n, self.key_mac)
        pass

    def enc(self, message: str, cpa_random_seed: int) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack
        :param message: m
        :type message: str
        :param cpa_random_seed: random seed for CPA encryption
        :type cpa_random_seed: int
        """
        # print(cpa_random_seed)
        c = self.cpa.enc(message, int(cpa_random_seed))
        # print(c)
        t = self.cbc_mac.mac(c)
        t = bin(t)[2:].zfill(self.n)
        # print(t)
        return c + t
        pass
    
    def vrfy(self,cipher:str) ->bool:
        cipher_len = len(cipher)
        c = cipher[:cipher_len - self.n]
        # print(c)
        
        t = cipher[cipher_len - self.n :]
        # print(t)
        return self.cbc_mac.vrfy(c, int(t,2))
        
        
        
    def dec(self, cipher: str) ->str:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str
        """
        vrfy = self.vrfy(cipher)
        if vrfy :
            mes = self.cpa.dec(cipher)
            return mes
        
        pass
    
    
    
    
    
    
# import csv

# with open('cca.csv') as file_obj:
#     heading = next(file_obj)
#     reader_obj = csv.reader(file_obj)
#     ciphers = []
#     messages = []
#     for row in reader_obj:
#         keys = list()
#         keys.append(row[3])
#         keys.append(row[4])
#         cca = CCA(security_parameter=row[0], prime_field=row[1], generator=row[2], key_cpa=row[3], key_mac=[row[4],row[5]])
#         cca_cipher = cca.enc(message=row[6], cpa_random_seed=row[7])
#         print(cca_cipher)
#         print(cca.dec(cca_cipher))
#         print()
        # exit()
