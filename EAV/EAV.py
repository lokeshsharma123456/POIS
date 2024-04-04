import sys
sys.path.append('../')
from PRG.PRG import PRG

class Eavesdrop:
    def __init__(self, security_parameter: int, key: int, expansion_factor: int,
                 generator: int, prime_field: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param key: k, uniformly sampled key
        :type key: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        """
        self.n = int(security_parameter)
        self.g = int(generator)
        self.p = int(prime_field)
        self.key = int(key)
        self.output_length = int(expansion_factor)
        self.prg = PRG(security_parameter, generator, prime_field, expansion_factor)
        
        pass

    def enc(self, message: str) -> str:
        """
        Encrypt Message against Eavesdropper Adversary
        :param message: message encoded as bit-string
        :type message: str
        """
        # c := G(k) ⊕ m.
        gen_key = self.prg.generate(self.key)
        # print('key', gen_key)
        # print('msg',message)
        c=''
        for i in range(len(gen_key)):
            c += str(int(gen_key[i]) ^ int(message[i]))
        return c    
        pass
    
    

    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        """
        gen_key = self.prg.generate(self.key)
        m=''
        for i in range(len(gen_key)):
            m += str(int(gen_key[i]) ^ int(cipher[i]))
        return m
        pass


# import csv

# with open('eav.csv') as file_obj:
#     heading = next(file_obj)
#     reader_obj = csv.reader(file_obj)
#     ciphers = []
#     messages = []
#     for row in reader_obj:
#         eav = Eavesdrop(security_parameter=row[0], key=row[1], expansion_factor=row[2],generator= row[3],prime_field=row[4])
#         ciphertext = eav.enc(message = row[5])
#         ciphers.append(ciphertext)
#         # exit(0)
#         mes = eav.dec(ciphertext)
#         messages.append(mes)
        
#     print("\nget back to message :")
#     for i in range(len(ciphers)):
#         print(ciphers[i])
#         print(messages[i])
#         print()
        # print(message)
    