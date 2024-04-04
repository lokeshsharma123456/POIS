import sys
sys.path.append('../')
from PRF.PRF import PRF


class CBC_MAC:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int, keys: list[int]):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        self.n = int(security_parameter)
        self.p = int(prime_field)
        self.g = int(generator)
        self.expansion_factor = int(expansion_factor)
        self.k1 = int(keys[0])
        self.k2 = int(keys[1])
        self.prf1 = PRF( self.n, self.g , self.p,  self.k1)
        self.prf2 = PRF( self.n, self.g , self.p,  self.k2)
        pass

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: m (with length l(n).n)
        :type message: str
        """
        mes_len = self.n 
        # print(mes_len)
        ##padding for last block
        while(len(message) % mes_len != 0):
            message = message + '0'
            
        m_blocks = len(message) // mes_len
        tag = 0
        for i in range(1,m_blocks+1,1):
            block = message[(i-1)*mes_len : (i)*mes_len]
            # print(block , tag)
            block_int = int(block, 2) ^ tag
            tag = self.prf1.evaluate(block_int) 
        tag = self.prf2.evaluate(tag)
        return  tag
        pass

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        mes_len = self.n 
        # print(mes_len)
        ##padding for last block
        while(len(message) % mes_len != 0):
            message = message + '0'
            
        m_blocks = len(message) // mes_len
        ctr = 0
        for i in range(1,m_blocks+1,1):
            block = message[(i-1)*mes_len : (i)*mes_len]
            # print(block , tag)
            block_int = int(block, 2) ^ ctr
            ctr = self.prf1.evaluate(block_int) 
        ctr = self.prf2.evaluate(ctr)
        return  tag == ctr
        pass


# import csv

# with open('cbc_mac.csv') as file_obj:
#     heading = next(file_obj)
#     reader_obj = csv.reader(file_obj)
#     ciphers = []
#     messages = []
#     for row in reader_obj:
#         keys = list()
#         keys.append(row[3])
#         keys.append(row[4])
#         cbc_mac = CBC_MAC(security_parameter=row[0], generator=row[1], prime_field=row[2],expansion_factor= 2 * int(row[0]),keys=keys)
#         MAC_tag = cbc_mac.mac(message = row[5])
#         print(MAC_tag)
#         print(cbc_mac.vrfy(message=row[5], tag = int(MAC_tag)))
#         # exit()
