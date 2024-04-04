import sys
sys.path.append('../')
from PRF.PRF import PRF


class MAC:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int,
                 seed: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param seed: k
        :type seed: int
        """
        self.n = int(security_parameter)
        self.p = int(prime_field)
        self.g = int(generator)
        self.seed = int(seed)
        self.prf = PRF( self.n, self.g , self.p, 2*self.n )
        self.mes_len = (self.n // 4)
        
        pass

    def mac(self, message: str, random_identifier: int) -> int:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        """
        mes_len = self.mes_len
        # print(mes_len)
        ##padding for last block
        while(len(message) % mes_len != 0):
            message = message + '0'
        
        #d blocks each of len = n/4
        d_blocks = len(message) // mes_len
        
        # print("num of dblocks",d_blocks)
       
        rndm_id = bin(random_identifier)[2:].zfill(mes_len)
        tag = rndm_id
        # print("enc rndm:",rndm_id)
        # print(rndm_id)
        # print(message)
        for i in range(1,d_blocks+1,1):
            block = message[(i-1)*mes_len : (i)*mes_len]
            # print(block)
            i_bin = bin(i)[2:].zfill(mes_len)
            d_blocks_bin = bin(d_blocks)[2:].zfill(mes_len)
            seed = rndm_id+d_blocks_bin+i_bin+block
            seed_int = int(seed,2)
            t = self.prf.evaluate(seed_int)
            # print(t)
            tag += bin(t)[2:].zfill(self.n)
        return tag
        
        pass

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        mes_len = self.mes_len
        d_blocks = len(message) // mes_len
        
        while(len(message) % mes_len != 0):
            message = message + '0'
        
        ##random bit findout
        tag_bin = bin(tag)[2:]
        # print("verify_mac", tag_bin)
        tag_len = len(tag_bin)
        req_part = tag_len - d_blocks* self.n
        rndm_id = tag_bin[:req_part].zfill(mes_len)
        # print("vrfrndm:",rndm_id)
        
        #-------------------------------------
        # print(rndm_id)
        computed_tag = rndm_id
        for i in range(1,d_blocks+1,1):
            block = message[(i-1)*mes_len : (i)*mes_len]
            # print(block)
            i_bin = bin(i)[2:].zfill(mes_len)
            d_blocks_bin = bin(d_blocks)[2:].zfill(mes_len)
            seed = rndm_id+d_blocks_bin+i_bin+block
            seed_int = int(seed,2)
            t = self.prf.evaluate(seed_int)
            # print(t)
            computed_tag += bin(t)[2:].zfill(self.n)
        # print(computed_tag)
        return int(computed_tag,2) == tag
        
        pass
    
    


# import csv

# with open('mac.csv') as file_obj:
#     heading = next(file_obj)
#     reader_obj = csv.reader(file_obj)
#     ciphers = []
#     messages = []
#     for row in reader_obj:
#         sec_mac = MAC(security_parameter=row[0], prime_field=row[1], generator=row[2],seed= row[3])
#         tagi = sec_mac.mac(message = row[4], random_identifier=int(row[5]))
#         ciphers.append(tagi)
#         print(tagi)
#         print(sec_mac.vrfy(message=row[4], tag = int(tagi,2)))
#         # exit()