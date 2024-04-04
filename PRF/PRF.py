import sys
sys.path.append('../')

from PRG.PRG import PRG


class PRF:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, key: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.n = int(security_parameter)
        self.g = int(generator)
        self.p = int(prime_field)
        self.key = int(key)
        self.output_length = 2 * self.n
        self.prg = PRG(security_parameter=self.n, generator=self.g, prime_field=self.p, expansion_factor= self.output_length)
        
        pass
    
    
    def split_string(self,x):
        '''
        splits string into two equal parts
        '''
        mid = int(len(x)//2)
        first = x[:mid]
        last = x[mid:]
        return first, last
    
    
    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        seed = self.key
        mess_x = bin(x)[2:].zfill(self.n)
        
        for i in range(len(mess_x)):
            res = self.prg.generate(seed)
            if  int(mess_x[i]) == 0:
                seed = int(res[0:self.output_length//2],2)
            else:
                seed = int(res[self.output_length//2:],2)
        return seed
        pass




# import csv

# with open('prf.csv') as file_obj:
#     heading = next(file_obj)
#     reader_obj = csv.reader(file_obj)
#     for row in reader_obj:
#         prf = PRF(security_parameter=row[0], prime_field=row[1],generator=row[2] , key=row[3])
#         output = prf.evaluate(int(row[4]))
#         print(output)
        # exit()
        
        
        
        
        
        
        # print(int(str(output,2)))
        # exit(0)
# prf = PRF(security_parameter=32, generator=2, prime_field=23, key=123456789)
# # Evaluate the PRF at some input value x
# message_x = 729
# output = prf.(message_x)
# print(output)
 
