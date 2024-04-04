

class PRG:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int):
        """
        Initialize values here
        :param security_parameter: n (from 1ⁿ)
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        """
        self.n = int(security_parameter)
        self.g = int(generator)
        self.p = int(prime_field)
        self.output_length = int(expansion_factor)
        # print(self.n,self.g,self.p,self.output_length)
        pass

    
    def get_hardcore_bit(self,x):
        '''
        Extracts Hardcore bit using Blum Micali:
        if  x <  prime/2    - 0
            x >= prime/2    - 1
        '''
        if x < (self.p - 1) // 2:
            return 0
        else:
            return 1
        
    def discrete_log(self,g,x,p):
        bit = self.get_hardcore_bit(x)
        # res = g^x mod p
        res = pow(g, x, p)
        return bit, res
        
    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        """
        x = seed
        prn = ""
        for i in range(self.output_length ):
            hardcore_bit, x = self.discrete_log(self.g, x ,self.p)
            prn = prn + str(hardcore_bit)
        return prn
        pass


# import csv

# with open('./prg.csv') as file_obj:
#     heading = next(file_obj)
#     reader_obj = csv.reader(file_obj)
#     for row in reader_obj:
#         prg = PRG(security_parameter=row[0], generator=row[1], prime_field=row[2], expansion_factor=row[3])
#         output = prg.generate(seed=int(row[4]))
#         print(output)
#         # exit(0)
