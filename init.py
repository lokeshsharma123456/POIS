import sys
# sys.path.append('../')
from PRG.PRG import PRG
from PRF.PRF import PRF
from EAV.EAV import Eavesdrop
from CPA.CPA import CPA
from MAC.MAC import MAC
from CBC_MAC.CBC_MAC import CBC_MAC
from CCA.CCA import CCA

import csv

print('OUTPUT OF PRG : ')
with open('PRG/prg.csv','r') as file_obj:
    heading = next(file_obj)
    reader_obj = csv.reader(file_obj)
    for row in reader_obj:
        prg = PRG(security_parameter=row[0], generator=row[1], prime_field=row[2], expansion_factor=row[3])
        output = prg.generate(seed=int(row[4]))
        print(output)
        # exit(0)
        

print()
print('OUTPUT OF PRF : ')
with open('PRF/prf.csv','r') as file_obj:
    heading = next(file_obj)
    reader_obj = csv.reader(file_obj)
    for row in reader_obj:
        prf = PRF(security_parameter=row[0], prime_field=row[1],generator=row[2] , key=row[3])
        output = prf.evaluate(int(row[4]))
        print(output)
        # exit(0)
        
print()
print('OUTPUT OF EAV : ',)
print('CYPHERTEXT')
with open('EAV/eav.csv') as file_obj:
    heading = next(file_obj)
    reader_obj = csv.reader(file_obj)
    ciphers = []
    messages = []
    for row in reader_obj:
        eav = Eavesdrop(security_parameter=row[0], key=row[1], expansion_factor=row[2],generator= row[3],prime_field=row[4])
        ciphertext = eav.enc(message = row[5])
        ciphers.append(ciphertext)
        # exit(0)
        mes = eav.dec(ciphertext)
        messages.append(mes)
        print(ciphertext)
        
    # print("\nget back to message :")
    # for i in range(len(ciphers)):
    #     print(ciphers[i])
        # print(messages[i])
        # print()
        # print(message)
        
        
print()
print('OUTPUT OF CPA : ',)
print('CYPHERTEXT')
with open('CPA/cpa.csv') as file_obj:
    heading = next(file_obj)
    reader_obj = csv.reader(file_obj)
    ciphers = []
    messages = []
    for row in reader_obj:
        cpa = CPA(security_parameter=row[0], prime_field=row[1], generator=row[2],key= row[3])
        ciphertext = cpa.enc(message = row[4], random_seed=int(row[5]))
        ciphers.append(ciphertext)
        print(ciphertext)
        # exit(0)
        mes = cpa.dec(ciphertext)
        messages.append(mes)
    #     print(mes)
    #     print(row[4])
        
    # print("\nget back to message :")
    # for i in range(len(ciphers)):
    #     print(ciphers[i])
    #     print(messages[i])
    #     print()
    

print()
print('OUTPUT OF MAC : ',)
print('TAGS WITH VERIFICATION')
with open('MAC/mac.csv') as file_obj:
    heading = next(file_obj)
    reader_obj = csv.reader(file_obj)
    ciphers = []
    messages = []
    for row in reader_obj:
        sec_mac = MAC(security_parameter=row[0], prime_field=row[1], generator=row[2],seed= row[3])
        tagi = sec_mac.mac(message = row[4], random_identifier=int(row[5]))
        ciphers.append(tagi)
        print(tagi)
        print(sec_mac.vrfy(message=row[4], tag = int(tagi,2)))
        print()
        # exit()
        
        
print()
print('OUTPUT OF CBC_MAC : ',)
print('TAGS WITH VERIFICATION')
with open('CBC_MAC/cbc_mac.csv') as file_obj:
    heading = next(file_obj)
    reader_obj = csv.reader(file_obj)
    ciphers = []
    messages = []
    for row in reader_obj:
        keys = list()
        keys.append(row[3])
        keys.append(row[4])
        cbc_mac = CBC_MAC(security_parameter=row[0], generator=row[1], prime_field=row[2],expansion_factor= 2 * int(row[0]),keys=keys)
        MAC_tag = cbc_mac.mac(message = row[5])
        print(MAC_tag)
        print(cbc_mac.vrfy(message=row[5], tag = int(MAC_tag)))
        print()
        # exit()
        
print()
print('OUTPUT OF CCA : ',)
print('CIPHER WITH VERIFICATION')
with open('CCA/cca.csv') as file_obj:
    heading = next(file_obj)
    reader_obj = csv.reader(file_obj)
    ciphers = []
    messages = []
    for row in reader_obj:
        keys = list()
        keys.append(row[3])
        keys.append(row[4])
        cca = CCA(security_parameter=row[0], prime_field=row[1], generator=row[2], key_cpa=row[3], key_mac=[row[4],row[5]])
        cca_cipher = cca.enc(message=row[6], cpa_random_seed=row[7])
        print(cca_cipher)
        print(cca.dec(cca_cipher))
        print()
