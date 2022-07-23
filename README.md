# Differential Cryptanalysis of Lightweight Block Ciphers LCB and SCENERY
This repository contains SMT models for the research on Differential Cryptanalysis of LCB and SCENERY Block Ciphers.

## LCB
LCB is a ultra lightweight block cipher using 32-bit blocks and 64 bits master key designed following the hybrid of SPN and Feistel strucure. [[1]](#1).

## SCENERY
SCENERY is a lightweight block cipher using 64-bit blocks and 80 bits master key designed following the balance Feistel structure [[2]](#2).

### References
<a id="1">[1]</a> 
Roy, S., Roy, S., Biswas, A., & Baishnab, K. (2021, nov). LCB: Light cipher block, an ultrafast lightweight block cipher for resource constrained IOT security applications. KSII Transactions on Internet and Information Systems, 15(11). doi:10.3837/tiis.2021.11.014 

<a id="2">[2]</a> 
Feng, J., & Li, L. (2022). SCENERY: a lightweight block cipher based on feistel structure. Frontiers Comput. Sci., 16(3), 163813. Retrieved from https://doi.org/10.1007/s11704-020-0115-9 doi: 10.1007/s11704-020-0115-9

### Summary
- ./lcb.py: LCB structure modelling in SMT model to be used in CryptoSMT tool for differential attack
- ./scenery.py: SCENERY structure modelling in SMT model to be used in CryptoSMT tool for differential attack
- ./scenery12.yaml: input file for running differential clustering (mode 4)
