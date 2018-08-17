# !/usr/bin/python
# encoding=utf-8

from __future__ import division
import json, base64, os, random
import random, copy
import functools
import sys

FLAGS = r'`~!@#$%^&*()_+-={}|[]\:;"\'<>?,./'
Replace_Table1 = [0, 255, 200, 8, 145, 16, 208, 54, 90, 62, 216, 67, 153, 119, 254, 24, 35, 32, 7, 112, 161, 108, 12, 127, 98, 139, 64, 70, 199, 75, 224, 14, 235, 22, 232, 173, 207, 205, 57, 83, 106, 39, 53, 147, 212, 78, 72, 195, 43, 121, 84, 40, 9, 120, 15, 33, 144, 135, 20, 42, 169, 156, 214, 116, 180, 124, 222, 237, 177, 134, 118, 164, 152, 226, 150, 143, 2, 50, 28, 193, 51, 238, 239, 129, 253, 48, 92, 19, 157, 41, 23, 196, 17, 68, 140, 128, 243, 115, 66, 30, 29, 181, 240, 18, 209, 91, 65, 162, 215, 44, 233, 213, 89, 203, 80, 168, 220, 252, 242, 86, 114, 166, 101, 47, 159, 155, 61, 186, 125, 194, 69, 130, 167, 87, 182, 163, 122, 117, 79, 174, 63, 55, 109, 71, 97, 190, 171, 211, 95, 176, 88, 175, 202, 94, 250, 133, 228, 77, 138, 5, 251, 96, 183, 123, 184, 38, 74, 103, 198, 26, 248, 105, 37, 179, 219, 189, 102, 221, 241, 210, 223, 3, 141, 52, 217, 146, 13, 99, 85, 170, 73, 236, 188, 149, 60, 132, 11, 245, 230, 231, 229, 172, 126, 110, 185, 249, 218, 142, 154, 201, 36, 225, 10, 21, 107, 58, 160, 81, 244, 234, 178, 151, 158, 93, 34, 136, 148, 206, 25, 1, 113, 76, 165, 227, 197, 49, 187, 204, 31, 45, 59, 82, 111, 246, 46, 137, 247, 192, 104, 27, 100, 4, 6, 191, 131, 56]
Replace_Table2 = [1, 229, 76, 181, 251, 159, 252, 18, 3, 52, 212, 196, 22, 186, 31, 54, 5, 92, 103, 87, 58, 213, 33, 90, 15, 228, 169, 249, 78, 100, 99, 238, 17, 55, 224, 16, 210, 172, 165, 41, 51, 89, 59, 48, 109, 239, 244, 123, 85, 235, 77, 80, 183, 42, 7, 141, 255, 38, 215, 240, 194, 126, 9, 140, 26, 106, 98, 11, 93, 130, 27, 143, 46, 190, 166, 29, 231, 157, 45, 138, 114, 217, 241, 39, 50, 188, 119, 133, 150, 112, 8, 105, 86, 223, 153, 148, 161, 144, 24, 187, 250, 122, 176, 167, 248, 171, 40, 214, 21, 142, 203, 242, 19, 230, 120, 97, 63, 137, 70, 13, 53, 49, 136, 163, 65, 128, 202, 23, 95, 83, 131, 254, 195, 155, 69, 57, 225, 245, 158, 25, 94, 182, 207, 75, 56, 4, 185, 43, 226, 193, 74, 221, 72, 12, 208, 125, 61, 88, 222, 124, 216, 20, 107, 135, 71, 232, 121, 132, 115, 60, 189, 146, 201, 35, 139, 151, 149, 68, 220, 173, 64, 101, 134, 162, 164, 204, 127, 236, 192, 175, 145, 253, 247, 79, 129, 47, 91, 234, 168, 28, 2, 209, 152, 113, 237, 37, 227, 36, 6, 104, 179, 147, 44, 111, 62, 108, 10, 184, 206, 174, 116, 177, 66, 180, 30, 211, 73, 233, 156, 200, 198, 199, 34, 110, 219, 32, 191, 67, 81, 82, 102, 178, 118, 96, 218, 197, 243, 246, 170, 205, 154, 160, 117, 84, 14, 1]

#define galois_field, it is important
class galois_field:

    def __init__(self, value):
        self.value = value % 256

    def __add__(self, bLafarB):
        return galois_field(self.value ^ bLafarB.value)

    def __iadd__(self, bLafarB):
        self.value ^= bLafarB.value
        return self

    def __mul__(self, bLafarB):
        if bLafarB.value == 0 or self.value == 0:
            return galois_field(0)
        return galois_field(Replace_Table2[(Replace_Table1[self.value] + Replace_Table1[bLafarB.value]) % 255])

    def __imul__(self, bLafarB):
        if bLafarB.value == 0 or self.value == 0:
            self.value = 0
        else:
            self.value = Replace_Table2[(Replace_Table1[self.value] + Replace_Table1[bLafarB.value]) % 255]
        return self

    def __div__(self, bLafarB):
        if bLafarB.value == 0:
            raise ZeroDivisionError('Division by zero')
        return galois_field(Replace_Table2[(255 + Replace_Table1[self.value] - Replace_Table1[bLafarB.value]) % 255])

    def __idiv__(self, bLafarB):
        if bLafarB.value == 0:
            raise ZeroDivisionError('Division by zero')
        self.value = Replace_Table2[(255 + Replace_Table1[self.value] - Replace_Table1[bLafarB.value]) % 255]
        return self

class encrypt_single:

    def __init__(self, shares, threshold):
        self.shares = shares
        self.rng = random.SystemRandom()
        self.base_poly = [ self.rng.randint(0, 256) for _ in range(threshold - 1) ]
        print self.base_poly

    def calculate(self, secret):
        coeffs = [secret] + self.base_poly
        coords = []
        result = []
        while len(coords) < self.shares:
            drawn = self.rng.randint(1, 255)
            if drawn not in coords:
                coords += [drawn]

        for coord in coords:
            B = galois_field(1)
            S = galois_field(0)
            X = galois_field(coord)
            for coeff in coeffs:
                T = B * galois_field(coeff)
                S += T
                B *= X
            result.append(S.value)
        return (coords, result)

class shamir_share_encrypt:

    def __init__(self):
        pass

    def encrypt(self, numshares, threshold, key):
        self.calculator = encrypt_single(numshares, threshold)
        xshares = [''] * numshares
        yshares = [''] * numshares
        for char in key:
            xcords, ycords = self.calculator.calculate(ord(char))
            for idx in range(numshares):
                xshares[idx] += chr(xcords[idx])
                yshares[idx] += chr(ycords[idx])

        return (xshares, yshares)

    def dump_data_to_json(self, shares, threshold, split):
        data = {'shares': shares,
         'threshold': threshold,
         'split': [base64.b64encode(split[0]), base64.b64encode(split[1])]}
        return json.dumps(data)

#Core calculation
class gauss_elimination:

    def __init__(self):
        pass
    
    def solve(self, ma, y):
        m = []
        for x in xrange(0,len(ma)):
            line = []
            for num in ma[x]:
                line.append(galois_field(num))
            line.append(galois_field(y[x]))
            m.append(line)
        
        i = 0; j = 0; row_pos = 0; col_pos = 0; ik = 0; jk = 0
        mik = galois_field(0)
        temp = galois_field(0)
        
        def swap( a, b ):
            t = a; a = b; b = t        
    
        n = len( m )
        while( ( row_pos < n ) and( col_pos < n ) ):
            #print "位置：row_pos = %d, col_pos = %d" % (row_pos, col_pos)
            # 选主元
            for i in range( row_pos, n ):
                if( m[i][col_pos].value > mik.value ):
                    mik = m[i][col_pos]
                    ik = i
            if( mik.value == 0 ):
                col_pos = col_pos + 1
                continue
            # 交换两行
            if( ik != row_pos ):
                for j in range( col_pos, n ):
                    swap( m[row_pos][j], m[ik][j] )
                    swap( m[row_pos][n], m[ik][n] ) # 区域之外？
            try:
                # 消元
                m[row_pos][n] = m[row_pos][n].__div__( m[row_pos][col_pos] )
            except ZeroDivisionError:
                # 除零异常 一般在无解或无穷多解的情况下出现……
                return 0;
            j = n - 1
            while( j >= col_pos ):
                m[row_pos][j] = m[row_pos][j].__div__( m[row_pos][col_pos] )
                j = j - 1
            for i in range( 0, n ):
                if( i == row_pos ):
                    continue
                m[i][n] += m[row_pos][n] * m[i][col_pos]

                j = n - 1
                while( j >= col_pos ):
                    m[i][j] += m[row_pos][j] * m[i][col_pos]
                    j = j - 1
            row_pos = row_pos + 1; col_pos = col_pos + 1
        for i in range( row_pos, n ):
            if( m[i][n].value == 0 ):
                return 0
        solution = []
        for x in xrange(0,len(m)):
            solution.append(m[x][len(m)].value)
        return solution

        
class shamir_share_decrypt:
    def __init__(self):
        pass

    def decrypt(self, xshares, yshares, keylen, threshold=5, shares=10):
        xcords, ycords = [], []
        for i in range(keylen):
            tmx, tmy = [], []
            for x, y in zip(xshares, yshares):
                tmx.append(ord(x[i]))
                tmy.append(ord(y[i]))
            xcords.append(tmx)
            ycords.append(tmy)

        lKey = []
        def PI(vals):
            accum = galois_field(1)
            for v in vals:
                if 'galois_field' not in str(v.__class__):
                    v = galois_field(v)
                accum *= v
            return accum

        def CRes(bv, yc):
            #guass = guass_inemiltion()
            #guass.solve(bv,yc)
            nums, dens, vS = [], [], galois_field(0)
            for i in range(len(yc)):
                vY, vMatrix = yc[i], copy.deepcopy(bv)
                cur = vMatrix.pop(i)
                vNums = galois_field(vY) * PI(j[1] for j in vMatrix)
                vDens = PI(galois_field(j[1]) + galois_field(cur[1]) for j in vMatrix)
                vS += vNums.__idiv__(vDens)
            return vS.value

        for xc, yc in zip(xcords, ycords):
            bv = []
            for x in xc:
                lV, vB, vX = [], galois_field(1), galois_field(x)
                for i in range(threshold):
                    lV.append(vB.value)
                    vB *= vX
                bv.append(lV)
            if len(bv) >= threshold:
                lKey.append(chr(CRes(bv, yc)))
            else:
                tSupply = [i for i in range(0, 256)]
                for i in bv:
                    tSupply.remove(i[1])

                lE = []
                for x in tSupply:
                    lV, vB, vX = [], galois_field(1), galois_field(x)
                    for i in range(threshold):
                        lV.append(vB.value)
                        vB *= vX
                    bv.append(lV)
                    v = CRes(bv, yc)
                    lE.append(v)
                    bv.pop(-1)
                lKey.append(lE)
        print(lKey)
        return lKey

    def read_json(self,fname):
        with open(fname,'r') as f:
            data = json.load(f)
            threshold = data[0]['threshold']
            xshares = [''] * threshold
            yshares = [''] * threshold
            lenkey = len(base64.b64decode(data[0]['split'][0]))
            for x in xrange(0,4):
                xshares[x] = base64.b64decode(data[x]['split'][0])
                yshares[x] = base64.b64decode(data[x]['split'][1])
        return xshares,yshares,threshold,lenkey
    
    def decrypt_try(self,fname):
        (xshares1,yshares1,threshold,lenkey) = self.read_json(fname)
        xcord = []
        ycord = []
        for x in xrange(0,4):
            xcord.append(ord(xshares1[x][1]))
            ycord.append(ord(yshares1[x][1]))
        
        xcord.append(0)
        ycord.append(0)
        
        #burp (x,y) , Just 256*256=65536 situations
        for xx in xrange(0,256):
            for yy in xrange(0,256):
                xcord[4] = xx
                ycord[4] = yy
                ma = []
                for x in xcord:
                    lV, vB, vX = [], galois_field(1), galois_field(x)
                    for i in range(5):
                        lV.append(vB.value)
                        vB *= vX
                    ma.append(lV)
                gauss = gauss_elimination()
                result = gauss.solve(ma, ycord)
                if(result != 0):
                    if result[0] == ord('l'):
                        print "Assume coefficients as below:"
                        print result[1:5]
                        return result[1:5]
        print "Error!"
        return  0
    
    def SolutionType(self,fname,xcords):
        (xshares1,yshares1,threshold,lenkey) = self.read_json(fname)
        linex = xshares1[0]
        liney = yshares1[0]
        result = ""
        for x,y in zip(linex,liney):
            linexnum = ord(x)
            lineynum = ord(y)
            T = galois_field(0)
            X = galois_field(linexnum)
            B = galois_field(linexnum)
            for coffe in xcords:
                Z = B*galois_field(coffe)
                T += Z
                B *= X
            secret = T+galois_field(lineynum)
            #print secret.value
            result += chr(secret.value)
        return result
   

m_de = shamir_share_decrypt()
xcords = m_de.decrypt_try(sys.argv[1])
if xcords!=0:
    print m_de.SolutionType(sys.argv[1], xcords)
    print "if plaintext not right,try another!"
        
'''
key = '[@,@]'
tm = shamir_share_encrypt()
(xshares, yshares) = tm.encrypt(10, 5, key)
tmR = shamir_share_decrypt()
tmR.decrypt(xshares[0:5], yshares[0:5], len(key))
tmR.decrypt(xshares[0:4], yshares[0:4], len(key))
'''