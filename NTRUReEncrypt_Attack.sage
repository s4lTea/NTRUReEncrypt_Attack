#!/usr/bin/env python
# coding: utf-8

# In[1]:


import random
R.<x> = PolynomialRing(ZZ)

#NTRUReEncrypt system
class NTRUReEncrypt(object):

    def gen_s(self, d):
        L_0 = [0] * (self.n - 2 * d)
        L_1 = d * [1]
        L_2 = d * [-1]
        L = L_0 + L_1 + L_2
        for i in range(randint(5,10)):
            random.shuffle(L)
        poly = R(L) % (x^self.n - 1)
        return poly
    
    def gen_m(self, seed):
        seed_1 = randint(0, seed)
        seed_2 = randint(0, seed)
        L_0 = (self.n - seed_1 - seed_2) * [0]
        L_1 = seed_1 * [-1]
        L_2 = seed_2 * [1]
        L = L_0 + L_1 + L_2
        for i in range(randint(1,5)):
            random.shuffle(L) 
        poly = R(L)
        return poly

    def modCoeffs(self, f, pp):
        clist = f.list()
        p2 = pp/2
        for i in range(len(clist)):
            clist[i] = clist[i] % pp
            if clist[i] > p2:
                clist[i] -= pp
        return R(clist)

    def __inv_poly_mod2__(self,poly):
        k = 0; b = 1; c = 0 * x;
        f= poly; g = x^self.n-1
        f = self.modCoeffs(f, 2)
        res = False
        while True:
            while f(0) == 0 and not f.is_zero():
                f = f.shift(-1)
                c = c.shift(1)
                c = self.modCoeffs(c, 2)
                k += 1
            if f.is_one():
                e = (-k) % self.n
                retval = x^e * b 
                res = True
                break
            elif f.degree() == -1 or f.is_zero():
                break
            if f.degree() < g.degree():
                f, g = g, f
                b, c = c, b
            f = f + g
            b = b + c
            f = self.modCoeffs(f, 2)
            c = self.modCoeffs(c, 2)
        if res:
            retval = retval % (x^self.n - 1)
            retval = self.modCoeffs(retval, 2)
            return True, retval
        else:
            return False,0

    def __inv_poly_mod_prime_pow__(self,poly):
        res,b = self.__inv_poly_mod2__(poly)
        if res:
            qr = 2
            while qr < self.q:
                qr = qr^2
                b = b * (2 - poly * b)
                b = b % (x^self.n - 1)
                b = self.modCoeffs(b, self.q)
            return True,b
        else:
            return False,0
    
    def __gen_priv_key__(self):
        res = False
        while (res == False):
            poly = self.gen_s(self.df)
            poly = 1 + self.p * poly
            res, poly_q = self.__inv_poly_mod_prime_pow__(poly)
        return poly, poly_q

    def gen_keys(self):
        f, f_q = self.__gen_priv_key__()
        g = self.gen_s(self.dg)
        h = self.p * g * f_q
        h = h % (x^self.n - 1)
        h = self.modCoeffs(h, self.q)
        return h, (f,g), f_q
    
    def gen_re_keys(self, f_a, f_b_q):
        rk = f_a * f_b_q   
        rk = rk % (x^self.n - 1)
        rk = self.modCoeffs(rk, self.q)
        return rk
        
    def encrypt(self, h, m):
        s = self.gen_s(self.df)
        c = s * h + m
        c = c % (x^self.n - 1)
        c = self.modCoeffs(c, self.q)
        return c, s
    
    def decrypt(self, c, Priv):
        f = Priv[0]
        a = f * c
        a = a % (x^self.n - 1)
        a = self.modCoeffs(a, self.q)
        a = a % (x^self.n - 1)
        a = self.modCoeffs(a, self.p)
        return a
    
    def re_encrypt(self, rk, c):
        s = self.gen_s(self.df)
        cc = c * rk + self.p * s
        cc = cc % (x^self.n - 1)
        cc = self.modCoeffs(cc, self.q)
        return cc, s


    def re_decrypt(self, cc, Priv):
        f = Priv[0]
        a = f * cc
        a = a % (x^self.n - 1)
        a = self.modCoeffs(a, self.q)
        a = a % (x^self.n - 1)
        a = self.modCoeffs(a, self.p)
        return a
    
    def __init__(self, Para):
        self.p = 3
        if Para == 'ees1171':
            self.n = 1171
            self.q = 2048
            self.dg = 390
            self.df = 106
            self.seed = 400
        elif Para == 'ees1087':
            self.n = 1087
            self.q = 2048
            self.dg = 362
            self.df = 120
            self.seed = 400  
        elif Para == 'ees1499':
            self.n = 1499
            self.q = 2048
            self.dg = 499
            self.df = 79
            self.seed = 400     
        elif Para == 'demo':
            self.n = 571
            self.q = 2048
            self.dg = 176
            self.df = 55
            self.seed = 200   
            


# In[2]:


#use specific parameter sets
#obtain keys
#collect ciphertexts

#-----------------------obtain keys-------------------------
ntru = NTRUReEncrypt('ees1087')
#ntru = NTRUReEncrypt('demo')



h_A, sk_A, f_A_q = ntru.gen_keys()
h_B, sk_B, f_B_q = ntru.gen_keys()
rk = ntru.gen_re_keys(sk_A[0], f_B_q)

#-----------------------------------------------------------




#----------------collect 5*N ciphertexts--------------------
Q = R.quotient(x^ntru.n - 1)              

dim = (ntru.n/2).floor() + 1 + ntru.n     

N = 5 * ntru.n

c_a = matrix(N, ntru.n) 
c_b = matrix(N, ntru.n)

for i in range(N):
    m = ntru.gen_m(ntru.seed)             
    c,s = ntru.encrypt(h_A, m)           
    cc, e = ntru.re_encrypt(rk, c)      

    c_a[i] = Q(c.list()).list()           
    c_b[i] = Q(cc.list()).list()          
    
print(c_a.parent())            
#------------------------------------------------------------





# In[3]:


#----------prepare to build equations on F_2----------------
import time


ll = 3

u = matrix(Integers(2048), dim + ll, 1)

d = 2 * ntru.p^2 * ntru.df

mat_coe = matrix(Integers(2048), dim + ll, dim)   


def splice(mat_0,mat_1):
    
    final = matrix(1, dim)
    for i in range(dim):
        if (i < 1):
            final[0,i] = mat_0[0,i]
        elif (i < (ntru.n/2).floor() + 1):
            final[0,i] = 2 * mat_0[0,i]
        else:
            final[0,i] = (-2) * mat_1[0,i - (ntru.n/2).floor() - 1 ]
    return final

def build(c_a_vector, c_b_vector, i):
    
    c_a = matrix.circulant(c_a_vector).T   
    c_b = c_b_vector.row().T               
    
    c_mat = c_a.T * c_a             
    
    c_coe = c_mat[0].row()
    k_coe = c_b.T * c_a                    
    
    mat_coe[i] = splice(c_coe, k_coe)      

    u[i] = d - c_b.T * c_b

    return mat_coe, u
#------------------------------------------------------------









#------------------------------------------------------------
#choose suitable ciphertexts and generate a system of equations
#this step is the main part of the total running time of the program
#------------------------------------------------------------


start = time.time()

js3 = 0
for i in range(N):
    
    ca = c_a[i].list()
    js = 0
    for j in range(ntru.n):
        js += ca[j]^2
    ccc = js%2048 
    
    cb = c_b[i].list()
    js2 = 0
    for j in range(ntru.n):
        js2 += cb[j]^2
    
    uuu = (d-js2)%2048

    if(ccc%2 == 0):
        if(uuu%2 == 0):
            c_a_vector = c_a[i]
            c_b_vector = c_b[i]
    
            build(c_a_vector, c_b_vector, js3)
            js3 += 1
            print("done", js3, "\n")
    
    if(js3 == dim + ll):
        print("finished !", i, "\n")
        break
    
    
end = time.time()

print ("time = ", str(end-start))    

#------------------------------------------------------------

    
    
    
print(mat_coe.parent())
print(u.parent())



# In[20]:


#------------------------------------------------------------
#sovle equations on F_2 to obtain rk mod2
#------------------------------------------------------------

left = mat_coe.change_ring(ZZ)/2
right = u.change_ring(ZZ)/2


zz = matrix(Integers(2),left)
yy = matrix(Integers(2),right)

l_0 = ((ntru.n/2).floor() + 1) * [0]
l_1 = (ntru.n) * [1]
l = l_0 + l_1
zz = zz.stack(vector(l))
yy= yy.stack(vector([1]))

get_ipython().run_line_magic('time', 'solu = zz.solve_right(yy)')

solu = solu.change_ring(Integers(ntru.q))

solu_rk = solu[dim - ntru.n:,:].change_ring(Integers(2))

true_rk = matrix(Integers(2),rk.list()).T


#check if recover the correct rk
print("if recover the correct rk: ", solu_rk == true_rk)


# In[21]:


#------------------------------------------------------------
#recover private keys on Z_q from rk mod2 to obtain Alice's private key sk_A modq
#this step is the negligible part of the total running time of the program(few seconds)
#------------------------------------------------------------



rk_mod2 = rk%2

check = rk_mod2 * sk_B[0] - 1
F_mod2_check = check%(x^ntru.n - 1)%2


F_list = F_mod2_check
F_list_index = []

for i in range(ntru.n):
    if F_list[i] == 0:
        F_list_index.append(i)


h_matrix = matrix.circulant(h_A.list()).T

h_matrix = h_matrix.delete_columns(F_list_index)



h_A_mod2 = h_A%2

g_A_mod2_check = (1 + ntru.p * F_mod2_check) * h_A_mod2 %(x^ntru.n - 1)%2


g_A_list = g_A_mod2_check
g_A_list_index = []

for i in range(ntru.n):
    if g_A_list[i] != 0:
        g_A_list_index.append(i)


h_matrix = h_matrix.delete_rows(g_A_list_index)

right = matrix(h_A.list()).T


right = right.delete_rows(g_A_list_index)


L = matrix(Integers(2048), 3*h_matrix)
S = matrix(Integers(2048), -right)


get_ipython().run_line_magic('time', 'solu = L.solve_right(S)')

solu_ls = solu.change_ring(ZZ).list()
for i in range(len(solu_ls)):
    if(solu_ls[i]>1):
        solu_ls[i] = 3*(solu_ls[i]-2048)
    else:
        solu_ls[i] = 3*(solu_ls[i])

sk_A_solu = []
for i in range(ntru.n):
    sk_A_solu.append(-1)

for i in range(len(F_list_index)):
    sk_A_solu[F_list_index[i]] = 0
    
solu_list_index = []   
for i in range(ntru.n):
    if sk_A_solu[i] == -1:
        solu_list_index.append(i)   
    
for i in range(len(solu_list_index)):
        sk_A_solu[solu_list_index[i]] = solu_ls[i]
    
sk_A_solu[0] = 1

sk_A_true = Q(sk_A[0].list()).list() 

#check if recover the correct sk_A
print("if recover the correct sk_A: ", sk_A_true == sk_A_solu)


# In[ ]:




