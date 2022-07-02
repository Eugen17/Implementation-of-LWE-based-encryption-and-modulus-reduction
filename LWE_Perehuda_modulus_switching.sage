#generating safe primes for parameters
def safe_prime(nbits=16):
    while True:
        p = random_prime(2^nbits-1, false, 2^(nbits-1))
        #Checking is prime safe or not
        if ZZ((p-1)/2).is_prime():
            return p

#Key generation
#parameter secret-key s can be defined in case if
#we want to generate new public key
#based on already specified s(is useful fo relinearization) 
def KeyGen(n,q, s = None):
    #Generating field of order q
    Fq = GF(q)
    
    #Noise generation
    e = vector([ZZ.random_element(2) for i in range(n)])
    
    #Generation of secret key if necessary with s1=1
    if s==None:
        s = vector([Fq(1)]+[Fq(ZZ.random_element(2)) for i in range(n-1)])
    
    #Public key generation
    preA = Matrix(Fq, [[Fq.random_element() for i in range(n-1)]for i in range(n)])
    add_a = e - preA*s[1:]
    A = preA[:, :0].augment(add_a).augment(preA[:, 0:])
    return A, s

#Encryption based on message={0,1} and public key matrix A
def encrypt(message,A):
    #generating vector u from binomial distrubution
    u =  vector([ZZ.random_element(2) for i in range(A.ncols())])
    m_vector =  vector([message]+[0 for i in range(A.ncols()-1)])
    c = m_vector + 2*u*A
    return c

#Decryption based on ciphertext vector s and secret key vector s
def decrypt(c, s, q):
    R2  = GF(2)
    #modulo q
    c = vector([int(ci)%q for ci in c])
    s = vector([int(si)%q for si in s])
    #modulo 2
    return R2((c*s)%q)

#Bit decomposition of each element of vector u
def bit_decomp(u,q,nq):
    def extend_to_nq(arr):
        for i in range(nq-len(arr)):
            arr.append(0) 
        return arr
    tup = [ extend_to_nq([int(x) for x in list(bin(ui))[:1:-1]]) for ui in u]
    #list concatenation
    return [uij for ui in tup for uij in ui]

#Power of 2 based on each element of vector v  
def power_of_2(v,q, nq):
    tup = [ [vi*2**j for j in range(nq)] for vi in v]
    #list concatenation
    return [vij for vi in tup for vij in vi]

#Multiplication of vectors of size m and n
#to generate vector of length m*n
#Useful for generating s'' and c''
def mul_vector(arr1, arr2):
    mul = []
    for i in arr1:
        for j in arr2:
            mul.append(i*j)
    return vector(mul)
 
#Generating t as ciphertext of s''
def generate_t(s, s_xx, n, q):
    A_t = KeyGen(n, q,s)[0]
    return Matrix([encrypt(s_xx_i, A_t) for s_xx_i in s_xx])

#Relinearization
#s_x is s', s_xx is s''
#Output is relinearized multiplication d of c1*c2
def relinearization_of_multiplication(c1,c2 , s,n ,q):
    nq = ceil(math.log2(q))
    s_x = mul_vector(s, s)
    s_xx = power_of_2(s_x, q, nq)
    c_x = mul_vector(c1, c2)
    c_xx = bit_decomp(c_x, q, nq)
    
    t = generate_t(s, s_xx, n, q)
    d = vector([0 for i in range(n)])
    for j in range(nq * n**2):
        d += c_xx[j]*t[j]
    return vector(d)

#Modulo reduction
def modulus_switching(c, q, sk):
    while True:
        #Finding new modulo p which smaller than q
        p = random_prime(q//2, False, 2*8)
        Fp=GF(p)
        #Generating c' which ciphertext with reducted modulo p
        result = [ Fp(round((p)/(q)* float(ci))) for ci in c]
        result_mod2 = [int(result_i)%2 for result_i in result]
        c_mod2 = [int(ci)%2 for ci in c]
        #Checking that c'==c mod 2 and that (c,s)<(q/2)-(q/p)
        if c_mod2 == result_mod2 and int(c*sk)<(q//2-q//p):
            return vector(result), p

#test of correct decryption, correct homomorphic multiplication
#with relinearization, correct modulo switching
def test():
    q = safe_prime(16)
    n = 5
    pk, sk = KeyGen(n,q)
    m0 = 0 
    m1 = 1
    
    c0 = encrypt(m0, pk)
    m0_dec = decrypt(c0, sk, q)
    c1 = encrypt(m1, pk)
    m1_dec = decrypt(c1, sk, q)
    print("Parameters:")
    print ("n =", n)
    print ("q =", q)
    print ("s =", sk)
    print ("A =", pk,"\n")
    print("===Test of correct decryption===")
    print ("m0 =", m0)
    print ("m1 =", m1)
    print ("c0 =", c0)
    print ("c1 =", c1)
    print ("m0_dec == m0:", m0_dec == m0)
    print ("m1_dec == m1:", m1_dec == m1,"\n")
    print("===Test of correct homomorphic multiplication with relinearization===")
    print ("enc(0) * enc(0) =", relinearization_of_multiplication(c0,c0, sk, n,q))
    print ("dec(enc(0) * enc(0)) =", decrypt(relinearization_of_multiplication(c0,c0, sk, n,q),sk, q))
    print ("enc(0) * enc(1) =", relinearization_of_multiplication(c0,c1, sk, n,q))
    print ("dec(enc(0) * enc(1)) =", decrypt(relinearization_of_multiplication(c0,c1, sk, n,q),sk, q))
    print ("enc(1) * enc(0) =", relinearization_of_multiplication(c1,c0, sk, n,q))
    print ("dec(enc(1) * enc(0)) =", decrypt(relinearization_of_multiplication(c1,c0, sk, n,q),sk, q))
    print ("enc(1) * enc(1) =", relinearization_of_multiplication(c1,c1, sk, n,q))
    print ("dec(enc(1) * enc(1)) =", decrypt(relinearization_of_multiplication(c1,c1, sk, n,q),sk, q),"\n")
    
    print("===Test of correct modulo reduction===")
    print("Old modulo q =",q,"\n")
    
    print("Old ciphertext of c0 =",c0)
    c_modulus_switching_c0, p = modulus_switching(c0,q, sk)
    print("New ciphertext after modulus switching p =",c_modulus_switching_c0)
    print("New modulo p =",p)
    print("Decryption of c0 after modulus switching", decrypt(c_modulus_switching_c0, sk, p),"\n")
    
    print("Old ciphertext of c1 =",c1)
    c_modulus_switching_c1, p = modulus_switching(c1,q, sk)
    print("New ciphertext after modulus switching p =",c_modulus_switching_c1)
    print("New modulo p =",p)
    print("Decryption of c1 after modulus switching", decrypt(c_modulus_switching_c1, sk, p),"\n")
    
    c1_c1 = relinearization_of_multiplication(c1,c1, sk, n,q)
    print("Old ciphertext of relinearized c1*c1 =",c1_c1)
    c_modulus_switching_c1_c1, p = modulus_switching(c1_c1,q, sk)
    print("New ciphertext after modulus switching p =",c_modulus_switching_c1_c1)
    print("New modulo p =",p)
    print("Decryption of c1*c1 after modulus switching", decrypt(c_modulus_switching_c1_c1, sk, p))

test()