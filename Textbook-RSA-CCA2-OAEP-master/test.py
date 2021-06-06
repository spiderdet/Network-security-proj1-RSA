from Rsa import get_prime, calculate_bits, get_gcd, calculate_equation
import math
import time
import decimal

size = 1024
len1 = size // 2
len2 = size - len1
p = get_prime(len1)
print("p bits:", calculate_bits(p))
print("p: ", p)
q = get_prime(len2)
print("q bits:", calculate_bits(q))
print("q: ", q)
n = p*q
k = calculate_bits(n)
if k != size:
    print("k != size, k = {0}, size = {1}".format(k, size))
e = 65537
phi= (p - 1) * (q - 1)
if get_gcd(e, phi)==1:
    x, y = calculate_equation(e, phi)
    # print(x)
    d = x % phi # otherwise, x might be negative
    # print(d)
print("public key, e:", e, ', n:', n)
print("private key, d:", d, ", n:", n)
decimal.getcontext().prec = 1000 #

# fermat's factorization attack
start_time = time.time()
a = int(decimal.Decimal(n)**decimal.Decimal(0.5))
simple_a = int(math.sqrt(n))
print("simple_a bits:", calculate_bits(simple_a),"a bits:", calculate_bits(a))
print("a       : ", a)
print("simple_a: ", simple_a)
difference = abs(a - simple_a)
print("difference bits:", calculate_bits(difference))
print("difference: ", difference)
b2 = n - a**2
if b2 < 0:
    print("\033[31;1mb2 is negative\033[0m: ", b2)
b = int(math.sqrt(b2))
print("first b bits:", calculate_bits(b))
print("first b: ", b)
while b**2 != b2 and calculate_bits(a) > size // 2 - 1:
    a -= 1
    b2 = n - a**2
    b = int(math.sqrt(b2))
end_time = time.time()
time_consumed = end_time - start_time
if a+b == p or a-b == p:
    print("\033[33;1mSuccess\033[0m, time consumed: ", time_consumed)
else:
    print("\033[31;1mFailure\033[0m, time consumed: ", time_consumed)
