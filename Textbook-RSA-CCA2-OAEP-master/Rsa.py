import random

def rabin_miller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1

    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
                    # if v == 1:   # 这两行可以删，因为v==1的情况最终会到if i == t-1这一分支上去
                    #     return False # 但加上的更能说明这是二次探测定理，如果num是素数，则v^2=1(mod num)的解只能是1或num-1不会是其他值。
                    # 因此在v!=1，!=num-1后，它能自救（证明大概率num是素数）的唯一方法是v^2=num-1(mod num)。换句话说这里用到二次探测定理的地方在于
                    # 检测除1和num-1外其他值会不会平方后mod=1，如果一路上升的时候都不会，说明大概率num是素数。
    return True


def is_prime(num):
    # 排除0,1和负数
    if num < 2:
        return False

    # 创建小素数的列表,可以大幅加快速度
    # 如果是小素数,那么直接返回true
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    if num in small_primes:
        return True

    # 如果大数是这些小素数的倍数,那么就是合数,返回false
    for prime in small_primes:
        if num % prime == 0:
            return False

    # 如果这样没有分辨出来,就一定是大整数,那么就调用rabin算法
    return rabin_miller(num)


# 得到大整数,默认位数为1024
def get_prime(key_size=1024):
    while True:
        num = random.randrange(2**(key_size-1), 2**key_size)
        if is_prime(num):
            return num


def calculate_bits(number):
    len = 0
    while number != 0:
        number >>= 1
        len += 1
    return len


def get_gcd(a, b):
    k = a // b
    remainder = a % b
    while remainder != 0:
        a = b
        b = remainder
        k = a // b
        remainder = a % b
    return b


# 改进欧几里得算法求线性方程的x与y http://www.so-cools.com/?p=818
def calculate_equation(a, b): # 计算 ax-by=1 的正整数解
    if b == 0:
        return 1, 0
    else:
        k = a // b
        remainder = a % b
        x1, y1 = calculate_equation(b, remainder)
        x, y = y1, x1 - k * y1
    return x, y


def s2e(s):
    e = [0,0,0,0,0,0,0,0]
    for i in range(0,8,1):
        e[i] = int(s%2)
        s=s//2
    e.reverse()
    return e
