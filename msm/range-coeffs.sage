# Range computations for the EC ADD circuit.

#var('b') # Symbolic integer division is hard

# Works with (15,4) too, or with pretty much anything?
b = 75
n = 4

def compute_c_eq1(i):
    if i == -1 or i > 2*n-2:
        return 0
    elif i < n:
        res = 2*(i+1)*(2^b - 1)^2 + (2^b - 1) + compute_c_eq1(i-1)
        ci = res // 2^b
        return ci
    else: #if n <= i <= 2*n-2
        res = 2*(2*n-i-1)*(2^b - 1)^2 + compute_c_eq1(i-1)
        ci = res // 2^b
        return ci

def compute_c_eq1_direct(i):
    if i == -1 or i > 2*n-2:
        return 0
    elif i < n:
        return (i+1)*2^(b+1) - 2*i - 3
    else: # n <= i <= 2*n-2
        return (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3



print([compute_c_eq1(i) for i in [0..2*n-2]])
print(max([compute_c_eq1(i) for i in [0..2*n-2]]))
print([compute_c_eq1(i) == compute_c_eq1_direct(i) for i in [0..2*n-2]])


def compute_c_eq2(i):
    if i == -1 or i > 2*n-2:
        return (0,0)
    (cprev1, cprev2) = compute_c_eq2(i-1)
    if i < n:
        res1 = 2*(i+1)*(2^b - 1)^2 + cprev1
        res2 = (i+1)*(2^b - 1)^2 + 3 * (2^b - 1) + cprev2
        c1 = res1 // 2^b
        c2 = res2 // 2^b
        return (c1,c2)
    else:  # n <= i <= 2*n-2
        res1 = 2*(2*n-i-1)*(2^b - 1)^2 + cprev1
        res2 = 2*(2*n-i-1)*(2^b - 1)^2 + cprev2
        c1 = res1 // 2^b
        c2 = res2 // 2^b
        return (c1,c2)


def compute_c_eq2_direct(i):
    if i == -1 or i > 2*n-2:
        return (0,0)
    if i < n:
        c1 = (i+1)*2^(b+1) - 2*i - 4
        if i == 0:
            c2 = 2^b
        else:
            c2 = i*2^b + 2^b - i
        return (c1,c2)
    else:
        c1 = (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3
        if i == n:
            c2 = (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3 - (n-1)
        else:
            c2 = (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3
        return (c1,c2)


print([compute_c_eq2(i) for i in [0..2*n-2]])
print(max([compute_c_eq2(i)[0] for i in [0..2*n-2]]))
print(max([compute_c_eq2(i)[1] for i in [0..2*n-2]]))
print([compute_c_eq2(i) == compute_c_eq2_direct(i) for i in [0..2*n-2]])


def compute_c_eq3(i):
    if i == -1 or i > 2*n-2:
        return (0,0)
    (cprev1, cprev2) = compute_c_eq3(i-1)
    if i < n:
        res1 = 2*(i+1)*(2^b - 1)^2 + cprev1
        res2 = (i+1)*(2^b - 1)^2 + 2 * (2^b - 1) + cprev2
        c1 = res1 // 2^b
        c2 = res2 // 2^b
        return (c1,c2)
    else:
        res1 = 2*(2*n-i-1)*(2^b - 1)^2 + cprev1
        res2 = 2*(2*n-i-1)*(2^b - 1)^2 + cprev2
        c1 = res1 // 2^b
        c2 = res2 // 2^b
        return (c1,c2)


def compute_c_eq3_direct(i):
    if i == -1 or i > 2*n-2:
        return (0,0)
    if i < n:
        c1 = (i+1)*2^(b+1) - 2*i - 4
        c2 = (i + 1) * 2^b - i - 1
        return (c1,c2)
    else:
        c1 = (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3
        if i == n:
            c2 = (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3 - (n-1)
        else:
            c2 = (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3
        return (c1,c2)



print([compute_c_eq3(i) for i in [0..2*n-2]])
print(max([compute_c_eq3(i)[0] for i in [0..2*n-2]]))
print(max([compute_c_eq3(i)[1] for i in [0..2*n-2]]))
print([compute_c_eq3(i) == compute_c_eq3_direct(i) for i in [0..2*n-2]])

#print([compute_c_eq3(i)[0] // 2^b for i in [0..n-1]])
#print([compute_c_eq3(i)[0] % 2^b - 2^b for i in [0..n-1]])
#print([compute_c_eq3(i)[0] // 2^b for i in [n..2*n-2]])
#print([compute_c_eq3(i)[0] % 2^b - 2^b for i in [n..2*n-2]])
#print([compute_c_eq3_direct(i)[0] // 2^b for i in [n..2*n-2]])
#print([compute_c_eq3_direct(i)[0] % 2^b - 2^b for i in [n..2*n-2]])
#print([compute_c_eq3(i)[1] // 2^b for i in [n..2*n-2]])
#print([compute_c_eq3(i)[1] % 2^b - 2^b for i in [n..2*n-2]])
#print([compute_c_eq3_direct(i)[1] // 2^b for i in [n..2*n-2]])
#print([compute_c_eq3_direct(i)[1] % 2^b - 2^b for i in [n..2*n-2]])
