# Range computations for the EC ADD circuit.

#var('b') # Symbolic integer division is hard
b = 75 # Works with 15 too

def compute_c_eq1(i):
    if i == -1:
        return 0
    res = 2*(i+1)*(2^b - 1)^2 + (2^b - 1) + compute_c_eq1(i-1)
    ci = res // 2^b
    return ci

def compute_c_eq1_direct(i):
    return (i+1)*2^(b+1) - 2*i - 3


print([compute_c_eq1(i) for i in [0..20]])
print([compute_c_eq1(i) == compute_c_eq1_direct(i) for i in [0..20]])

def compute_c_eq2(i):
    if i == -1:
        return (0,0)
    (cprev1, cprev2) = compute_c_eq2(i-1)
    res1 = 2*(i+1)*(2^b - 1)^2 + cprev1
    res2 = (i+1)*(2^b - 1)^2 + 3 * (2^b - 1) + cprev2
    c1 = res1 // 2^b
    c2 = res2 // 2^b
    return (c1,c2)


def compute_c_eq2_direct(i):
    c1 = (i+1)*2^(b+1) - 2*i - 4
    if i == 0:
        c2 = 2^b
    else:
        c2 = i*2^b + 2^b - i
    return (c1,c2)

print([compute_c_eq2(i) for i in [0..20]])
print([compute_c_eq2(i) == compute_c_eq2_direct(i) for i in [0..20]])

def compute_c_eq3(i):
    if i == -1:
        return (0,0)
    (cprev1, cprev2) = compute_c_eq3(i-1)
    res1 = 2*(i+1)*(2^b - 1)^2 + cprev1
    res2 = (i+1)*(2^b - 1)^2 + 2 * (2^b - 1) + cprev2
    c1 = res1 // 2^b
    c2 = res2 // 2^b
    return (c1,c2)


def compute_c_eq3_direct(i):
    c1 = (i+1)*2^(b+1) - 2*i - 4
    c2 = (i + 1) * 2^b - i - 1
    return (c1,c2)


print([compute_c_eq3(i) for i in [0..20]])
print([compute_c_eq3(i) == compute_c_eq3_direct(i) for i in [0..20]])
