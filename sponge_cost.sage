import math

def grobner_complexity(state_size, alpha, rounds_full, rounds_partial):
    num_vars = (state_size - 1) * rounds_full + rounds_partial
    num_equations = num_vars
    d_reg = (1 + num_equations * (alpha - 1)) // 2
    return math.log(binomial(num_vars + d_reg, d_reg) ** 2, 2)

security = 128

def interpolation_rounds_lower_bound(state_size, alpha):
    return 1 + security * math.log(2, alpha) + math.log(state_size, alpha)

rounds_full = 8
rounds_partial = 25
state_size = 3 # the state size
alpha = 17

assert (rounds_full + rounds_partial >= interpolation_rounds_lower_bound(state_size, alpha))
assert (security <= grobner_complexity(state_size, alpha, rounds_full, rounds_partial))
