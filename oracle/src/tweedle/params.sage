import hashlib

# This script generates the round constants and MDS matrices for poseidon for the tweedle fields

tweedle_p = 2^254 + 4707489545178046908921067385359695873
tweedle_q = 2^254 + 4707489544292117082687961190295928833

def random_value(F, prefix, i):
    r = F.order()
    j = 0
    while True:
        x = int(hashlib.sha256('%s%d_%d' % (prefix, i, j)).hexdigest(), 16)
        if x < r:
            return F(x)
        j += 1

m = 3
rounds = 100

prefix = 'CodaRescue'

def round_constants(prefix, F):
    name = prefix + 'RoundConstants'
    return [ [ random_value(F, name, r * m + i) for i in xrange(m) ]
            for r in xrange( rounds ) ]

def matrix_str(of_string_wrap, rows):
    return '[|' + ';'.join('[|' + ';'.join(of_string_wrap('"{}"'.format(str(x))) for x in row) + '|]' for row in rows) + '|]'

def mds(F):
    name = prefix + 'MDS'
    for attempt in xrange(100):
        x_values = [random_value(F, name + 'x', attempt * m + i)
                    for i in xrange(m)]
        y_values = [random_value(F, name + 'y', attempt * m + i)
                    for i in xrange(m)]
# Make sure the values are distinct.
        assert len(set(x_values + y_values)) == 2 * m, \
            'The values of x_values and y_values are not distinct'
        mds = matrix([[1 / (x_values[i] - y_values[j]) for j in xrange(m)]
                        for i in xrange(m)])
# Sanity check: check the determinant of the matrix.
        x_prod = product(
            [x_values[i] - x_values[j] for i in xrange(m) for j in xrange(i)])
        y_prod = product(
            [y_values[i] - y_values[j] for i in xrange(m) for j in xrange(i)])
        xy_prod = product(
            [x_values[i] - y_values[j] for i in xrange(m) for j in xrange(m)])
        expected_det = (1 if m % 4 < 2 else -1) * x_prod * y_prod / xy_prod
        det = mds.determinant()
        assert det != 0
        assert det == expected_det, \
            'Expected determinant %s. Found %s' % (expected_det, det)
        if len(mds.characteristic_polynomial().roots()) == 0:
            # There are no eigenvalues in the field.
            return mds

def rc_str(of_string_wrap, rows):
    return '[|' + ';'.join('[|' + ';'.join(of_string_wrap('"{}"'.format(str(x))) for x in row) + '|]' for row in rows) + '|]'

print ("type 'a t = { mds: 'a array array; round_constants: 'a array array }")

for name, r in  [ ('Tweedle_p', tweedle_p), ('Tweedle_q', tweedle_q) ]:
    wrap = lambda x: x
    F = FiniteField(r)
    print ('let params_{} = '.format(name)
            + '{ mds=' + matrix_str(wrap, mds(F)) + ';'
            + 'round_constants= ' + rc_str(wrap, round_constants(name, F))
            + '}' )
