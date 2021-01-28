import hashlib
import sys

# This script generates the round constants and MDS matrices for poseidon for the tweedle fields

pasta_p = 28948022309329048855892746252171976963363056481941560715954676764349967630337
pasta_q = 28948022309329048855892746252171976963363056481941647379679742748393362948097

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

def caml_matrix_str(of_string_wrap, rows):
    return '[|' + ';'.join('[|' + ';'.join(of_string_wrap('"{}"'.format(str(x))) for x in row) + '|]' for row in rows) + '|]'

def rust_matrix_str(of_string_wrap, rows):
    return 'vec![' + ','.join('vec![' + ','.join(of_string_wrap('"{}"'.format(str(x))) for x in row) + ']' for row in rows) + ']'

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

def caml_rc_str(of_string_wrap, rows):
    return '[|' + ';'.join('[|' + ';'.join(of_string_wrap('"{}"'.format(str(x))) for x in row) + '|]' for row in rows) + '|]'

def rust_rc_str(of_string_wrap, rows):
    return 'vec![' + ','.join('vec![' + ','.join(of_string_wrap('"{}"'.format(str(x))) for x in row) + ']' for row in rows) + ']'

print ("type 'a t = { mds: 'a array array; round_constants: 'a array array }")

if len(sys.argv) > 1 and sys.argv[1] == 'caml':
  for name, r in  [ ('Pasta_p', pasta_p), ('Pasta_q', pasta_q) ]:
      wrap = lambda x: x
      F = FiniteField(r)
      print ('let params_{} = '.format(name)
              + '{ mds=' + caml_matrix_str(wrap, mds(F)) + ';'
              + 'round_constants= ' + caml_rc_str(wrap, round_constants(name, F))
              + '}' )
else:
  for letter, r in  [ ('p', pasta_p), ('q', pasta_q) ]:
      name = 'Pasta_' + letter
      wrap = lambda x: 'F{}::from_str({}).unwrap()'.format(letter, x)
      F = FiniteField(r)
      print ('let params_{} = '.format(name)
              + 'ArithmeticSpongeParams { mds:' + rust_matrix_str(wrap, mds(F)) + ','
              + 'round_constants: ' + rust_rc_str(wrap, round_constants(name, F))
              + '}' )
