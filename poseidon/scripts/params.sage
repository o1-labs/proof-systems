#!/usr/bin/env sage

import hashlib
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('language', choices=['ocaml', 'rust'], help='Target language (e.g. ocaml or rust)')
parser.add_argument('width', type=int, default=3, help='Width of sponge (e.g. 3)')
parser.add_argument('name', type=str, help='Name of parameter set (e.g. \'\', 5 or 3wa7)')
parser.add_argument('--rounds', type=int, default=100, help='Number of round constants')
args = parser.parse_args()

# FIXME: This is a hack to make the script work for BN254. We should generalize the script later.
# BN254/Grumpkin ("Ethereum" curves)
## BN254 Base field
_bn254_q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
## BN254 Scalar field
_bn254_p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

# Pasta (Pallas/Vesta) curves
_pasta_p = 28948022309329048855892746252171976963363056481941560715954676764349967630337
_pasta_q = 28948022309329048855892746252171976963363056481941647379679742748393362948097

def random_value(F, prefix, i):
  r = F.order()
  j = 0
  while True:
    x = int(hashlib.sha256("{}{}_{}".format(prefix, i, j).encode('utf-8')).hexdigest(), 16)
    if x < r:
      return F(x)
    j += 1

_prefix        = 'CodaRescue'
_width         = args.width
_rounds        = args.rounds
_legacy        = args.name == ''
_instance_name = '_' + args.name
_params        = [ ('p', _pasta_p), ('q', _pasta_q) ]

if _legacy:
  # Backward compatibility for generating the original 3- and 5-wire poseidon
  # parameters, before it was decided each instance of the cryptographic hash
  # function should have a unique round constants and mds.
  if args.width == 3:
    _instance_name = ''
  elif args.width == 5:
    _instance_name = '5'
  else:
    print("Instance name required (use --name option)")
    sys.exit()

def round_constants(prefix, F):
  prefix = (prefix if _legacy else _prefix + prefix) + 'RoundConstants'
  return [ [ random_value(F, prefix, r * _width + i) for i in range(_width) ]
            for r in range( _rounds ) ]

def caml_matrix_str(of_string_wrap, rows):
  return '[|' + ';'.join('[|' + ';'.join(of_string_wrap('"{}"'.format(str(x))) for x in row) + '|]' for row in rows) + '|]'

def rust_matrix_str(of_string_wrap, rows):
  return 'vec![' + ','.join('vec![' + ','.join(of_string_wrap('"{}"'.format(str(x))) for x in row) + ']' for row in rows) + ']'

def mds(prefix, F):
  prefix = _prefix + ('' if _legacy else prefix) + 'MDS'
  for attempt in range(100):
    x_values = [random_value(F, prefix + 'x', attempt * _width + i)
                for i in range(_width)]
    y_values = [random_value(F, prefix + 'y', attempt * _width + i)
                for i in range(_width)]

    # Make sure the values are distinct.
    assert len(set(x_values + y_values)) == 2 * _width, \
      'The values of x_values and y_values are not distinct'

    mds = matrix([[1 / (x_values[i] - y_values[j]) for j in range(_width)]
                    for i in range(_width)])

    # Sanity check: check the determinant of the matrix.
    x_prod = product(
      [x_values[i] - x_values[j] for i in range(_width) for j in range(i)])
    y_prod = product(
      [y_values[i] - y_values[j] for i in range(_width) for j in range(i)])
    xy_prod = product(
      [x_values[i] - y_values[j] for i in range(_width) for j in range(_width)])
    expected_det = (1 if _width % 4 < 2 else -1) * x_prod * y_prod / xy_prod
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

if args.language == 'ocaml':
  print ("type 'a t = { mds: 'a array array; round_constants: 'a array array }")
  for letter, order in _params:
    prefix = "Pasta_" + letter + _instance_name
    wrap = lambda x: x
    F = FiniteField(order)
    print ('let params_{} = '.format(prefix)
            + '{ mds=' + caml_matrix_str(wrap, mds(prefix, F)) + ';'
            + 'round_constants= ' + caml_rc_str(wrap, round_constants(prefix, F))
            + '}' )
elif args.language == "rust":
  for letter, order in _params:
    prefix = 'Pasta_' + letter + _instance_name
    wrap = lambda x: 'F{}::from_str({}).unwrap()'.format(letter, x)
    F = FiniteField(order)
    print ('let params_{} = '.format(prefix)
            + 'ArithmeticSpongeParams { mds:' + rust_matrix_str(wrap, mds(prefix, F)) + ','
            + 'round_constants: ' + rust_rc_str(wrap, round_constants(prefix, F))
            + '}' )
