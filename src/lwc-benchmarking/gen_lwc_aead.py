
import sys

modes = ['AEAD_ENCRYPT', 'AEAD_DECRYPT', 'AEAD_BOTH']

def main():
    """ Replace the encrypt/decrypt function pointers in the aead_ctx
        structure with 0 depending on the mode [enc dec both].
        Setting the function pointer to 0 allows the linker to remove the
        function from the executable.
    """
    if len(sys.argv) != 3:
        print('usage : gen_lwc_aead.py filename [AEAD_ENCRYPT | AEAD_DECRYPT | AEAD_BOTH]')
        return

    filename = sys.argv[1]
    mode = sys.argv[2]
    
    if mode not in modes:
        print('unknown mode: %s' % mode)
        return

    with open(filename) as file:
        lines = file.readlines()
        for i in range(len(lines)):
            print(lines[i], end='')
            if '\tCRYPTO_ABYTES,' in lines[i]:
                encstr = '\t0,\n' if mode == 'AEAD_DECRYPT' else lines[i + 1]
                decstr = '\t0\n'  if mode == 'AEAD_ENCRYPT' else lines[i + 2]
                print(encstr, end='')
                print(decstr, end='')
                print('};')
                break
    

if __name__ == '__main__':
    main()
