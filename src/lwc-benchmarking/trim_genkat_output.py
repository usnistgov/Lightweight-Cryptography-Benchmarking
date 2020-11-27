import sys


if __name__ == '__main__':
    ''' Remove unnecessary lines from serial monitor outputs of
        KAT capture in order to make it match with the original KAT file.
    '''
    out = False
    with open(sys.argv[1]) as f:
        for line in f.readlines():
            if line.startswith('Count = 1'):
                out = True
            elif line.startswith('# lwc exit'):
                break

            if out:
                print(line, end='')
