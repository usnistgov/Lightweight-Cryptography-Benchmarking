
import sys

def load_default_sections():
    sections=set()
    with open('chipkit_sections.txt') as f:
        for line in f:
            sections.add(line.strip())
        return sections
            

def process(file, verbose = False):
    """
    Computes the sum of the sizes of the sections in the linker output for
    calculating the code size of an implementation. The section names which do
    not belong to the implementation are loaded by load_default_sections() and
    are is discarded.
    """
    sections = load_default_sections()
    #for s in sections:
    #    print(s)
    processing = False
    codesize = 0
    with open(file) as f:
        for line in f:
            cols = line.split()
            if processing and len(cols) == 3:
                if cols[0] not in sections:
                    codesize += int(cols[1])
                    if verbose:
                        print(f'added {cols[0]} {cols[1]}')
            elif len(cols) == 3 and cols[0] == 'section':
                processing = True
            elif len(cols) == 2 and cols[0] == 'Total':
                break
    return codesize


if __name__ == '__main__':
    if len(sys.argv) != 2:
        progname = sys.argv[0][sys.argv[0].rfind('\\')+1:]
        print(f'Usage: {progname} filename')
    else:
        codesize = process(sys.argv[1])
        print(codesize)
