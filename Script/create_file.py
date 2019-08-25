import sys

USAGE = "usage: *.py <file_name> <size> <K for KB or M for MB>"

# gets size in KB
def create_file(file_name, size):
    with open(file_name, "wb") as out_file:
        while size > 0:
            for j in xrange(10):
                for i in xrange(26):
                    # 1KB
                    if size <= 0:
                        return
                    c = chr(ord('a') + i) + str(j)
                    out_file.write(c * 512)
                    size -= 1

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print USAGE
        sys.exit(1)
    
    size = int(sys.argv[2])
    if sys.argv[3] == 'M':
        size *= 1024
    elif sys.argv[3] != 'K':
        print USAGE
        sys.exit(1)

    create_file(sys.argv[1], size)