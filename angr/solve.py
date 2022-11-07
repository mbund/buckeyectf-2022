import angr
import sys


def main(argv):
    path_to_binary = "./angry"  # path of the binary program
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    cmp = bytes([0x89, 0xea, 0x8d, 0x6d, 0xac, 0x97, 0xb2, 0xed, 0x6e, 0x1d, 0x24, 0xc6, 0x1b, 0xfa, 0x89, 0x66, 0x1d, 0x8e, 0xcc, 0x27, 0xaf, 0x3a, 0xa1, 0x68, 0x6e, 0xd7, 0xb9, 0xe8, 0x72, 0x99, 0xe4, 0x97, 0xbe, 0x00])

    print_good_address = 0x001013c1  # :integer (probably in hexadecimal)
    simulation.explore(find=print_good_address)

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))

    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main(sys.argv)
