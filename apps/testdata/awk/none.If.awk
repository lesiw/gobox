BEGIN {
    if (1) {
        print("if1")
    }
    if (1)
        print("if2")
    if (1) print("if3")
    if (1) { print("if4") }
    if (0)
        print("if5")
    print("not if")
}
