BEGIN {
    while (i < 5) {
        print(++i)
    }
    while (j < 5) {
        print(++j)
        break
    }
    while (k < 5) {
        if (k == 2) {
            k++
            continue
        }
        print(++k)
    }
    while (x < 5) {
        while (y < 5) {
            if (++y > 1) {
                break
            }
        }
        print(++x, y)
    }
}
