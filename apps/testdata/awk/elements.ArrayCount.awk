/Noble gas/ { type["noble"]++ }
/nonmetal/ { type["nonmetal"]++ }
END {
    print "Noble gasses:", type["noble"]
    print "Nonmetals:", type["nonmetal"]
}
