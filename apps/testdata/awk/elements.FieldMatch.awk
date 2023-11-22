BEGIN { FS="\t" } $6 == "Noble gas" { print $1 }
