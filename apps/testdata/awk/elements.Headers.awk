BEGIN { FS = "\t"
	printf "%10s %6s %6s %10s\n", "NAME", "SYMBOL", "NUMBER", "MASS" }
	{ printf "%10s %6s %6d %10f\n", $1, $2, $3, $4 }
