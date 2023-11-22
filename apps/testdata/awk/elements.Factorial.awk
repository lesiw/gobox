function fact(n) {
	if (n <= 1)
		return 1
	else
		return n * fact(n-1)
}
{ print $3 "! is " fact($3) }
