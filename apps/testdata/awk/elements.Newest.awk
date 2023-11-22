discovery < $5 { discovery = $5; element = $1 }
END	{ print element, discovery }
