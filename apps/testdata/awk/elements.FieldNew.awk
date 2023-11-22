BEGIN { FS = OFS = "\t" }
{ $7 = sprintf("%.0f", $4) - $3; print $1, $2, $3, $4, $5, $6, $7 }
