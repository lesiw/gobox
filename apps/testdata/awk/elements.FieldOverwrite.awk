BEGIN { FS = OFS = "\t" }
{ $6 = sprintf("%.0f", $4) - $3; print $1, $2, $3, $4, $5, $6 }
