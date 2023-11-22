BEGIN { printf "%10s %7s %8s\n", "ELEMENT", "PROTONS", "NEUTRONS" }
{ printf "%10s %7d %8d\n", $1, $3, sprintf("%.0f", $4) - $3 }
