package vuln

import (
	"math"
	"strings"
)

// cvss3BaseScore computes a CVSS v3.0/v3.1 base score from a vector string.
// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
func cvss3BaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		metrics[key] = value
	}
	weight := func(metric string, table map[string]float64) (float64, bool) {
		value, ok := table[metrics[metric]]
		return value, ok
	}
	changed := metrics["S"] == "C"
	if metrics["S"] != "U" && !changed {
		return 0, false
	}
	privileges := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		privileges = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	impactTable := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	av, ok1 := weight("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := weight("AC", map[string]float64{"L": 0.77, "H": 0.44})
	pr, ok3 := weight("PR", privileges)
	ui, ok4 := weight("UI", map[string]float64{"N": 0.85, "R": 0.62})
	c, ok5 := weight("C", impactTable)
	i, ok6 := weight("I", impactTable)
	a, ok7 := weight("A", impactTable)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp(math.Min(impact+exploitability, 10)), true
}

// roundUp implements the CVSS v3.1 Roundup function, avoiding floating point drift.
func roundUp(value float64) float64 {
	scaled := int64(math.Round(value * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000
	}
	return (math.Floor(float64(scaled)/10000) + 1) / 10
}
