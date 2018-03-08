package scanners

type Scanner interface {
	Scan(string, int) (bool, error)
}
