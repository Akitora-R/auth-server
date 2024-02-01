package util

func Must[T any](d T, err error) T {
	if err != nil {
		panic(err)
	}
	return d
}
