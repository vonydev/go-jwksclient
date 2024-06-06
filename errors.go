package jwksclient

type ErrKeysNotFetched struct{}

func (e *ErrKeysNotFetched) Error() string {
	return "keys not fetched"
}
