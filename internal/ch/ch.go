package ch

// Drain drains a channel.
func Drain[T any](c <-chan T) {
	for {
		select {
		case <-c:
		default:
			return
		}
	}
}
