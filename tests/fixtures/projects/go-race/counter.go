package race

import (
	"fmt"
	"sync"
)

type Counter struct{ n int }

func (c *Counter) Inc() { c.n++ }

// CountTo increments from many goroutines without a lock: a data race.
func CountTo(k int) int {
	c := &Counter{}
	var wg sync.WaitGroup
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Inc() }()
	}
	wg.Wait()
	return c.n
}

func Label(n int) string {
	return fmt.Sprintf("%d items %s", n) // vet: missing argument
}
