package hrproxy

// BufferPool implements a pool of bytes.Buffers in the form of a bounded
// channel.
type BufferPool struct {
	c       chan []byte
	bufsize int
}

// NewBufferPool creates a new BufferPool bounded to the given size.
func NewBufferPool(capacity, bufsize int) (bp *BufferPool) {
	return &BufferPool{
		c:       make(chan []byte, capacity),
		bufsize: bufsize,
	}
}

// Get gets a Buffer from the BufferPool, or creates a new one if none are
// available in the pool.
func (bp *BufferPool) Get() (b []byte) {
	select {
	case b = <-bp.c:
	// reuse existing buffer
	default:
		// create new buffer
		b = make([]byte, bp.bufsize, bp.bufsize)
	}
	return
}

// Put returns the given Buffer to the BufferPool.
func (bp *BufferPool) Put(b []byte) {
	select {
	case bp.c <- b:
	default: // Discard the buffer if the pool is full.
	}
}
