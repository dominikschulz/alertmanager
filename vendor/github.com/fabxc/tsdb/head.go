package tsdb

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bradfitz/slice"
	"github.com/fabxc/tsdb/chunks"
	"github.com/fabxc/tsdb/labels"
	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
)

var (
	// ErrNotFound is returned if a looked up resource was not found.
	ErrNotFound = fmt.Errorf("not found")

	// ErrOutOfOrderSample is returned if an appended sample has a
	// timestamp larger than the most recent sample.
	ErrOutOfOrderSample = errors.New("out of order sample")

	// ErrAmendSample is returned if an appended sample has the same timestamp
	// as the most recent sample but a different value.
	ErrAmendSample = errors.New("amending sample")

	// ErrOutOfBounds is returned if an appended sample is out of the
	// writable time range.
	ErrOutOfBounds = errors.New("out of bounds")
)

// headBlock handles reads and writes of time series data within a time window.
type headBlock struct {
	mtx        sync.RWMutex
	dir        string
	generation uint8
	wal        *WAL

	activeWriters uint64

	symbols map[string]struct{}
	// descs holds all chunk descs for the head block. Each chunk implicitly
	// is assigned the index as its ID.
	series []*memSeries
	// mapping maps a series ID to its position in an ordered list
	// of all series. The orderDirty flag indicates that it has gone stale.
	mapper *positionMapper
	// hashes contains a collision map of label set hashes of chunks
	// to their chunk descs.
	hashes map[uint64][]*memSeries

	values   map[string]stringset // label names to possible values
	postings *memPostings         // postings lists for terms

	metamtx sync.RWMutex
	meta    BlockMeta
}

func createHeadBlock(dir string, seq int, l log.Logger, mint, maxt int64) (*headBlock, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	if err := writeMetaFile(dir, &BlockMeta{
		Sequence: seq,
		MinTime:  mint,
		MaxTime:  maxt,
	}); err != nil {
		return nil, err
	}
	return openHeadBlock(dir, l)
}

// openHeadBlock creates a new empty head block.
func openHeadBlock(dir string, l log.Logger) (*headBlock, error) {
	wal, err := OpenWAL(dir, log.NewContext(l).With("component", "wal"), 5*time.Second)
	if err != nil {
		return nil, err
	}
	meta, err := readMetaFile(dir)
	if err != nil {
		return nil, err
	}

	h := &headBlock{
		dir:      dir,
		wal:      wal,
		series:   []*memSeries{},
		hashes:   map[uint64][]*memSeries{},
		values:   map[string]stringset{},
		postings: &memPostings{m: make(map[term][]uint32)},
		mapper:   newPositionMapper(nil),
		meta:     *meta,
	}

	r := wal.Reader()

	for r.Next() {
		series, samples := r.At()

		for _, lset := range series {
			h.create(lset.Hash(), lset)
			h.meta.Stats.NumSeries++
		}
		for _, s := range samples {
			h.series[s.ref].append(s.t, s.v)

			if !h.inBounds(s.t) {
				return nil, errors.Wrap(ErrOutOfBounds, "consume WAL")
			}
			h.meta.Stats.NumSamples++
		}
	}
	if err := r.Err(); err != nil {
		return nil, errors.Wrap(err, "consume WAL")
	}

	h.updateMapping()

	return h, nil
}

// inBounds returns true if the given timestamp is within the valid
// time bounds of the block.
func (h *headBlock) inBounds(t int64) bool {
	return t >= h.meta.MinTime && t <= h.meta.MaxTime
}

// Close syncs all data and closes underlying resources of the head block.
func (h *headBlock) Close() error {
	if err := writeMetaFile(h.dir, &h.meta); err != nil {
		return err
	}
	return h.wal.Close()
}

func (h *headBlock) Meta() BlockMeta {
	h.metamtx.RLock()
	defer h.metamtx.RUnlock()

	return h.meta
}

func (h *headBlock) Dir() string          { return h.dir }
func (h *headBlock) Persisted() bool      { return false }
func (h *headBlock) Index() IndexReader   { return &headIndexReader{h} }
func (h *headBlock) Series() SeriesReader { return &headSeriesReader{h} }

func (h *headBlock) Appender() Appender {
	atomic.AddUint64(&h.activeWriters, 1)

	h.mtx.RLock()
	return &headAppender{headBlock: h, samples: getHeadAppendBuffer()}
}

var headPool = sync.Pool{}

func getHeadAppendBuffer() []refdSample {
	b := headPool.Get()
	if b == nil {
		return make([]refdSample, 0, 512)
	}
	return b.([]refdSample)
}

func putHeadAppendBuffer(b []refdSample) {
	headPool.Put(b[:0])
}

type headAppender struct {
	*headBlock

	newSeries map[uint64]hashedLabels
	newHashes map[uint64]uint64
	refmap    map[uint64]uint64
	newLabels []labels.Labels

	samples []refdSample
}

type hashedLabels struct {
	hash   uint64
	labels labels.Labels
}

type refdSample struct {
	ref uint64
	t   int64
	v   float64
}

func (a *headAppender) Add(lset labels.Labels, t int64, v float64) (uint64, error) {
	return a.hashedAdd(lset.Hash(), lset, t, v)
}

func (a *headAppender) hashedAdd(hash uint64, lset labels.Labels, t int64, v float64) (uint64, error) {
	if ms := a.get(hash, lset); ms != nil {
		return uint64(ms.ref), a.AddFast(uint64(ms.ref), t, v)
	}
	if ref, ok := a.newHashes[hash]; ok {
		return uint64(ref), a.AddFast(uint64(ref), t, v)
	}

	// We only know the actual reference after committing. We generate an
	// intermediate reference only valid for this batch.
	// It is indicated by the the LSB of the 4th byte being set to 1.
	// We use a random ID to avoid collisions when new series are created
	// in two subsequent batches.
	// TODO(fabxc): Provide method for client to determine whether a ref
	// is valid beyond the current transaction.
	ref := uint64(rand.Int31()) | (1 << 32)

	if a.newSeries == nil {
		a.newSeries = map[uint64]hashedLabels{}
		a.newHashes = map[uint64]uint64{}
		a.refmap = map[uint64]uint64{}
	}
	a.newSeries[ref] = hashedLabels{hash: hash, labels: lset}
	a.newHashes[hash] = ref

	return ref, a.AddFast(ref, t, v)
}

func (a *headAppender) AddFast(ref uint64, t int64, v float64) error {
	// We only own the last 5 bytes of the reference. Anything before is
	// used by higher-order appenders. We erase it to avoid issues.
	ref = (ref << 24) >> 24

	// Distinguish between existing series and series created in
	// this transaction.
	if ref&(1<<32) != 0 {
		if _, ok := a.newSeries[ref]; !ok {
			return ErrNotFound
		}
		// TODO(fabxc): we also have to validate here that the
		// sample sequence is valid.
		// We also have to revalidate it as we switch locks an create
		// the new series.
	} else {
		ms := a.series[int(ref)]
		if ms == nil {
			return ErrNotFound
		}
		// TODO(fabxc): memory series should be locked here already.
		// Only problem is release of locks in case of a rollback.
		c := ms.head()

		if !a.inBounds(t) {
			return ErrOutOfBounds
		}
		if t < c.maxTime {
			return ErrOutOfOrderSample
		}
		if c.maxTime == t && ms.lastValue != v {
			return ErrAmendSample
		}
	}

	a.samples = append(a.samples, refdSample{
		ref: ref,
		t:   t,
		v:   v,
	})
	return nil
}

func (a *headAppender) createSeries() {
	if len(a.newSeries) == 0 {
		return
	}
	a.newLabels = make([]labels.Labels, 0, len(a.newSeries))
	base0 := len(a.series)

	a.mtx.RUnlock()
	a.mtx.Lock()

	base1 := len(a.series)

	for ref, l := range a.newSeries {
		// We switched locks and have to re-validate that the series were not
		// created by another goroutine in the meantime.
		if base1 > base0 {
			if ms := a.get(l.hash, l.labels); ms != nil {
				a.refmap[ref] = uint64(ms.ref)
				continue
			}
		}
		// Series is still new.
		a.newLabels = append(a.newLabels, l.labels)
		a.refmap[ref] = uint64(len(a.series))

		a.create(l.hash, l.labels)
	}

	a.mtx.Unlock()
	a.mtx.RLock()
}

func (a *headAppender) Commit() error {
	defer atomic.AddUint64(&a.activeWriters, ^uint64(0))
	defer putHeadAppendBuffer(a.samples)

	a.createSeries()

	for i := range a.samples {
		s := &a.samples[i]

		if s.ref&(1<<32) > 0 {
			s.ref = a.refmap[s.ref]
		}
	}

	// Write all new series and samples to the WAL and add it to the
	// in-mem database on success.
	if err := a.wal.Log(a.newLabels, a.samples); err != nil {
		a.mtx.RUnlock()
		return err
	}

	var (
		total = uint64(len(a.samples))
		mint  = int64(math.MaxInt64)
		maxt  = int64(math.MinInt64)
	)

	for _, s := range a.samples {
		if !a.series[s.ref].append(s.t, s.v) {
			total--
		}

		if s.t < mint {
			mint = s.t
		}
		if s.t > maxt {
			maxt = s.t
		}
	}

	a.mtx.RUnlock()

	a.metamtx.Lock()
	defer a.metamtx.Unlock()

	a.meta.Stats.NumSamples += total
	a.meta.Stats.NumSeries += uint64(len(a.newSeries))

	return nil
}

func (a *headAppender) Rollback() error {
	a.mtx.RUnlock()
	atomic.AddUint64(&a.activeWriters, ^uint64(0))
	putHeadAppendBuffer(a.samples)
	return nil
}

type headSeriesReader struct {
	*headBlock
}

// Chunk returns the chunk for the reference number.
func (h *headSeriesReader) Chunk(ref uint64) (chunks.Chunk, error) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	si := ref >> 32
	ci := (ref << 32) >> 32

	c := &safeChunk{
		Chunk: h.series[si].chunks[ci].chunk,
		s:     h.series[si],
		i:     int(ci),
	}
	return c, nil
}

type safeChunk struct {
	chunks.Chunk
	s *memSeries
	i int
}

func (c *safeChunk) Iterator() chunks.Iterator {
	c.s.mtx.RLock()
	defer c.s.mtx.RUnlock()
	return c.s.iterator(c.i)
}

// func (c *safeChunk) Appender() (chunks.Appender, error) { panic("illegal") }
// func (c *safeChunk) Bytes() []byte                      { panic("illegal") }
// func (c *safeChunk) Encoding() chunks.Encoding          { panic("illegal") }

type headIndexReader struct {
	*headBlock
}

// LabelValues returns the possible label values
func (h *headIndexReader) LabelValues(names ...string) (StringTuples, error) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	if len(names) != 1 {
		return nil, errInvalidSize
	}
	var sl []string

	for s := range h.values[names[0]] {
		sl = append(sl, s)
	}
	sort.Strings(sl)

	return &stringTuples{l: len(names), s: sl}, nil
}

// Postings returns the postings list iterator for the label pair.
func (h *headIndexReader) Postings(name, value string) (Postings, error) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	return h.postings.get(term{name: name, value: value}), nil
}

// Series returns the series for the given reference.
func (h *headIndexReader) Series(ref uint32) (labels.Labels, []ChunkMeta, error) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	if int(ref) >= len(h.series) {
		return nil, nil, ErrNotFound
	}
	s := h.series[ref]
	metas := make([]ChunkMeta, 0, len(s.chunks))

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	for i, c := range s.chunks {
		metas = append(metas, ChunkMeta{
			MinTime: c.minTime,
			MaxTime: c.maxTime,
			Ref:     (uint64(ref) << 32) | uint64(i),
		})
	}

	return s.lset, metas, nil
}

func (h *headIndexReader) LabelIndices() ([][]string, error) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	res := [][]string{}

	for s := range h.values {
		res = append(res, []string{s})
	}
	return res, nil
}

// get retrieves the chunk with the hash and label set and creates
// a new one if it doesn't exist yet.
func (h *headBlock) get(hash uint64, lset labels.Labels) *memSeries {
	series := h.hashes[hash]

	for _, s := range series {
		if s.lset.Equals(lset) {
			return s
		}
	}
	return nil
}

func (h *headBlock) create(hash uint64, lset labels.Labels) *memSeries {
	s := &memSeries{
		lset: lset,
		ref:  uint32(len(h.series)),
	}

	// Allocate empty space until we can insert at the given index.
	h.series = append(h.series, s)

	h.hashes[hash] = append(h.hashes[hash], s)

	for _, l := range lset {
		valset, ok := h.values[l.Name]
		if !ok {
			valset = stringset{}
			h.values[l.Name] = valset
		}
		valset.set(l.Value)

		h.postings.add(s.ref, term{name: l.Name, value: l.Value})
	}

	h.postings.add(s.ref, term{})

	return s
}

func (h *headBlock) fullness() float64 {
	h.metamtx.RLock()
	defer h.metamtx.RUnlock()

	return float64(h.meta.Stats.NumSamples) / float64(h.meta.Stats.NumSeries+1) / 250
}

func (h *headBlock) updateMapping() {
	h.mtx.RLock()

	if h.mapper.sortable != nil && h.mapper.Len() == len(h.series) {
		h.mtx.RUnlock()
		return
	}

	series := make([]*memSeries, len(h.series))
	copy(series, h.series)

	h.mtx.RUnlock()

	s := slice.SortInterface(series, func(i, j int) bool {
		return labels.Compare(series[i].lset, series[j].lset) < 0
	})

	h.mapper.update(s)
}

// remapPostings changes the order of the postings from their ID to the ordering
// of the series they reference.
// Returned postings have no longer monotonic IDs and MUST NOT be used for regular
// postings set operations, i.e. intersect and merge.
func (h *headBlock) remapPostings(p Postings) Postings {
	list, err := expandPostings(p)
	if err != nil {
		return errPostings{err: err}
	}

	h.mapper.mtx.Lock()
	defer h.mapper.mtx.Unlock()

	h.updateMapping()
	h.mapper.Sort(list)

	return newListPostings(list)
}

type memSeries struct {
	mtx sync.RWMutex

	ref    uint32
	lset   labels.Labels
	chunks []*memChunk

	lastValue float64
	sampleBuf [4]sample

	app chunks.Appender // Current appender for the chunkdb.
}

func (s *memSeries) cut() *memChunk {
	c := &memChunk{
		chunk:   chunks.NewXORChunk(),
		maxTime: math.MinInt64,
	}
	s.chunks = append(s.chunks, c)

	app, err := c.chunk.Appender()
	if err != nil {
		panic(err)
	}

	s.app = app
	return c
}

func (s *memSeries) append(t int64, v float64) bool {
	var c *memChunk

	if s.app == nil || s.head().samples > 2000 {
		c = s.cut()
		c.minTime = t
	} else {
		c = s.head()
		// Skip duplicate samples.
		if c.maxTime == t && s.lastValue != v {
			return false
		}
	}
	s.app.Append(t, v)

	c.maxTime = t
	c.samples++

	s.lastValue = v

	s.sampleBuf[0] = s.sampleBuf[1]
	s.sampleBuf[1] = s.sampleBuf[2]
	s.sampleBuf[2] = s.sampleBuf[3]
	s.sampleBuf[3] = sample{t: t, v: v}

	return true
}

func (s *memSeries) iterator(i int) chunks.Iterator {
	c := s.chunks[i]

	if i < len(s.chunks)-1 {
		return c.chunk.Iterator()
	}

	it := &memSafeIterator{
		Iterator: c.chunk.Iterator(),
		i:        -1,
		total:    c.samples,
		buf:      s.sampleBuf,
	}
	return it
}

func (s *memSeries) head() *memChunk {
	return s.chunks[len(s.chunks)-1]
}

type memChunk struct {
	chunk            chunks.Chunk
	minTime, maxTime int64
	samples          int
}

type memSafeIterator struct {
	chunks.Iterator

	i     int
	total int
	buf   [4]sample
}

func (it *memSafeIterator) Next() bool {
	if it.i+1 >= it.total {
		return false
	}
	it.i++
	if it.total-it.i > 4 {
		return it.Iterator.Next()
	}
	return true
}

func (it *memSafeIterator) At() (int64, float64) {
	if it.total-it.i > 4 {
		return it.Iterator.At()
	}
	s := it.buf[4-(it.total-it.i)]
	return s.t, s.v
}

// positionMapper stores a position mapping from unsorted to
// sorted indices of a sortable collection.
type positionMapper struct {
	mtx      sync.RWMutex
	sortable sort.Interface
	iv, fw   []int
}

func newPositionMapper(s sort.Interface) *positionMapper {
	m := &positionMapper{}
	if s != nil {
		m.update(s)
	}
	return m
}

func (m *positionMapper) Len() int           { return m.sortable.Len() }
func (m *positionMapper) Less(i, j int) bool { return m.sortable.Less(i, j) }

func (m *positionMapper) Swap(i, j int) {
	m.sortable.Swap(i, j)

	m.iv[i], m.iv[j] = m.iv[j], m.iv[i]
}

func (m *positionMapper) Sort(l []uint32) {
	slice.Sort(l, func(i, j int) bool {
		return m.fw[l[i]] < m.fw[l[j]]
	})
}

func (m *positionMapper) update(s sort.Interface) {
	m.sortable = s

	m.iv = make([]int, s.Len())
	m.fw = make([]int, s.Len())

	for i := range m.iv {
		m.iv[i] = i
	}
	sort.Sort(m)

	for i, k := range m.iv {
		m.fw[k] = i
	}
}
