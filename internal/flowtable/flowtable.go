package flowtable

import (
    "log"
    "sync"
    "time"

	"ReBPF/internal/timer"
)

type FlowTable struct {
    Ticker *time.Ticker
    sync.Map
}

func NewFlowTable() *FlowTable {
    return &FlowTable{Ticker: time.NewTicker(time.Second * 10)}
}

func (table *FlowTable) Insert(hash, timestamp uint64) {
    table.Store(hash, timestamp)
}

func (table *FlowTable) Get(hash uint64) (uint64, bool) {
    value, ok := table.Load(hash)

    if !ok {
        return 0, ok
    }
    return value.(uint64), ok
}

func (table *FlowTable) Remove(hash uint64) {
    _, found := table.Load(hash)

    if found {
        table.Delete(hash)
    } else {
        log.Printf("hash %v is not in flow table", hash)
    }
}

func (table *FlowTable) Prune() {
    now := timer.GetNanosecSinceBoot()

    table.Range(func(hash, timestamp interface{}) bool {
        if (now-timestamp.(uint64))/1000000 > 10000 {
            log.Printf("Pruning stale entry from flow table: %v", hash)

            table.Delete(hash)

            return true
        }
        return false
    })
}

func (table *FlowTable) Entries() int {
    count := 0
    table.Range(func(_, _ interface{}) bool {
        count++
        return true
    })
    return count
}