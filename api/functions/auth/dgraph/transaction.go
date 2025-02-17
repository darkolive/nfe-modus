package dgraph

import (
	"context"
	"fmt"

	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// Transaction wraps Modus DGraph transaction
type Transaction struct {
	conn string
}

// NewTransaction initializes a new DGraph transaction
func NewTransaction(connectionName string) (*Transaction, error) {
	return &Transaction{conn: connectionName}, nil
}

// Mutate performs a mutation
func (t *Transaction) Mutate(ctx context.Context, mutation string) error {
	_, err := dgraph.ExecuteQuery(t.conn, &dgraph.Query{
		Query: mutation,
	})
	if err != nil {
		return fmt.Errorf("mutation failed: %v", err)
	}

	return nil
}

// Query performs a DGraph query
func (t *Transaction) Query(ctx context.Context, queryStr string) ([]byte, error) {
	resp, err := dgraph.ExecuteQuery(t.conn, &dgraph.Query{
		Query: queryStr,
	})
	if err != nil {
		return nil, fmt.Errorf("query failed: %v", err)
	}

	return []byte(resp.Json), nil
}

// Close is a no-op since we don't maintain any connections
func (t *Transaction) Close() error {
	return nil
}
