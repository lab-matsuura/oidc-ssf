package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// txKey is the context key for storing transactions
type txKey struct{}

// BeginTX implements fosite.Transactional
func (s *PostgresStore) BeginTX(ctx context.Context) (context.Context, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, txKey{}, tx), nil
}

// CommitTX implements fosite.Transactional
func (s *PostgresStore) CommitTX(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	if !ok {
		return errors.New("no transaction in context")
	}
	return tx.Commit(ctx)
}

// RollbackTX implements fosite.Transactional
func (s *PostgresStore) RollbackTX(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	if !ok {
		return errors.New("no transaction in context")
	}
	return tx.Rollback(ctx)
}
