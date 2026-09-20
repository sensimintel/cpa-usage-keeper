package service

import (
	"context"
	"fmt"

	"cpa-usage-keeper/internal/config"
	"cpa-usage-keeper/internal/cpa/dto/cpaapikeys"
	"cpa-usage-keeper/internal/repository"
	"errors"
	"gorm.io/gorm"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyIdentitiesFilterHistoryButCannotAuthenticate(t *testing.T) {
	db, err := repository.OpenDatabase(config.Config{SQLitePath: filepath.Join(t.TempDir(), "policy.db")})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	now := time.Now()
	keys := []cpaapikeys.PolicyKey{{ID: "policy-alice", Name: "Alice"}, {ID: "policy-bob", Name: "Bob"}}
	if err := repository.SyncCPAAPIKeys(db, []string{"native-secret"}, now); err != nil {
		t.Fatal(err)
	}
	if err := repository.SyncKeyPolicyIdentities(db, keys, now); err != nil {
		t.Fatal(err)
	}
	// A later native sync must not hide policy identities.
	if err := repository.SyncCPAAPIKeys(db, []string{"native-secret"}, now); err != nil {
		t.Fatal(err)
	}
	provider := NewCPAAPIKeyService(db)
	rows, err := provider.ListCPAAPIKeys(context.Background())
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	for _, row := range rows {
		if !row.IsPolicy {
			continue
		}
		if _, err := provider.FindActiveCPAAPIKeyByValue(context.Background(), row.APIKey); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("policy ID authenticated: %v", err)
		}
		if _, err := provider.FindActiveCPAAPIKeyByID(context.Background(), row.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("policy session authenticated: %v", err)
		}
		group, err := (&usageService{db: db}).resolveAPIGroupKey(context.Background(), fmt.Sprint(row.ID))
		if err != nil || group != row.APIKey {
			t.Fatalf("wrong history group %q %v", group, err)
		}
	}
	if _, err := provider.FindActiveCPAAPIKeyByValue(context.Background(), "native-secret"); err != nil {
		t.Fatal(err)
	}
	if err := repository.SyncKeyPolicyIdentities(db, keys[:1], now); err != nil {
		t.Fatal(err)
	}
	rows, _ = provider.ListCPAAPIKeys(context.Background())
	if len(rows) != 2 {
		t.Fatal("removed policy identity still listed")
	}
	if err := repository.SyncKeyPolicyIdentities(db, []cpaapikeys.PolicyKey{{ID: "native-secret", Name: "collision"}}, now); err == nil {
		t.Fatal("native credential overwritten")
	}
}
