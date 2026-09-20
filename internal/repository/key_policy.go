package repository

import (
	"cpa-usage-keeper/internal/cpa/dto/cpaapikeys"
	"cpa-usage-keeper/internal/entities"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"strings"
	"time"
)

func SyncKeyPolicyIdentities(db *gorm.DB, keys []cpaapikeys.PolicyKey, now time.Time) error {
	return db.Transaction(func(tx *gorm.DB) error {
		ids := make([]string, 0, len(keys))
		for _, key := range keys {
			if strings.TrimSpace(key.ID) == "" {
				return fmt.Errorf("empty policy identity")
			}
			var row entities.CPAAPIKey
			err := tx.Where("api_key = ?", key.ID).First(&row).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if err == nil && !row.IsPolicy {
				return fmt.Errorf("policy identity conflicts with native key")
			}
			row.APIKey = key.ID
			row.IsPolicy = true
			row.KeyAlias = key.Name
			row.DisplayKey = "Key Policy"
			row.IsDeleted = false
			row.LastSyncedAt = &now
			if err := tx.Save(&row).Error; err != nil {
				return err
			}
			ids = append(ids, key.ID)
		}
		q := tx.Model(&entities.CPAAPIKey{}).Where("is_policy = ?", true)
		if len(ids) > 0 {
			q = q.Where("api_key NOT IN ?", ids)
		}
		return q.Updates(map[string]any{"is_deleted": true, "updated_at": now}).Error
	})
}
