package globacl

import (
	"encoding/json"
	"testing"
)

func TestCommitOutcomeResponseDecodesUint64Hashes(t *testing.T) {
	const keyHash uint64 = 15758513741689562926
	const ruleHash uint64 = 18446744073709551615

	payload := []byte(`{"key_hash":15758513741689562926,"rule_hash":18446744073709551615}`)

	var outcome CommitOutcomeResponse
	if err := json.Unmarshal(payload, &outcome); err != nil {
		t.Fatalf("unmarshal commit outcome: %v", err)
	}
	if outcome.KeyHash != keyHash {
		t.Fatalf("key_hash = %d, want %d", outcome.KeyHash, keyHash)
	}
	if outcome.RuleHash == nil {
		t.Fatal("rule_hash was nil")
	}
	if *outcome.RuleHash != ruleHash {
		t.Fatalf("rule_hash = %d, want %d", *outcome.RuleHash, ruleHash)
	}
}
