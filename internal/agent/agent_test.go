package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The watchdog state machine is what keeps a locked-out node recoverable;
// these tests pin its decisions without touching the network.

func TestWatchdogRollsBackUnverifiedConfig(t *testing.T) {
	dir := t.TempDir()
	// A conf file marks an interface as managed; no real device exists, so
	// teardown logs and moves on.
	os.WriteFile(filepath.Join(dir, "wg0.conf"), []byte("[Interface]\n"), 0o600)

	a := &Agent{confDir: dir, verifyTimeout: 180 * time.Second}
	a.appliedVer = 7
	a.verifying = true
	a.pendingSince = time.Now().Add(-200 * time.Second) // past the deadline

	a.checkWatchdog()

	if a.quarantinedVer != 7 {
		t.Errorf("quarantinedVer = %d, want 7", a.quarantinedVer)
	}
	if a.verifying {
		t.Error("verifying should be cleared after rollback")
	}
}

func TestWatchdogDoesNotFireWithinDeadline(t *testing.T) {
	a := &Agent{verifyTimeout: 180 * time.Second, verifying: true, pendingSince: time.Now()}
	a.checkWatchdog()
	if a.quarantinedVer != 0 || !a.verifying {
		t.Error("watchdog fired within the deadline")
	}
}

func TestWatchdogDisabledOrIdle(t *testing.T) {
	// Timeout disabled.
	a := &Agent{verifyTimeout: 0, verifying: true, pendingSince: time.Now().Add(-time.Hour)}
	a.checkWatchdog()
	if a.quarantinedVer != 0 {
		t.Error("disabled watchdog must not fire")
	}
	// Not verifying.
	b := &Agent{verifyTimeout: time.Second, verifying: false}
	b.checkWatchdog()
	if b.quarantinedVer != 0 {
		t.Error("idle watchdog must not fire")
	}
}

func TestQuarantinePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{confDir: dir, verifyTimeout: time.Second, verifying: true, appliedVer: 7}
	a.pendingSince = time.Now().Add(-2 * time.Second)
	a.checkWatchdog() // fires: rollback + save

	if a.quarantinedVer != 7 {
		t.Fatalf("quarantinedVer = %d, want 7", a.quarantinedVer)
	}

	// A "restarted" agent loads the quarantine state from the conf dir.
	b := &Agent{confDir: dir}
	b.loadQuarantine()
	if b.quarantinedVer != 7 {
		t.Errorf("quarantine lost on restart: %d", b.quarantinedVer)
	}

	// Successful apply clears it (file included).
	b.clearQuarantine()
	c := &Agent{confDir: dir}
	c.loadQuarantine()
	if c.quarantinedVer != 0 {
		t.Errorf("quarantine not cleared: %d", c.quarantinedVer)
	}
}

func TestQuarantineRejectsOnlyTheBadVersion(t *testing.T) {
	// Mirrors the gate in PollOnce: quarantined at v7 means exactly v7 stays
	// rejected. Not <=: versions can DROP (deleting the top-version
	// interface lowers the node's MAX), and a fixed config must be allowed
	// to carry a lower number — otherwise the node never recovers.
	a := &Agent{quarantinedVer: 7}
	rejected := func(v int64) bool { return v == a.quarantinedVer }
	if !rejected(7) {
		t.Error("the quarantined version must be rejected")
	}
	if rejected(6) || rejected(8) {
		t.Error("other versions must be allowed (lower included — versions can drop)")
	}
}
