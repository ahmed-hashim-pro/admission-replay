package replay

import (
	"sort"
	"strings"
)

// Summary scores a replay.
type Summary struct {
	Replayed int
	Skipped  int
	// FailedBefore counts writes the cluster itself rejected at the time;
	// they are replayed but not counted as blocked or admitted below.
	FailedBefore int

	Blocked      int // legitimate writes the candidate would have denied
	BlockedBySys int // of those, by system: users (controllers and the like)
	Flagged      int // legitimate writes warned or audited but admitted

	Bad       int
	Caught    int // bad writes denied
	BadWarned int // bad writes only warned or audited
	Missed    int // bad writes admitted with nothing said
}

// IsSystem reports whether a username belongs to the cluster itself.
func IsSystem(name string) bool { return strings.HasPrefix(name, "system:") }

// Summarize counts the outcomes.
func (r *Result) Summarize() Summary {
	var s Summary
	for i := range r.Outcomes {
		o := &r.Outcomes[i]
		if o.IsBad {
			s.Bad++
		}
		if o.Skipped != "" {
			s.Skipped++
			if o.IsBad {
				s.Missed++
			}
			continue
		}
		s.Replayed++
		if o.Entry.Failed() && !o.IsBad {
			s.FailedBefore++
			continue
		}
		switch {
		case o.IsBad && o.Verdict.Denied:
			s.Caught++
		case o.IsBad && o.Flagged():
			s.BadWarned++
		case o.IsBad:
			s.Missed++
		case o.Verdict.Denied:
			s.Blocked++
			if IsSystem(o.Entry.User.GetName()) {
				s.BlockedBySys++
			}
		case o.Flagged():
			s.Flagged++
		}
	}
	return s
}

// Count is a label and how often it occurred.
type Count struct {
	Label string
	N     int
}

// BlockReasons counts, over the legitimate writes the candidate would have
// blocked, each failed validation's message. A write that fails two
// validations counts under both.
func (r *Result) BlockReasons() []Count {
	return r.tally(func(o *Outcome) []string {
		if o.IsBad || !o.Blocked() || o.Entry.Failed() {
			return nil
		}
		var out []string
		seen := map[string]bool{}
		for _, f := range o.Verdict.Failures {
			denies := f.Index < 0
			for _, a := range f.Actions {
				denies = denies || a == "Deny"
			}
			if denies && !seen[f.Message] {
				seen[f.Message] = true
				out = append(out, f.Message)
			}
		}
		return out
	})
}

// BlockedUsers counts the users whose legitimate writes would have been blocked.
func (r *Result) BlockedUsers() []Count {
	return r.tally(func(o *Outcome) []string {
		if o.IsBad || !o.Blocked() || o.Entry.Failed() {
			return nil
		}
		return []string{o.Entry.User.GetName()}
	})
}

func (r *Result) tally(keys func(*Outcome) []string) []Count {
	m := map[string]int{}
	for i := range r.Outcomes {
		for _, k := range keys(&r.Outcomes[i]) {
			m[k]++
		}
	}
	out := make([]Count, 0, len(m))
	for k, n := range m {
		out = append(out, Count{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Label < out[j].Label
	})
	return out
}
