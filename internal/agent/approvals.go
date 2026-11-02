package agent

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"entowire.com/ento/internal/api"
)

// Sign-in approvals (see the control package): this device asks that a person approve a sign-in
// on it from another of their devices, or answers such a request as an approving device. The calls
// are signed with this device's key.

// RequestApproval asks for a sign-in approval of user on service: the number to show comes back.
func RequestApproval(ctx context.Context, cfg Config, user, service string, timeout time.Duration) (api.ApprovalResponse, error) {
	var res api.ApprovalResponse
	c, err := ownClient(cfg)
	if err != nil {
		return res, err
	}
	err = c.Do(ctx, "POST", api.PathApprovals, api.ApprovalRequest{User: user, Service: service,
		TimeoutSeconds: int(timeout.Seconds()), BootID: bootID()}, &res)
	return res, err
}

// WaitApproval waits until an approval this device asked for is answered or expires (its state:
// approved, denied, expired), or until ctx ends.
func WaitApproval(ctx context.Context, cfg Config, id string) (string, error) {
	c, err := ownClient(cfg)
	if err != nil {
		return "", err
	}
	for {
		var st api.ApprovalStatus
		if err := c.Do(ctx, "GET", api.PathApprovals+"/"+url.PathEscape(id)+"?wait=25", nil, &st); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if code := HTTPStatus(err); code != 0 {
				return "", err
			}
			// The control node went away (failover): ask another after a moment.
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		if st.State != "pending" {
			return st.State, nil
		}
	}
}

// PendingApprovals returns the approvals waiting for this device's person, waiting up to wait for
// one (at most 25 seconds).
func PendingApprovals(ctx context.Context, cfg Config, wait time.Duration) ([]api.PendingApproval, error) {
	c, err := ownClient(cfg)
	if err != nil {
		return nil, err
	}
	var out []api.PendingApproval
	err = c.Do(ctx, "GET", fmt.Sprintf("%s?wait=%d", api.PathApprovals, int(wait.Seconds())), nil, &out)
	return out, err
}

// AnswerApproval answers an approval: the number picked, and whether the person approves. It
// returns the approval's state (denied when the number is not the one the asking device shows).
func AnswerApproval(ctx context.Context, cfg Config, id string, number int, approve bool) (string, error) {
	c, err := ownClient(cfg)
	if err != nil {
		return "", err
	}
	var st api.ApprovalStatus
	err = c.Do(ctx, "POST", api.PathApprovals+"/"+url.PathEscape(id), api.ApprovalAnswer{Number: number, Approve: approve}, &st)
	return st.State, err
}
