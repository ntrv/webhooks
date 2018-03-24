package github

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/ntrv/webhooks"
)

func (hook Webhook) getGitHubEvent(w http.ResponseWriter, r *http.Request) (Event, error) {
	webhooks.DefaultLog.Info("Parsing Payload...")

	event := r.Header.Get("X-GitHub-Event")
	if len(event) == 0 {
		err := errors.New("Missing X-GitHub-Event Header")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, err
	}
	webhooks.DefaultLog.Debug(fmt.Sprintf("X-GitHub-Event:%s", event))
	return Event(event), nil
}

func (hook Webhook) verifySignature(w http.ResponseWriter, r *http.Request) error {
	// If we have a Secret set, we should check the MAC
	if len(hook.secret) > 0 {
		webhooks.DefaultLog.Info("Checking secret")
		signature := r.Header.Get("X-Hub-Signature")
		if len(signature) == 0 {
			err := errors.New("Missing X-Hub-Signature required for HMAC verification")
			webhooks.DefaultLog.Error(err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return err
		}
		webhooks.DefaultLog.Debug(fmt.Sprintf("X-Hub-Signature:%s", signature))

		mac := hmac.New(sha1.New, []byte(hook.secret))
		mac.Write(payload)

		expectedMAC := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(signature[5:]), []byte(expectedMAC)) {
			err := errors.New("HMAC verification failed")
			webhooks.DefaultLog.Error(err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return err
		}
	}
	return nil
}

func (hook Webhook) readPayload(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil || len(payload) == 0 {
		err := errors.New("Issue reading Payload")
		webhooks.DefaultLog.Error(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, err
	}
	webhooks.DefaultLog.Debug(fmt.Sprintf("Payload:%s", string(payload)))
	return payload, nil
}

func getGitHubHandler(event Event) (webhooks.ProcessPayloadFunc, error) {
	fn, ok := hook.eventFuncs[event]
	// if no event registered
	if !ok {
		return nil, fmt.Errorf("Webhook Event %s not registered, it is recommended to setup only events in github that will be registered in the webhook to avoid unnecessary traffic and reduce potential attack vectors.", string(event))
	}
	return fn, nil
}

// ParsePayload parses and verifies the payload and fires off the mapped function, if it exists.
func (hook Webhook) ParsePayload(w http.ResponseWriter, r *http.Request) {
	gitHubEvent, err := getGitHubEvent(w, r)
	if err != nil {
		webhooks.DefaultLog.Error(err.Error())
		return
	}

	fn, err := getGitHubHandler(gitHubEvent)
	if err != nil {
		webhooks.DefaultLog.Error(err.Error())
		return
	}

	if err := verifySignature(w, r); err != nil {
		Webhook.DefaultLog.Debug(err.Error())
		return
	}

	payload, err := readPayload(w, r)
	if err != nil {
		Webhook.DefaultLog.Debug(err.Error())
		return
	}

	// Make headers available to ProcessPayloadFunc as a webhooks type
	hd := webhooks.Header(r.Header)

	switch gitHubEvent {
	case CommitCommentEvent:
		var cc CommitCommentPayload
		json.Unmarshal([]byte(payload), &cc)
		hook.runProcessPayloadFunc(fn, cc, hd)
	case CreateEvent:
		var c CreatePayload
		json.Unmarshal([]byte(payload), &c)
		hook.runProcessPayloadFunc(fn, c, hd)
	case DeleteEvent:
		var d DeletePayload
		json.Unmarshal([]byte(payload), &d)
		hook.runProcessPayloadFunc(fn, d, hd)
	case DeploymentEvent:
		var d DeploymentPayload
		json.Unmarshal([]byte(payload), &d)
		hook.runProcessPayloadFunc(fn, d, hd)
	case DeploymentStatusEvent:
		var d DeploymentStatusPayload
		json.Unmarshal([]byte(payload), &d)
		hook.runProcessPayloadFunc(fn, d, hd)
	case ForkEvent:
		var f ForkPayload
		json.Unmarshal([]byte(payload), &f)
		hook.runProcessPayloadFunc(fn, f, hd)
	case GollumEvent:
		var g GollumPayload
		json.Unmarshal([]byte(payload), &g)
		hook.runProcessPayloadFunc(fn, g, hd)
	case InstallationEvent, IntegrationInstallationEvent:
		var i InstallationPayload
		json.Unmarshal([]byte(payload), &i)
		hook.runProcessPayloadFunc(fn, i, hd)
	case IssueCommentEvent:
		var i IssueCommentPayload
		json.Unmarshal([]byte(payload), &i)
		hook.runProcessPayloadFunc(fn, i, hd)
	case IssuesEvent:
		var i IssuesPayload
		json.Unmarshal([]byte(payload), &i)
		hook.runProcessPayloadFunc(fn, i, hd)
	case LabelEvent:
		var l LabelPayload
		json.Unmarshal([]byte(payload), &l)
		hook.runProcessPayloadFunc(fn, l, hd)
	case MemberEvent:
		var m MemberPayload
		json.Unmarshal([]byte(payload), &m)
		hook.runProcessPayloadFunc(fn, m, hd)
	case MembershipEvent:
		var m MembershipPayload
		json.Unmarshal([]byte(payload), &m)
		hook.runProcessPayloadFunc(fn, m, hd)
	case MilestoneEvent:
		var m MilestonePayload
		json.Unmarshal([]byte(payload), &m)
		hook.runProcessPayloadFunc(fn, m, hd)
	case OrganizationEvent:
		var o OrganizationPayload
		json.Unmarshal([]byte(payload), &o)
		hook.runProcessPayloadFunc(fn, o, hd)
	case OrgBlockEvent:
		var o OrgBlockPayload
		json.Unmarshal([]byte(payload), &o)
		hook.runProcessPayloadFunc(fn, o, hd)
	case PageBuildEvent:
		var p PageBuildPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case PingEvent:
		var p PingPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case ProjectCardEvent:
		var p ProjectCardPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case ProjectColumnEvent:
		var p ProjectColumnPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case ProjectEvent:
		var p ProjectPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case PublicEvent:
		var p PublicPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case PullRequestEvent:
		var p PullRequestPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case PullRequestReviewEvent:
		var p PullRequestReviewPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case PullRequestReviewCommentEvent:
		var p PullRequestReviewCommentPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case PushEvent:
		var p PushPayload
		json.Unmarshal([]byte(payload), &p)
		hook.runProcessPayloadFunc(fn, p, hd)
	case ReleaseEvent:
		var r ReleasePayload
		json.Unmarshal([]byte(payload), &r)
		hook.runProcessPayloadFunc(fn, r, hd)
	case RepositoryEvent:
		var r RepositoryPayload
		json.Unmarshal([]byte(payload), &r)
		hook.runProcessPayloadFunc(fn, r, hd)
	case StatusEvent:
		var s StatusPayload
		json.Unmarshal([]byte(payload), &s)
		hook.runProcessPayloadFunc(fn, s, hd)
	case TeamEvent:
		var t TeamPayload
		json.Unmarshal([]byte(payload), &t)
		hook.runProcessPayloadFunc(fn, t, hd)
	case TeamAddEvent:
		var t TeamAddPayload
		json.Unmarshal([]byte(payload), &t)
		hook.runProcessPayloadFunc(fn, t, hd)
	case WatchEvent:
		var w WatchPayload
		json.Unmarshal([]byte(payload), &w)
		hook.runProcessPayloadFunc(fn, w, hd)
	}
}

func (hook Webhook) runProcessPayloadFunc(
	fn webhooks.ProcessPayloadFunc,
	results interface{},
	header webhooks.Header,
) {
	fn(results, header)
}
