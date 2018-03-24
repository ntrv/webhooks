package github

// Event defines a GitHub hook event type
type Event string

// GitHub hook types
const (
	CommitCommentEvent            Event = "commit_comment"
	CreateEvent                   Event = "create"
	DeleteEvent                   Event = "delete"
	DeploymentEvent               Event = "deployment"
	DeploymentStatusEvent         Event = "deployment_status"
	ForkEvent                     Event = "fork"
	GollumEvent                   Event = "gollum"
	InstallationEvent             Event = "installation"
	IntegrationInstallationEvent  Event = "integration_installation"
	IssueCommentEvent             Event = "issue_comment"
	IssuesEvent                   Event = "issues"
	LabelEvent                    Event = "label"
	MemberEvent                   Event = "member"
	MembershipEvent               Event = "membership"
	MilestoneEvent                Event = "milestone"
	OrganizationEvent             Event = "organization"
	OrgBlockEvent                 Event = "org_block"
	PageBuildEvent                Event = "page_build"
	PingEvent                     Event = "ping"
	ProjectCardEvent              Event = "project_card"
	ProjectColumnEvent            Event = "project_column"
	ProjectEvent                  Event = "project"
	PublicEvent                   Event = "public"
	PullRequestEvent              Event = "pull_request"
	PullRequestReviewEvent        Event = "pull_request_review"
	PullRequestReviewCommentEvent Event = "pull_request_review_comment"
	PushEvent                     Event = "push"
	ReleaseEvent                  Event = "release"
	RepositoryEvent               Event = "repository"
	StatusEvent                   Event = "status"
	TeamEvent                     Event = "team"
	TeamAddEvent                  Event = "team_add"
	WatchEvent                    Event = "watch"
)

// EventSubtype defines a GitHub Hook Event subtype
type EventSubtype string

// GitHub hook event subtypes
const (
	NoSubtype     EventSubtype = ""
	BranchSubtype EventSubtype = "branch"
	TagSubtype    EventSubtype = "tag"
	PullSubtype   EventSubtype = "pull"
	IssueSubtype  EventSubtype = "issues"
)
