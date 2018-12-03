package notifiers

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/log"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/alerting"
)

func init() {
	alerting.RegisterNotifier(&alerting.NotifierPlugin{
		Type:        "aws_sns",
		Name:        "AWS SNS",
		Description: "Sends HTTP POST request to a AWS SNS API",
		Factory:     NewAwsSnsNotifier,
		OptionsTemplate: `
      <h3 class="page-heading">AWS SNS settings</h3>
      <div class="gf-form">
        <span class="gf-form-label width-10">Region</span>
        <input type="text" required class="gf-form-input max-width-26" ng-model="ctrl.model.settings.region" ng-init="ctrl.model.settings.region = 'eu-west-1'" placeholder="eu-west-1"></input>
      </div>
      <div class="gf-form">
        <span class="gf-form-label width-10">Topic Arn</span>
				<input type="text" required class="gf-form-input max-width-26" ng-model="ctrl.model.settings.topic_arn" placeholder="arn:aws:sns:eu-west-1:123456789012:topic"></input>
      </div>
      <div class="gf-form">
        <span class="gf-form-label width-10">Access Key</span>
        <input type="text" class="gf-form-input max-width-26" ng-model="ctrl.model.settings.access_key"></input>
      </div>
      <div class="gf-form">
        <span class="gf-form-label width-10">Secret Key</span>
        <input type="text" class="gf-form-input max-width-26" ng-model="ctrl.model.settings.secret_key"></input>
			</div>
			<div class="gf-form">
        <span class="gf-form-label width-10">Message Template</span>
				<select required class="gf-form-input max-width-26" ng-model="ctrl.model.settings.message_template" ng-options="v as k for (k, v) in {
          'Default': 'default',
					'OTG Monitoring (Zenoss)': '247ops',
					'Plaintext (SMS)': 'plaintext'
        }" ng-init="ctrl.model.settings.message_template=ctrl.model.settings.message_template||'default'">
				</select>
      </div>
      <div class="gf-form" ng-show="ctrl.model.settings.message_template == '247ops'">
        <span class="gf-form-label width-10">Runbook URL</span>
        <input type="text" ng-required="ctrl.model.settings.message_template == '247ops'" class="gf-form-input max-width-26" ng-model="ctrl.model.settings.runbook_url"></input>
      </div>
      <div class="gf-form" ng-show="ctrl.model.settings.message_template == '247ops'">
        <span class="gf-form-label width-10">Component</span>
        <input type="text" ng-required="ctrl.model.settings.message_template == '247ops'" class="gf-form-input max-width-26" ng-model="ctrl.model.settings.component"></input>
			</div>
			<div class="gf-form" ng-show="ctrl.model.settings.message_template == '247ops'">
        <span class="gf-form-label width-10">Severity</span>
				<select required class="gf-form-input max-width-26" ng-model="ctrl.model.settings.severity" ng-options="v as k for (k, v) in {
          'Critical (alerts 24/7)': 'critical',
					'Error': 'error',
					'Warning': 'warning',
					'Info': 'info',
					'Debug': 'debug',
					'Clear': 'clear'
        }" ng-init="ctrl.model.settings.severity=ctrl.model.settings.severity||'info'">
				</select>
      </div>
    `,
	})
}

func NewAwsSnsNotifier(model *m.AlertNotification) (alerting.Notifier, error) {
	region := model.Settings.Get("region").MustString()
	if region == "" {
		return nil, alerting.ValidationError{Reason: "Could not find region property in settings"}
	}

	topicArn := model.Settings.Get("topic_arn").MustString()
	if topicArn == "" {
		return nil, alerting.ValidationError{Reason: "Could not find topic arn property in settings"}
	}

	messageTemplate := model.Settings.Get("message_template").MustString()
	if messageTemplate == "" {
		return nil, alerting.ValidationError{Reason: "Could not find Message Template property in settings"}
	}

	runbookUrl := model.Settings.Get("runbook_url").MustString()
	if messageTemplate == "ops247" && runbookUrl == "" {
		return nil, alerting.ValidationError{Reason: "Runbook is required for Ops"}
	}

	component := model.Settings.Get("component").MustString()
	if messageTemplate == "ops247" && component == "" {
		return nil, alerting.ValidationError{Reason: "Component is required for Ops"}
	}

	severity := model.Settings.Get("severity").MustString()
	if messageTemplate == "ops247" && severity == "" {
		return nil, alerting.ValidationError{Reason: "Severity is required for Ops"}
	}

	return &AwsSnsNotifier{
		NotifierBase:    NewNotifierBase(model),
		Region:          region,
		TopicArn:        topicArn,
		AccessKey:       model.Settings.Get("access_key").MustString(),
		SecretKey:       model.Settings.Get("secret_key").MustString(),
		MessageTemplate: messageTemplate,
		RunbookURL:      runbookUrl,
		Component:       component,
		Severity:        severity,
		log:             log.New("alerting.notifier.aws_sns"),
	}, nil
}

type AwsSnsNotifier struct {
	NotifierBase
	Region          string
	TopicArn        string
	AccessKey       string
	SecretKey       string
	MessageTemplate string
	RunbookURL      string
	Component       string
	Severity        string
	log             log.Logger
}

func (this *AwsSnsNotifier) getMessageBody(evalContext *alerting.EvalContext) ([]byte, error) {
	bodyJSON := simplejson.New()

	ruleUrl, ruleUrlErr := evalContext.GetRuleUrl()
	switch this.MessageTemplate {
	case "plaintext":
		alarm := fmt.Sprintf(
			"Grafana Alert: %s\nTime: %s\nState: %s\nMessage: %s\nAlert URL: %s\nImage: %s",
			evalContext.GetNotificationTitle(),
			evalContext.StartTime,
			evalContext.Rule.State,
			evalContext.Rule.Message,
			ruleUrl,
			evalContext.ImagePublicUrl,
		)
		return []byte(alarm), nil
	case "247ops":
		monitoringJSON := simplejson.New()
		monitoringJSON.Set("runbookurl", this.RunbookURL)

		if evalContext.Rule.State != m.AlertStateAlerting {
			monitoringJSON.Set("severity", "clear")
		} else {
			monitoringJSON.Set("severity", this.Severity)
		}

		monitoringJSON.Set("component", this.Component)
		monitoringJSON.Set("summary", evalContext.GetNotificationTitle())
		monitoringJSON.Set("message", evalContext.Rule.Message)
		monitoringJSON.Set("startTime", evalContext.StartTime)
		monitoringJSON.Set("alertUrl", ruleUrl)
		bodyJSON.Set("BBCMonitoring", monitoringJSON)

	case "default":
		bodyJSON.Set("title", evalContext.GetNotificationTitle())
		bodyJSON.Set("ruleId", evalContext.Rule.Id)
		bodyJSON.Set("ruleName", evalContext.Rule.Name)
		bodyJSON.Set("state", evalContext.Rule.State)
		bodyJSON.Set("evalMatches", simplejson.NewFromAny(evalContext.EvalMatches))

		if ruleUrlErr == nil {
			bodyJSON.Set("ruleUrl", ruleUrl)
		}

		if evalContext.ImagePublicUrl != "" {
			bodyJSON.Set("imageUrl", evalContext.ImagePublicUrl)
		}

		if evalContext.Rule.Message != "" {
			bodyJSON.Set("message", evalContext.Rule.Message)
		}
		bodyJSON.Set("default", "")
	}

	body, _ := bodyJSON.MarshalJSON()
	return body, nil
}

func (this *AwsSnsNotifier) Notify(evalContext *alerting.EvalContext) error {
	this.log.Info("Sending AWS SNS message")

	body, _ := this.getMessageBody(evalContext)

	sess, err := session.NewSession()
	if err != nil {
		return err
	}
	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.StaticProvider{Value: credentials.Value{
				AccessKeyID:     this.AccessKey,
				SecretAccessKey: this.SecretKey,
			}},
			&credentials.EnvProvider{},
			&ec2rolecreds.EC2RoleProvider{Client: ec2metadata.New(sess), ExpiryWindow: 5 * time.Minute},
		})
	cfg := &aws.Config{
		Region:      aws.String(this.Region),
		Credentials: creds,
	}

	notificationSubject := evalContext.GetNotificationTitle()
	if this.MessageTemplate == "247ops" {
		notificationSubject = "BBCMonitoring"
	}

	svc := sns.New(sess, cfg)
	params := &sns.PublishInput{
		Subject:  aws.String(notificationSubject),
		Message:  aws.String(string(body)),
		TopicArn: aws.String(this.TopicArn),
	}

	if _, err = svc.Publish(params); err != nil {
		this.log.Error("Failed to send AWS SNS event", "error", err)
		return err
	}

	return nil
}
