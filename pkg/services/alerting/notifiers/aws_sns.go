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
					'24/7 Ops (Zenoss)': '247ops',
					'Plaintext (SMS)': 'plaintext'
        }" ng-init="ctrl.model.settings.message_template=ctrl.model.settings.message_template||'default'">
				</select>
      </div>
      <div class="gf-form" ng-show="ctrl.model.settings.message_template == '247ops'">
        <span class="gf-form-label width-10">Runbook URL</span>
        <input type="text" ng-required="ctrl.model.settings.message_template == '247ops'" class="gf-form-input max-width-26" ng-model="ctrl.model.settings.runbook_url"></input>
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
		return nil, alerting.ValidationError{Reason: "Could not find Message Templase property in settings"}
	}

	runbookUrl := model.Settings.Get("runbook_url").MustString()
	if messageTemplate == "ops247" && runbookUrl == "" {
		return nil, alerting.ValidationError{Reason: "Runbook is required for Ops"}
	}

	return &AwsSnsNotifier{
		NotifierBase:    NewNotifierBase(model),
		Region:          region,
		TopicArn:        topicArn,
		AccessKey:       model.Settings.Get("access_key").MustString(),
		SecretKey:       model.Settings.Get("secret_key").MustString(),
		MessageTemplate: messageTemplate,
		RunbookUrl:      runbookUrl,
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
	RunbookUrl      string
	log             log.Logger
}

func getMessageBody(messageTemplate string, runbookUrl string, evalContext *alerting.EvalContext) ([]byte, error) {
	bodyJSON := simplejson.New()

	alarmDescription := fmt.Sprintf("severity=%s,runbookurl=%s", "debug", runbookUrl)

	switch messageTemplate {
	case "plaintext":
		alarm := fmt.Sprintf(
			"Grafana Alert: %s\nTime: %s\nState: %s\nMessage: %s\nAlert URL: %s\nImage: %s",
			evalContext.GetNotificationTitle(),
			evalContext.StartTime,
			evalContext.Rule.State,
			evalContext.Rule.Message,
			evalContext.GetRuleUrl(),
			evalContext.ImagePublicUrl,
		)
		return []byte(alarm), nil
	case "247ops":
		bodyJSON.Set("AlarmName", evalContext.GetNotificationTitle())
		bodyJSON.Set("AlarmDescription", alarmDescription)
		bodyJSON.Set("StateChangeTime", evalContext.StartTime)
		bodyJSON.Set("state", evalContext.Rule.State)
		ruleUrl, err := evalContext.GetRuleUrl()
		if err == nil {
			bodyJSON.Set("ruleUrl", ruleUrl)
		}
		if evalContext.Rule.Message != "" {
			bodyJSON.Set("message", evalContext.Rule.Message)
		}
	case "default":
		bodyJSON.Set("title", evalContext.GetNotificationTitle())
		bodyJSON.Set("ruleId", evalContext.Rule.Id)
		bodyJSON.Set("ruleName", evalContext.Rule.Name)
		bodyJSON.Set("state", evalContext.Rule.State)
		bodyJSON.Set("evalMatches", simplejson.NewFromAny(evalContext.EvalMatches))

		ruleUrl, err := evalContext.GetRuleUrl()
		if err == nil {
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

	body, _ := getMessageBody(this.MessageTemplate, this.RunbookUrl, evalContext)

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

	svc := sns.New(sess, cfg)
	params := &sns.PublishInput{
		Subject:  aws.String(evalContext.GetNotificationTitle()),
		Message:  aws.String(string(body)),
		TopicArn: aws.String(this.TopicArn),
	}

	if _, err = svc.Publish(params); err != nil {
		this.log.Error("Failed to send AWS SNS event", "error", err)
		return err
	}

	return nil
}
