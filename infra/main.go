package main

import (
	"bytes"
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/sns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Create an AWS resource (S3 Bucket)

		eventPattern := map[string]interface{}{
			"detail-type": []string{"AWS Console Sign In via CloudTrail"},
			"detail": map[string]interface{}{
				"eventSource": []string{"signin.amazonaws.com"},
				"eventName":   []string{"ConsoleLogin"},
			},
		}

		rule, err := cloudwatch.NewEventRule(ctx, "console-login", &cloudwatch.EventRuleArgs{
			Description:  pulumi.StringPtr("monitors for logins"),
			EventPattern: pulumi.StringPtr(jsonString(eventPattern)),
		})

		if err != nil {
			return err
		}

		snsTopic, err := sns.NewTopic(ctx, "console-login", nil)
		if err != nil {
			return err
		}

		snsPolicy := snsTopic.Arn.ApplyT(func(v string) (string, error) {
			policy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
				PolicyId: aws.String("InvokeCWRule"),
				Statements: []iam.GetPolicyDocumentStatement{
					{
						Actions: []string{
							"sns:Publish",
						},
						Resources: []string{v},
						Effect:    aws.String("Allow"),
						Principals: []iam.GetPolicyDocumentStatementPrincipal{
							{
								Identifiers: []string{"events.amazonaws.com"},
								Type:        "Service",
							},
						},
					},
				},
			},
			)
			return policy.Json, err
		}).(pulumi.StringOutput)

		_, err = sns.NewTopicPolicy(ctx, "console-login", &sns.TopicPolicyArgs{
			Arn:    snsTopic.Arn,
			Policy: snsPolicy,
		})

		if err != nil {
			return err
		}

		template := map[string]string{
			"sourceIp":  "<sourceIp>",
			"userAgent": "<userAgent>",
			"entity":    "<user>",
			"time":      "<time>",
		}

		transformer := cloudwatch.EventTargetInputTransformerArgs{
			InputPaths: pulumi.StringMap{
				"sourceIp":  pulumi.String("$.detail.sourceIPAddress"),
				"user":      pulumi.String("$.detail.userIdentity.arn"),
				"userAgent": pulumi.String("$.detail.userAgent"),
				"time":      pulumi.String("$.detail.eventTime"),
			},

			InputTemplate: pulumi.String(jsonString(template)),
		}

		_, err = cloudwatch.NewEventTarget(ctx, "console-login", &cloudwatch.EventTargetArgs{
			Arn:              snsTopic.Arn,
			Rule:             rule.Name,
			InputTransformer: transformer,
		})

		if err != nil {
			return err
		}
		cfg := config.New(ctx, "")
		email := cfg.RequireSecret("email")
		_, err = sns.NewTopicSubscription(ctx, "console-login", &sns.TopicSubscriptionArgs{
			Topic:    snsTopic.Arn,
			Protocol: pulumi.String("email"),
			Endpoint: email,
		})

		if err != nil {
			return err
		}
		return nil
	})
}

// Needed to roll own Json Marshal as json.Marshal escapes '>' chars
func jsonString(i interface{}) string {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(i)
	return buffer.String()
}
