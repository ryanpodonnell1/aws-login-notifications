package main

import (
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

		cwRoleAssumeRole, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
			PolicyId: aws.String("CwAssumeRole"),
			Statements: []iam.GetPolicyDocumentStatement{
				{
					Actions: []string{"sts:AssumeRole"},
					Effect:  aws.String("Allow"),
					Principals: []iam.GetPolicyDocumentStatementPrincipal{
						{
							Identifiers: []string{"events.amazonaws.com"},
							Type:        "Service",
						},
					},
				},
			},
		})

		if err != nil {
			return err
		}

		cwRole, err := iam.NewRole(ctx, "console-login", &iam.RoleArgs{
			AssumeRolePolicy: pulumi.StringPtr(cwRoleAssumeRole.Json),
		})
		if err != nil {
			return err
		}

		rule, err := cloudwatch.NewEventRule(ctx, "console-login", &cloudwatch.EventRuleArgs{
			Description:  pulumi.StringPtr("monitors flor logins"),
			EventPattern: pulumi.StringPtr(jsonString(eventPattern)),
			RoleArn:      cwRole.Arn,
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

		iamPolicy := snsTopic.Arn.ApplyT(func(v string) (string, error) {
			policy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
				PolicyId: aws.String("InvokeCWRule"),
				Statements: []iam.GetPolicyDocumentStatement{
					{
						Actions: []string{
							"sns:Publish",
						},
						Resources: []string{v},
						Effect:    aws.String("Allow"),
					},
				},
			},
			)
			return policy.Json, err
		}).(pulumi.StringOutput)

		_, err = iam.NewRolePolicy(ctx, "console-login", &iam.RolePolicyArgs{
			Role:   cwRole.Name,
			Policy: iamPolicy,
		})

		if err != nil {
			return err
		}

		transformer := cloudwatch.EventTargetInputTransformerArgs{
			InputPaths: pulumi.StringMap{
				"sourceIp":  pulumi.String("$.detail.sourceIPAddress"),
				"user":      pulumi.String("$.detail.userIdentity.arn"),
				"userAgent": pulumi.String("$.detail.userAgent"),
				"time":      pulumi.String("$.detail.eventTime"),
			},

			InputTemplate: pulumi.String(`
		    {
			"sourceIp"  : "<sourceIp>",
			"userAgent" : "<userAgent>",
			"entity"    : "<user>",
			"time"      : "<time>"
			}`,
			),
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

func jsonString(i interface{}) string {
	xb, _ := json.Marshal(i)
	return string(xb)
}
