# aws-login-notifications

Sets up minimal monitoring for personal AWS account to send an email notification to email of choice for any login activity.

## usage

1. authenticate to AWS account and set env vars: `AWS_PROFILE,AWS_REGION`  
1. replace `Pulumi.prd.yaml` file with your own to set secrets provider/region. 
1. Set a secret of `email`:

    ```bash
    pulumi config set --secret email <email>
    ```

1. `pulumi up`
