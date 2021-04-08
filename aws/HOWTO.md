# AWS HOWTO

**NOTE.** This document is intended for the initial AWS setup. If you have not
configured your AWS environment yet, then make sure to do that first by
thoroughly carrying out any instructions from this document. This setup only
needs to be done one time in your AWS environment.

## Using Custom AWS IAM Users, Roles, Policies

### Custom AWS IAM Users and Policies for Deployment

#### Sample AWS IAM User for Deployment (`serverless`)

To get started, you have to create an IAM user with the name `serverless` by
going through the following steps:

1. Go to the `Identity and Access Management (IAM)` console.
2. Select the `Users` tab under the `Access management` drop-down list.
3. Click the `Add user` button.
4. Give your user the name `serverless` and enable `Programmatic access` via
the corresponding check-box. Click the `Next: Permissions` button.
5. Click the `Next: Tags` button and then the `Next: Review` button.
6. Click the `Create user` button. You might see a warning that the user has no
permissions at the moment. Just ignore it, we will fix it soon.
7. Click the `Download .csv` button. Notice that this is the last time these
credentials will be available to download, so make sure to store them somewhere.
Rename the file to `serverless.csv` so that we can refer to it later on.

Once the user is created and the credentials are downloaded, the best way to
store that data is to put it into your AWS `credentials` file usually located
on `~/.aws/credentials` (Linux and Mac) or `%USERPROFILE%\.aws\credentials`
(Windows). So make sure to add the user's credentials from the `serverless.csv`
file to the AWS `credentials` file (manually create an empty one if missing)
as a separate profile:
```
[serverless]
aws_access_key_id=<AWS_ACCESS_KEY_ID>
aws_secret_access_key=<AWS_SECRET_ACCESS_KEY>
```

**NOTE.** Throughout this document everything between a pair of angle brackets
`<...>` (including the brackets themselves!) is considered a placeholder for
your actual credentials. So please pay attention to this fact and be careful of
simply copying and pasting without filling any gaps.

Each profile can also specify different AWS regions and output formats in the
AWS `config` file usually located on `~/.aws/config` (Linux and Mac) or
`%USERPROFILE%\.aws\config` (Windows). So make sure to also add the following
lines to your AWS `config` file:
```
[profile serverless]
region=<REGION>
output=json
```

**NOTE.** The profile name in the AWS `config` file must include the `"profile"`
prefix but still match the profile name in the AWS `credentials` file. Compare:
`[profile serverless]` vs `[serverless]`.

**NOTE.** Your AWS region should be geographically as close to your SecureX Threat
Response region as possible to reduce latency as much as possible. The
recommended AWS regions are:
- `us-east-1` (for [North America](https://visibility.amp.cisco.com)),
- `eu-west-1` (for [Europe](https://visibility.eu.amp.cisco.com)),
- `ap-northeast-1` (for [Asia](https://visibility.apjc.amp.cisco.com)).

Finally, you have to specify which AWS profile to use for deploying your Zappa
application by defining the `profile_name` setting in the
[Zappa Settings](../zappa_settings.json).

**NOTE.** In the [Zappa Settings](../zappa_settings.json) the value of the
`profile_name` setting must correspond to the profile name in the AWS
`credentials` file. Compare: `"profile_name": "serverless"` vs `[serverless]`.

**NOTE.** In the [Zappa Settings](../zappa_settings.json) the value of the
`aws_region` setting must correspond to the region name for the `serverless`
profile in the AWS `config` file.

#### Sample AWS IAM Policy for Deployment (`ZappaLambdaDeploymentPolicy`)

By default, Zappa just assumes that the user already has all the necessary
permissions before deploying or running any other command. On the other hand,
it is not always possible (and is not a good idea either according to the
[PoLP](https://en.wikipedia.org/wiki/Principle_of_least_privilege))
to simply work on behalf of a user with administrator access to any resource.

So a better solution is to grant your user a more granular (ideally minimum)
set of permissions. To achieve that, we have already compiled the necessary
[Deployment Policy](ZappaLambdaDeploymentPolicy.json) for you to simplify
things. Basically, it is just a JSON document in a special format that AWS can
understand and work with. You are encouraged to check the document's contents
before we move on.

**NOTE.** Make sure to replace `<ACCOUNT_ID>` by the actual ID of your AWS
account. An AWS account ID is a 12-digit number, such as 123456789012, and there
are several places in the `AWS Management Console` where it can be found. E.g,
you may go to the [Support Center](https://console.aws.amazon.com/support/home)
and look for something like `Account number: 123456789012` in the upper left
corner of the page.

Before:
```json
...
"Resource": [
    "arn:aws:iam::<ACCOUNT_ID>:role/*-ZappaLambdaExecutionRole"
]
...
```

After:
```json
...
"Resource": [
    "arn:aws:iam::123456789012:role/*-ZappaLambdaExecutionRole"
]
...
```

**NOTE.** You might have noticed the lines like `"arn:aws:s3:::zappa-*"` or
`"arn:aws:s3:::zappa-*/*"`. What Zappa does under the hood when deploying an
application is that it automatically packages up the application and its local
virtual environment into a Lambda-compatible archive, uploads the archive to S3
and temporary stores it in an S3 bucket, keeps provisioning the other resources,
and then deletes the archive from the S3 bucket. So that is why your user must
have almost full access to S3 buckets starting with the `zappa-` prefix. Thus,
make sure that in the [Zappa Settings](../zappa_settings.json) the value of the
`s3_bucket` setting starts with the `zappa-` prefix. Also, make sure that the
bucket name is globally unique (e.g. by adding some random suffix to the end)
because the namespace of S3 is shared between all AWS accounts.

To attach the corrected [Deployment Policy](ZappaLambdaDeploymentPolicy.json)
to your `serverless` user, you have to go through the following steps:
1. Go to the `Identity and Access Management (IAM)` console.
2. Select the `Policies` tab under the `Access management` drop-down list.
3. Click the `Create policy` button.
4. Select the `JSON` tab. Copy and paste the JSON contents of the
[Deployment Policy](ZappaLambdaDeploymentPolicy.json).
5. Click the `Review policy` button.
6. Give your policy the name `ZappaLambdaDeploymentPolicy` and click
the `Create policy` button.
7. Select the `Users` tab under the `Access management` drop-down list.
8. Find the `serverless` user and go to the corresponding configuration page.
9. Click the `Add permissions` button.
10. Select the `Attach existing policies directly` tab.
11. Search for the `ZappaLambdaDeploymentPolicy` policy and enable it via the
corresponding check-box.
12. Click the `Next: Review` button and then the `Add permissions` button.

### Custom AWS IAM Roles and Policies for Execution

#### Sample AWS IAM Role for Execution (`tr-serverless-relay-ZappaLambdaExecutionRole`)

The default IAM policy created by Zappa for executing Lambdas is very
permissive. It grants access to all actions for all resources for types
CloudWatch, S3, Kinesis, SNS, SQS, DynamoDB, and Route53; lambda:InvokeFunction
for all Lambda resources; Put to all X-Ray resources; and all Network Interface
operations to all EC2 resources. While this allows most Lambdas to work
correctly with no extra permissions, it is generally not an acceptable set of
permissions for most continuous integration pipelines or production
deployments. Instead, you will probably want to manually manage your IAM
policies.

That is why in the [Zappa Settings](../zappa_settings.json) the `manage_roles`
setting is set to `false`. Also, notice the `role_name` setting, it makes Zappa
look for a custom IAM role named `tr-serverless-relay-ZappaLambdaExecutionRole`.
The role will be automatically attached to your Lambda by Zappa. Moreover, once
you have created the role, you will be able to re-use it for any future Lambdas.

**NOTE.** After having properly configured your `serverless` user, Zappa must
be able to attach such roles (i.e. with the `ZappaLambdaExecutionRole` suffix)
to any of your Lambdas on behalf of `serverless`. Again, you may check the
[Deployment Policy](ZappaLambdaDeploymentPolicy.json) one more time to figure
out where that permission comes from. Hint: remember the line where you must
have already substituted some placeholder with your AWS account ID.

#### Sample AWS IAM Policy for Execution (`ZappaLambdaExecutionPolicy`)

We have already compiled the [Execution Policy](ZappaLambdaExecutionPolicy.json)
for your with a much smaller set of permissions intended exactly for our
particular use case (i.e. implementation of Serverless Relays). It is still a
JSON document in the format you should already be familiar with.

To create your `tr-serverless-relay-ZappaLambdaExecutionRole` role and attach
the [Execution Policy](ZappaLambdaExecutionPolicy.json) to it, you have to go
through the following steps:
1. Go to the `Identity and Access Management (IAM)` console.
2. Select the `Policies` tab under the `Access management` drop-down list.
3. Click the `Create policy` button.
4. Select the `JSON` tab. Copy and paste the JSON contents of the
[Execution Policy](ZappaLambdaExecutionPolicy.json).
5. Click the `Review policy` button.
6. Give your policy the name `ZappaLambdaExecutionPolicy` and click
the `Create policy` button.
7. Select the `Roles` tab under the `Access management` drop-down list.
8. Click the `Create role` button.
9. Select the `AWS service` tab and choose the `Lambda` service.
10. Click the `Next: Permissions` button.
11. Search for the `ZappaLambdaExecutionPolicy` policy and enable it via the
corresponding check-box.
12. Click the `Next: Tags` button and then the `Next: Review` button.
13. Give your role the name `tr-serverless-relay-ZappaLambdaExecutionRole`
and click the `Create role` button.
14. Find the newly created role and go to the corresponding configuration page.
15. Select the `Trust relationships` tab.
16. Click the `Edit trust relationship` button.
17. By default, the `Service` field will be equal to `lambda.amazonaws.com`.
Convert the value to a list and add `apigateway.amazonaws.com` to it.

Before:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

After:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "apigateway.amazonaws.com",
          "lambda.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Extra Notes on Zappa Settings

In the previous section, we have covered the required AWS setup also explaining
how to properly configure some of the most important Zappa settings along the
way. In this section, we will explain the rest of them. Any setting not covered
here is assumed to have an already reasonable default value and thus may be
simply left as-is.

- `stage`. A logical group of settings representing a separate environment.
This is not an actual setting. Instead, this is the way individual settings are
grouped by different environments in the [Zappa Settings](../zappa_settings.json).
You may define as many stages as you like - we recommend having at least the
`dev` stage (the default one).

- `project_name`. The name of the project as it appears on AWS.
The concatenation of `project_name` and `stage` (e.g. `tr-serverless-relay-dev`)
and its derivatives serve as unique identifiers for any groups of resources in
different AWS services related to the same Lambda. Unlike `s3_bucket`,
`project_name` does not have to be globally unique, it just has to be unique
within `aws_region` of your AWS account.

- `runtime`. The Python version used for running the Lambda.
The Lambda has been implemented and tested using `python3.7`. You may try to
use any higher versions if you wish as they should be backward-compatible.
