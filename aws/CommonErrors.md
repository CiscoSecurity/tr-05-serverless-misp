# AWS Common Errors

**NOTE.** If you are reading this document then most probably you have missed
some steps/notes from the [AWS HOWTO](HOWTO.md)/[README](../README.md). So this
document itself just lists some most common types of errors and repeats the
same instructions one more time.

## AWS Credentials Not Found

### Errors

- `NoCredentialsError: Unable to locate credentials.`

- `botocore.exceptions.ProfileNotFound: The config profile (serverless) could
not be found.`

### Solution

To fix the problem, follow the instructions from the
[Custom AWS IAM Users and Policies for Deployment](HOWTO.md#custom-aws-iam-users-and-policies-for-deployment)
section and configure your local AWS `credentials` and `config` files to have
the corresponding sections for your `serverless` user.

## Deployment Policy Not Applied To User

### Error

`botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling
the CreateBucket operation: Access Denied.`

### Solution

To fix the problem, follow the instructions from the
[Custom AWS IAM Users and Policies for Deployment](HOWTO.md#custom-aws-iam-users-and-policies-for-deployment)
section and attach the corrected [Deployment Policy](ZappaLambdaDeploymentPolicy.json)
to your `serverless` user.

## S3 Bucket Not Globally Unique

### Errors

- `botocore.exceptions.ClientError: An error occurred
(IllegalLocationConstraintException) when calling the CreateBucket operation:
The unspecified location constraint is incompatible for the region specific
endpoint this request was sent to.`

- `botocore.errorfactory.InvalidParameterValueException: An error occurred
(InvalidParameterValueException) when calling the CreateFuncion operation:
Error occurred while GetObject. S3 Error Code: PermanentRedirect. S3 Error
Message: The bucket is in this region: <AWS_REGION>. Please use this region to
retry the request.`

- `botocore.errorfactory.BucketAlreadyExists: An error occurred
(BucketAlreadyExists) when calling the CreateBucket operation: The requested
bucket name is not available. The bucket namespace is shared by all users of
the system. Please select a different name and try again.`

### Solution

Remember that S3 bucket names are globally unique even if they are physically
located in different regions. To fix the problem, modify the value of the
`s3_bucket` setting in the [Zappa Settings](../zappa_settings.json) to be a
globally unique bucket name (e.g. by adding some random suffix to the end).

Example:

- Before:

  `"s3_bucket": "tr-template-relay"`

- After:

  `"s3_bucket": "tr-template-relay-auk8ah9o15"`

**NOTE.** Here is a simple code snippet in Python that might be helpful for
generating random alphanumeric 10-character suffixes:
```python
import random
import string

alphabet = string.ascii_lowercase + string.digits
length = 10

suffix = ''.join(random.choice(alphabet) for _ in range(length))
print(suffix)
```

## Execution Role Not Found

### Error

`botocore.errorfactory.NoSuchEntityException: An error occurred (NoSuchEntity)
when calling the GetRole operation: The role with name
tr-serverless-relay-ZappaLambdaExecutionRole cannot be found.`

### Solution

To fix the problem, follow the instructions from the
[Custom AWS IAM Roles and Policies for Execution](HOWTO.md#custom-aws-iam-roles-and-policies-for-execution)
section and create a role (based on the [Execution Policy](ZappaLambdaExecutionPolicy.json))
with the name corresponding to the value of the `role_name` setting in the
[Zappa Settings](../zappa_settings.json).

## Requirements Not Installed

### Error

`Error: Warning! Status check on the deployed lambda failed. A GET request to
'/' yielded a 502 response code.`

### Solution

To fix the problem, install the application's requirements and `update` the
Lambda:
```
pip install --upgrade --requirement requirements.txt && zappa update dev
```

If that does not help then try to `undeploy` the Lambda altogether and `deploy`
it from scratch again:
```
zappa undeploy dev && zappa deploy dev
```
