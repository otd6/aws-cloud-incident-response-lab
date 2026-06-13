# aws-cloud-incident-response-lab
This project documents my completion of the Flaws2 Defender Track, a cloud security incident response and threat hunting lab focused on AWS environments. I created this walkthrough to show the steps, commands, and reasoning I used. This lab demonstrates the various vulnerabilities found within AWS cloud environments and the path that an incident responder would take in investigating.

The investigation involved:
- Configuring AWS CLI profiles
- Assuming IAM roles across AWS accounts
- Downloading and analyzing CloudTrail logs
- Querying JSON log data using jq
- Investigating suspicious IAM role usage
- Identifying credential theft indicators
- Analyzing ECR repository policies
- Identifying publicly exposed cloud resources

This project gave me hands-on experience in cloud security operations, specifically with cloud forensics, IAM, CloudTrail, and incident response.

Tools Used:
- AWS CLI
- CloudTrail
- IAM
- jq
- Amazon S3
- Amazon ECR
- PowerShell

Skills Demonstrated
- Cloud Security
- Incident Response
- Threat Hunting
- Log Analysis
- IAM Analysis
- AWS Security
- Cloud Forensics

# AWS Cloud Incident Response Lab
### Cloud Security Final Project - AWS CloudTrail Threat Analysis 
## Defender Path

## objective 1: download cloudtrail logs
## step 1: setup CLI

## Install AWS vault by downloading it at https://github.com/99designs/aws-vault

## Verify that aws CLI is installed/configured
aws -–version

## configure credentials
aws configure

## AWS Access Key ID: [REDACTED]
## AWS Secret Access Key: [REDACTED]
## Default region name: us-east-1
## Default output format: json

# test that everything is configured properly
aws sts get-caller-identity
## verify that the command returns your IAM identity and account information 


## step 2: download the logs

## download the CloudTrail logs
aws s3 sync  s3://flaws2-logs .
## you should get a bunch of .json.gz files within the directory path AWSLogs….
## these logs contain CloudTrail records associated with the simulated attack scenario
## this S3 bucket is public so that you can reference it from Athena later 


## Objective 2

## create a dedicated flaws2log directory
mkdir C:\Users\<USERNAME>\flaws2logs
cd C:\Users\<USERNAME>\flaws2logs
aws s3 sync s3://flaws2-logs . 


## verify
dir AWSLogs



## verify that your AWS config file exists
notepad $HOME\.aws\config

## add a profile for the target to that file:

[profile target_security]
region=us-east-1
output=json
source_profile=default
role_arn=<cross-account security role> 


## save the file

## test
aws --profile target_security sts get-caller-identity
















## Enumerate accessible s3 buckets
aws --profile target_security s3 ls



## objective 3

## install jq
winget install jqlang.jq

## re-open powershell and verify jq is installed

jq –version

## gzip isn’t installed on windows but powershell can unzip .gz files itself
Get-ChildItem -Recurse -Filter *.json.gz | ForEach-Object {
  $infile = $_.FullName
  $outfile = $infile -replace '\.gz$',''
  $inputStream = [System.IO.File]::OpenRead($infile)
  $outputStream = [System.IO.File]::Create($outfile)
  $gzipStream = New-Object System.IO.Compression.GzipStream($inputStream, [System.IO.Compression.CompressionMode]::Decompress)
  $gzipStream.CopyTo($outputStream)
  $gzipStream.Close()
  $outputStream.Close()
  $inputStream.Close()
}


## verify the .json files exist
Get-ChildItem -Recurse -Filter *.json | Select-Object -First 5


## run the jq test
Get-ChildItem -Recurse -Filter *.json | ForEach-Object {
  Get-Content $_.FullName
} | jq '.'





## show only event names
Get-ChildItem -Recurse -Filter *.json | ForEach-Object {
  Get-Content $_.FullName
} | jq '.Records[] | .eventName'





## show timestamps and event names
Get-ChildItem -Recurse -Filter *.json | ForEach-Object {
  Get-Content $_.FullName
} | jq -r '.Records[] | [.eventTime, .eventName] | @tsv'





## show the useful investigation fields
Get-ChildItem -Recurse -Filter *.json | ForEach-Object {
  Get-Content $_.FullName
} | jq -r '.Records[] | [.eventTime, .sourceIPAddress, .userIdentity.arn, .userIdentity.accountId, .userIdentity.type, .eventName] | @tsv'


## objective 4: Identify credential theft
## Review the IAM role trust policy to determine the intended
## principal and compare it against observed CloudTrail activity
aws --profile target_security iam get-role --role-name level3



## objective 5: identify the public resource
## Analysis:
## The ECR repository policy contained:
## “Principal”: “*”
## which allowed unauthenticated public access to several repository actions
## this misconfiguration enabled attackers to enumerate and receive container image information

## get the repository policy
aws --profile target_security ecr get-repository-policy --repository-name level2



