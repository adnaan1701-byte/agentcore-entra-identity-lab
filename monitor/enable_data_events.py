"""
Module V (Varonis-style), step 1: start recording data access.

Creates a CloudTrail trail that logs DATA events (every S3 object read and
write in the lab bucket, every DynamoDB call on the employees table) to a
private log bucket. Run this BEFORE generating activity: CloudTrail only
records from the moment the trail exists.

  python monitor/enable_data_events.py

Cost: data events are $0.10 per 100,000 events; this lab produces a few
hundred. Teardown (aws/teardown.py) deletes the trail and the log bucket.
"""

import json
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, ".lab")
PREFIX = "agentlab"
TRAIL = f"{PREFIX}-data-trail"


def log(m):
    print(f"[monitor] {m}", flush=True)


def main():
    p = os.path.join(LAB, "aws.json")
    if not os.path.exists(p):
        sys.exit("Missing .lab/aws.json. Deploy the lab first.")
    aws = json.load(open(p))
    region, account = aws["region"], aws["account"]
    s = boto3.Session(region_name=region)
    s3, ct = s.client("s3"), s.client("cloudtrail")
    log_bucket = f"{PREFIX}-trail-{account}-{region}"
    trail_arn = f"arn:aws:cloudtrail:{region}:{account}:trail/{TRAIL}"
    table_arn = f"arn:aws:dynamodb:{region}:{account}:table/{aws.get('employees_table', PREFIX + '-employees')}"

    try:
        s3.head_bucket(Bucket=log_bucket)
        log(f"log bucket {log_bucket} exists")
    except ClientError:
        kw = {"Bucket": log_bucket}
        if region != "us-east-1":
            kw["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**kw)
        log(f"created log bucket {log_bucket}")
    s3.put_public_access_block(Bucket=log_bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_lifecycle_configuration(Bucket=log_bucket, LifecycleConfiguration={"Rules": [{
        "ID": "expire-lab-logs", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 14}}]})
    # Only this trail, in this account, may write here (confused-deputy protection via aws:SourceArn).
    s3.put_bucket_policy(Bucket=log_bucket, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "CloudTrailAclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{log_bucket}",
         "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}},
        {"Sid": "CloudTrailWrite", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{log_bucket}/AWSLogs/{account}/*",
         "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": trail_arn}}},
    ]}))

    try:
        ct.get_trail(Name=TRAIL)
        log(f"trail {TRAIL} exists")
    except ClientError:
        for attempt in range(6):  # the new bucket policy can take a few seconds to be visible
            try:
                ct.create_trail(Name=TRAIL, S3BucketName=log_bucket, IsMultiRegionTrail=False,
                                IncludeGlobalServiceEvents=False, EnableLogFileValidation=True,
                                TagsList=[{"Key": "project", "Value": PREFIX}])
                break
            except ClientError as e:
                if "InsufficientS3BucketPolicy" not in e.response["Error"]["Code"] or attempt == 5:
                    raise
                time.sleep(5)
        log(f"created trail {TRAIL}")
    ct.put_event_selectors(TrailName=TRAIL, AdvancedEventSelectors=[
        {"Name": "Lab bucket object reads and writes",
         "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
                            {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                            {"Field": "resources.ARN", "StartsWith": [f"arn:aws:s3:::{aws['bucket']}/"]}]},
        {"Name": "Employees table",
         "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
                            {"Field": "resources.type", "Equals": ["AWS::DynamoDB::Table"]},
                            {"Field": "resources.ARN", "Equals": [table_arn]}]},
    ])
    ct.start_logging(Name=TRAIL)
    state = {"trail": TRAIL, "log_bucket": log_bucket}
    with open(os.path.join(LAB, "monitor.json"), "w") as f:
        json.dump(state, f, indent=2)
    log("recording data events from now on. Logs reach the bucket 5-15 minutes after each call.")
    log("Generate activity (run_scenarios, the DSPM and Immuta demos), then: python monitor/access_report.py")


if __name__ == "__main__":
    main()
