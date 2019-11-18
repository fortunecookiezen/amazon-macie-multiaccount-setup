#!/usr/bin/env python
"""
Copyright 2018 Amazon.com, Inc. or its affiliates.
All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at

   http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file.
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

This script orchestrates the enablement and centralization of GuardDuty across an enterprise of AWS accounts.
It takes in a list of AWS Account Numbers, iterates through each account and region to enable GuardDuty.
It creates each account as a Member in the GuardDuty Master account.
It invites and accepts the invite for each Member account.
"""

import boto3
import sys
import time
import argparse
import re

from collections import OrderedDict
from botocore.exceptions import ClientError

def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call, not required for IAM calls
    :return: Macie client in the specified AWS Account and Region
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')

    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='EnableMacie'
    )
    print(response)

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    print(session)

    print("Assumed session for {}.".format(
        aws_account_number
    ))

    return session


def list_member_accounts(master_session, aws_region):
    """
    Returns a list of current members linked to the Macie master account
    :param aws_region: AWS Region of the Macie master account
    :return: dict of accountId
    """
    print(master_session)
    member_dict = dict()

    macie_client = master_session.client('macie', region_name=aws_region)
    # Need to paginate and iterate over results
    paginator = macie_client.get_paginator('list_member_accounts')
    operation_parameters = {
        "maxResults": 250
    }
    page_iterator = paginator.paginate(**operation_parameters)
    for page in page_iterator:
        print(page['memberAccounts'])
        if page['memberAccounts']:
            for member in page['memberAccounts']:
                member_dict.update({"accountId": member['accountId']})

    return member_dict


def list_s3_resources(master_session, aws_region, member_account_id):
    """
    Returns a list of current S3 Resources from the member account linked to the Macie master account
    :param aws_region: AWS Region of the member account
    :param member_account_id: the member account id to list associated resources
    :return: dict of s3Resources
    """

    bucket_set = set()

    macie_client = master_session.client('macie', region_name=aws_region)

    # Need to paginate and iterate over results
    paginator = macie_client.get_paginator('list_s3_resources')
    operation_parameters = {
        'memberAccountId': member_account_id
    }

    try:
        page_iterator = paginator.paginate(**operation_parameters)

        for page in page_iterator:
            if page['s3Resources']:
                for bucket in page['s3Resources']:
                    bucket_set.add(bucket['bucketName'])

    # Macie returns a 400 with Invalid Input, rather than an empty response, if there are no associated resources
    # Ignoring the 400, and otherwise letting this call fail
    except ClientError as err:
        if not err.response['ResponseMetadata']['HTTPStatusCode'] == 400:
            raise err

    return bucket_set

if __name__ == '__main__':

    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Link AWS Accounts to central Macie Account')
    parser.add_argument('--master_account', type=str, required=True, help="AccountId for Central AWS Account")
    parser.add_argument('input_file', type=argparse.FileType('r'), help='Path to CSV file containing the list of account IDs and S3 resources')
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume in each account")
    parser.add_argument('--enabled_regions', type=str, help="comma separated list of regions to enable Macie. If not specified, all available regions enabled")
    args = parser.parse_args()

    # Validate master accountId
    if not re.match(r'[0-9]{12}', args.master_account):
        raise ValueError("Master AccountId is not valid")

    # Generate dict with account & resource information
    aws_account_dict = OrderedDict()

    for acct in args.input_file.readlines():
        split_line = acct.rstrip().split(",")
        if len(split_line) != 2:
            print("Unable to process line: {}. Expected 2 fields, found {}".format(acct, len(split_line)))
            continue

        if not re.match(r'[0-9]{12}', str(split_line[0])):
            print("Invalid account number {}, skipping".format(split_line[0]))
            continue

        account_id = split_line[0]
        bucket_name = split_line[1]

        if not account_id in aws_account_dict:
            aws_account_dict[account_id] = []

        aws_account_dict[account_id].append(bucket_name)

    # Getting Macie regions
    session = boto3.session.Session()

    macie_regions = []
    if args.enabled_regions:
        macie_regions = [str(item) for item in args.enabled_regions.split(',')]
        print("Enabling members in these regions: {}".format(macie_regions))
    else:
        macie_regions = session.get_available_regions('macie')
        print("Enabling members in all available Macie regions {}".format(macie_regions))

    # Associating member accounts
    failed_master_regions = []
    for account in aws_account_dict.keys():
        try:
            master_session = assume_role(args.master_account, args.assume_role)

            for aws_region in macie_regions:
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))

                macie_client = session.client('macie', region_name=aws_region)

                # List current members
                member_dict = list_member_accounts(master_session, aws_region)

                # If member is not associated, associate it
                if account not in member_dict:
                    macie_client = master_session.client('macie', region_name=aws_region)

                    macie_client.associate_member_account(
                        memberAccountId=account
                    )

                    print('Added {account} to master Macie account in {region}'.format(
                        account=account,
                        region=aws_region
                    ))

                else:
                    print('Account {account} is already a member of the master Macie account in {region}'.format(
                        account=account,
                        region=aws_region
                    ))

        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                print(
                    "Failed to associate Macie in Master account for region: {} due to an authentication error.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the master account.  Skipping {} and attempting to continue").format(
                    aws_region, aws_region)
                failed_master_regions.append(aws_region)

    # Associating member resources
    failed_master_regions = []
    for account in aws_account_dict.keys():
        try:
            buckets_for_account = aws_account_dict[account]
            master_session = assume_role(args.master_account, args.assume_role)

            for aws_region in macie_regions:
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))

                # List current resources associated with Macie in this account
                macie_buckets = list_s3_resources(master_session, aws_region, account)

                buckets_to_add = []

                for bucket in buckets_for_account:
                    if bucket not in macie_buckets:
                        buckets_to_add.append(bucket)

                # If resource is not associated, associate it
                if len(buckets_to_add) > 0:
                    macie_client = master_session.client('macie', region_name=aws_region)

                    s3_resources = []
                    for bucket_to_add in buckets_to_add:
                        s3_resources.append(
                            {
                                'bucketName': bucket_to_add,
                                'classificationType': {
                                    'oneTime': 'FULL',
                                    'continuous': 'FULL'
                                }
                            }
                        )

                    macie_response = macie_client.associate_s3_resources(
                        memberAccountId=account,
                        s3Resources = s3_resources
                    )

                    for failed_bucket in macie_response['failedS3Resources']:
                        bucket_name = failed_bucket['failedItem']['bucketName']
                        error_message = failed_bucket['errorMessage']
                        print(f"Failed to associate bucket {bucket_name} for account {account} in region {aws_region}. Error: {error_message}")

                    print(F"Added {len(buckets_to_add) - len(macie_response['failedS3Resources'])} buckets for account {account} in region {aws_region}")

                else:
                    print(F"All buckets from {account} are already associated to the master Macie account in {aws_region}")

        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                print(
                    "Failed to associate Macie in Master account for region: {} due to an authentication error.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the master account.  Skipping {} and attempting to continue").format(
                    aws_region, aws_region)
                failed_master_regions.append(aws_region)
