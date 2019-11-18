# amazon-macie-multiaccount-setup

This script automates the process of enabling Amazon Macie simultaneously across a group of AWS accounts that are in your control. (Note, that you can have one master account and up to a 10 member accounts).

enablemacie.py will enable Macie, send handshakes from the master account and accept handshakes in all member accounts. It will also create the AWSServiceRoleForAmazonMacie in each account that Macie needs to operate. The result will be a master account that contains all security findings for all member accounts. Since Macie is regionally isolated, findings for each member account will roll up to the corresponding region in the master account. For example, the us-east-1 region in your Macie master account will contain the security findings for all us-east-1 findings from all associated member accounts.

## License Summary
This sample code is made available under a modified MIT license. See the LICENSE file.

## Prerequisites

* The script depends on a pre-existing role in the master account and all of the member accounts that will be linked, the role must be named AmazonMacieHandshakeRole in all accounts and the role trust relationship needs to allow the Macie service to assume the role. The AmazonMacieHandshakeRole managed poilicy (shown below) contains the required permissions for the script to succeed:

``` 
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "macie.amazonaws.com"
                }
            }
        }
    ]
}
```

You can use the EnableMacie.yaml CloudFormation Template to automate the handshake Role creation, as the template creates only global resources it can be created in any region.  

* A CSV file that includes the list of accounts and resources to be linked to the master account.  Accounts and resources should be listed one per line in the format of AccountId,BucketName. The BucketName must be in the same region you are enabling Macie.
* Master AccountId which will recieve findings for all the linked accounts within the CSV file 

## Steps
### 1. Setup execution environment:
#### Option 1: Launch EC2 instance:
* Launch ec2 instance in your master account https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html
* Attach an IAM role to an instance that has permissions to allow the instance to call AssumeRole within the master account, if you used the EnableMacie.yaml template an instance role with a profile name of "EnableMacie" has been created, otherwise see the documentation on creating an instance role here:  https://aws.amazon.com/blogs/security/easily-replace-or-attach-an-iam-role-to-an-existing-ec2-instance-by-using-the-ec2-console/ on creating an instance role.
* Install required software
    * APT: sudo apt-get -y install python2-pip python2 git
    * RPM: sudo yum -y install python2-pip python2 git
    * sudo pip install boto3
* Clone the Repository
    * git clone https://github.com/aws-samples/amazon-macie-multiaccount-setup.git
* Copy the CSV containing the account numbers and bucket names to the instance using one of the methods below
    * S3 `s3 cp s3://bucket/key_name enable.csv .`
    * pscp.exe `pscp local_file_path username@hostname:.`
    * scp `scp local_file_path username@hostname:.`
    
#### Option 2: Locally:
* Ensure you have credentials setup on your local machine for your master account that have permission to call AssumeRole.
* Install Required Software:
    * Windows:
        * Install Python https://www.python.org/downloads/windows/
        * Open command prompt:
            * pip install boto3
        * Download sourcecode from https://github.com/aws-samples/amazon-macie-multiaccount-setup
        * Change directory of command prompt to the newly downloaded amazon-macie-multiaccount-setup folder
    * Mac:
        * Install Python https://www.python.org/downloads/mac-osx/
        * Open command prompt:
            * pip install boto3
        * Download sourcecode from https://github.com/aws-samples/amazon-macie-multiaccount-setup
        * Change directory of command prompt to the newly downloaded amazon-macie-multiaccount-setup folder
    * Linux:
        * sudo apt-get -y install install python2-pip python2 git
        * sudo pip install boto3
        * git clone https://github.com/aws-samples/amazon-macie-multiaccount-setup
        * cd amazon-macie-multiaccount-setup
        Or
        * sudo yum install git python
        * sudo pip install boto3
        * git clone https://github.com/aws-samples/amazon-macie-multiaccount-setup
        * cd amazon-macie-multiaccount-setup
        
### 2. Execute Scripts
#### 2a. Enable Macie
* Copy the required CSV file to this directory
    * Should be in the formation of "AccountId,BucketName" with one AccountID and BucketName per line.

```
usage: enablemacie.py [-h] --master_account MASTER_ACCOUNT --assume_role
                          ASSUME_ROLE
                          input_file

Link AWS Accounts to central Macie Account

positional arguments:
  input_file            Path to CSV file containing the list of account IDs
                        and Bucket names

optional arguments:
  -h, --help            show this help message and exit
  --master_account MASTER_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account
  
```
