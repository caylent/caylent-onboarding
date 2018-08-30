#!/bin/bash
#
# Purpose: to create AWS users with read-only permissions for auditing.
# 
# The script will create a new group with the ReadOnlyAccess policy attached 
# to it. It also will create 'N' users (according to user input) as members of 
# the new group and will create custom AWS policies for each one (to allow them 
# to update their own passwords, access keys and MFAs).
#

function usage() {
 echo "  Usage:"
 echo -e "    $0 [-u=\"user1 user2\"]\n"
 echo "  Example:"
 echo -e "    $0 -u=\"john peter\"\n"
 exit 1
}

function check_flag() {
 users="stefan ignacio"
 if [ $# -ne 0 ]; then
  for i in "$@"; do
    case $i in 
      -u=*|--users=*)
        users="${i#*=}"
        ;;
      *) 
        usage
        ;;
    esac
  done
 fi 
 IFS=' ' read -r -a USER_ARRAY <<< $users 
}

function validate_aws_cli()
{
 # Check AWS CLI is installed 
 if ! type aws > /dev/null 2>&1 ; then
   url="docs.aws.amazon.com/cli/latest/userguide/installing.html"
   echo -e "\e[31m[ERROR] Requirements not met. Install and setup" \
   "AWS CLI to proceed."
   echo -e "Get installation instructions from:\e[0m\n"
   echo -e "${url}\n"
   exit 1
 fi

 # Check AWS CLI is configured
 if [[ ! -f ~/.aws/config ]]; then
   url="docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html"
   echo -e "\e[31m[ERROR] No AWS profile found. Setup AWS CLI to continue."
   echo -e "Get setup instructions from:\e[0m\n"
   echo -e "${url}\n"
   exit 1
 fi
} 

function load_aws_cli_profile()
{
 read -p "Enter the name of the AWS CLI profile to use [default]: " AWS_PROFILE
 if [ -z "$AWS_PROFILE" ]; then
   AWS_PROFILE="default"
 fi  

 # Check user entered a valid AWS profile
 aws ec2 describe-availability-zones --profile "${AWS_PROFILE}" > /dev/null 2>&1
 if [ $? -ne 0 ]; then
   echo -e "\e[31m[ERROR] The profile you entered is not correct." \
   "Please double check it and try again.\e[0m\n" 
   exit 1
 fi  
}

function get_aws_account()
{
 AWS_ACCOUNT=$(aws sts get-caller-identity --output text \
   --query 'Account' --profile "${AWS_PROFILE}")
}

#### create_aws_group ######
#
# A function for creating a new AWS group and attach the AWS policy 
# 'ReadOnlyAccess' to it. It will return exit code 1 if the group exists.
#
# Example:
#   create_aws_group - will create a new AWS user according to user input
#                      but will fail if the group already exists.
# Globals:
#   AWS_PROFILE
#   AWS_GROUP
# Args:
#   None
# Returns:
#   None
# Exit Code:
#   0: Success
#   1: Failure
#
#### create_aws_group ######
function create_aws_group()
{
  echo ; read -p "Enter the name of the AWS group to create: " AWS_GROUP

  if [ -z "${AWS_GROUP}" ]; then
    echo -e "\e[31m[ERROR] Invalid input.\e[0m\n" 
    exit 1
  fi  
  
  aws iam get-group --group-name "${AWS_GROUP}" \
    --profile "${AWS_PROFILE}" > /dev/null 2>&1
    
  if [ $? -eq 0 ]; then
    echo -e "\e[31m[ERROR] Group already exists. Please specify a new one" \
    "to avoid potentinal issues with your current settings.\e[0m\n" 
    exit 1
  else
    echo "[INFO] Creating AWS group ${AWS_GROUP}..."
    aws iam create-group --group-name "${AWS_GROUP}" \
      --profile "${AWS_PROFILE}" > /dev/null 2>&1
    
    echo -e "[INFO] Attaching ReadOnlyAccess policy to group ${AWS_GROUP}...\n"
    aws iam attach-group-policy --group-name "${AWS_GROUP}" \
      --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess \
      --profile "${AWS_PROFILE}" > /dev/null 2>&1
  fi  
}

function create_aws_policy_document()
{
cat << EOF > /tmp/policy.json
{
        "Version": "2012-10-17",
        "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:DeleteAccessKey",
                "iam:GetAccessKeyLastUsed",
                "iam:UpdateAccessKey",
                "iam:CreateAccessKey",
                "iam:ListAccessKeys"
            ],
            "Resource": "arn:aws:iam::${AWS_ACCOUNT}:user/${AWS_USER}"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:DeactivateMFADevice",
                "iam:DeleteVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:ResyncMFADevice",
                "iam:CreateVirtualMFADevice",
                "iam:ListVirtualMFADevices",
                "iam:ListMFADevices"
            ],
            "Resource": [
                "arn:aws:iam::${AWS_ACCOUNT}:mfa/${AWS_USER}",
                "arn:aws:iam::${AWS_ACCOUNT}:user/${AWS_USER}"
            ]
        },
	    {
            "Effect": "Allow",
            "Action": [
                "iam:ChangePassword",
                "iam:UpdateLoginProfile"
            ],
            "Resource": "arn:aws:iam::${AWS_ACCOUNT}:user/${AWS_USER}"
        }
        ]
}
EOF
}

#### create_aws_users ######
#
# A function for creating 'N' AWS users (according to user input).
# If no flag is specified when executing the main script, users 
# stefan and ignacio are created by default.
# Users are added to the group created by function create_aws_group.
# A custom policy (created by function create_aws_policy_document) is attached
# to each one, for allowing the user to change its password/access keys/MFA.
#
# Example:
# create_aws_users - will create 'N' new AWS users according to what was 
#                    specified with the flag -u when executing the script
#
# Globals:
#   USER_ARRAY
#   AWS_PROFILE
#   AWS_USER
#   AWS_GROUP
# Args:
#   None
# Returns:
#   None
# Exit Code:
#  0: Success
#
#### create_aws_users ######
function create_aws_users
{
  if [ "${USER_ARRAY[*]}" = "stefan ignacio" ]; then
    echo -e "[INFO] No users were specified (-u=\"user1 user2\"). Creating"\
    "Stefan and Ignacio by default...\n"  
  fi  

  for AWS_USER in ${USER_ARRAY[*]}; do 
    # Check the AWS user does not exist before creating it
    aws iam get-user --user-name "${AWS_USER}" \
      --profile "${AWS_PROFILE}" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo -e "[WARNING] Duplicated user: ${AWS_USER} already exists"\
      "and won't be created. Continuing...\n"
    else
      aws iam create-user --user-name "${AWS_USER}" \
        --profile "${AWS_PROFILE}" > /dev/null 2>&1
      
      # Check password meet company's Password Policy
      valid_password=false
      while ! ${valid_password}; do
        echo -e "[INFO] Creating user ${AWS_USER}"
        read -p "Enter the password. User will be prompt to change it: " \
          aws_user_password
          
        aws iam create-login-profile --user-name "${AWS_USER}" \
          --password "${aws_user_password}" \
          --password-reset-required \
          --profile "${AWS_PROFILE}" > /dev/null 2>&1

        if [ $? -ne 0 ]; then
          echo -e "[WARNING] Password doesn't meet company" \
          "password policy. Please try again."
        else
          valid_password=true  
        fi  
      done

      echo -e "[INFO] Adding ${AWS_USER} to group ${AWS_GROUP}..."
      aws iam add-user-to-group --user-name "${AWS_USER}" \
        --group-name "${AWS_GROUP}" --profile "${AWS_PROFILE}" >/dev/null 2>&1
        
      create_aws_policy_document
      policy_name="allow_change_MFA_and_keys_${AWS_USER}"
      policy_arn="arn:aws:iam::${AWS_ACCOUNT}:policy/${policy_name}"

      aws iam create-policy --policy-name "$policy_name" \
        --policy-document file:///tmp/policy.json \
        --profile "${AWS_PROFILE}" > /dev/null 2>&1
                
      aws iam attach-user-policy --user-name "${AWS_USER}" \
        --policy-arn "${policy_arn}" \
        --profile "${AWS_PROFILE}" > /dev/null 2>&1

      echo -e "[INFO] User ${AWS_USER} successfully created.\n"
      rm /tmp/policy.json
    fi  
  done
}

clear;
check_flag "$@";
validate_aws_cli;
load_aws_cli_profile;
get_aws_account;
create_aws_group;
create_aws_users;