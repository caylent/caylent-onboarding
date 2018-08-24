#!/bin/bash
#
# Purpose: to create AWS users with read-only permissions for auditing.
# 
# The script will create a new group with the ReadOnlyAccess policty attached 
# to it. It also will create 'N' users (according to user input) as members of 
# the new group and will create custom AWS policies for each one (to allow them 
# to update their own passwords, access keys and MFAs).
#

function validate_aws_cli()
{
 if ! type aws > /dev/null 2>&1 ; then
   echo -e "\e[31mRequirements not met. Install and setup AWS CLI to proceed."
   echo -e "Get installation instructions from:\e[0m"
   echo 
   echo "docs.aws.amazon.com/cli/latest/userguide/installing.html"
   echo 
   exit 1
 fi

 if [[ ! -f ~/.aws/config ]]; then
   echo -e "\e[31mNo AWS profile found. Setup AWS CLI to continue."
   echo -e "Get setup instructions from:\e[0m"
   echo 
   echo "docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html"
   echo 
   exit 1
 fi
} 

function set_aws_cli_profile()
{
 read -p "Enter the name of the AWS CLI profile to use [default]: " AWS_PROFILE
 echo
 if [ -z "$AWS_PROFILE" ]; then
   AWS_PROFILE="default"
 fi  

 # Check user entered a valid AWS profile
 aws ec2 describe-availability-zones --profile "${AWS_PROFILE}" > /dev/null 2>&1
 if [ $? -ne 0 ]; then
   echo -e "\e[31mThe profile you entered is not correct." \
   "Please double check it.\e[0m" 
   echo 
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
# 'ReadOnlyAccess' to it. 
#
# Globals:
#   AWS_PROFILE
#   AWS_GROUP
# Args:
#   None
# Returns:
#   None
# Exit Code:
#   0: Success
#
#### create_aws_group ######
function create_aws_group()
{
  valid_aws_group=false
  
  while ! ${valid_aws_group}; do
    read -p "Enter the name of the AWS group to create: " AWS_GROUP
    
    aws iam get-group --group-name "${AWS_GROUP}" \
      --profile "${AWS_PROFILE}" > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
      echo -e "\e[31mGroup already exists. Please specify a new one to avoid" \
      "potentinal issues with your current settings.\e[0m" 
      echo 
    else
      echo "Creating AWS group ${AWS_GROUP}..."
      aws iam create-group --group-name "${AWS_GROUP}" \
        --profile "${AWS_PROFILE}" > /dev/null 2>&1
      
      echo "Attaching ReadOnlyAccess policy to group ${AWS_GROUP}..."
      echo 
      aws iam attach-group-policy --group-name "${AWS_GROUP}" \
        --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess \
        --profile "${AWS_PROFILE}" > /dev/null 2>&1
      
      valid_aws_group=true
    fi  
  done
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
# They are added to the group created by function create_aws_group.
# A custom policy (created by function create_aws_policy_document) is attached
# to each one, for allowing the user to change its password/access keys/MFA.
#
# Globals:
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
  valid_count=false

  while ! "${valid_count}"; do
    read -p "Enter the number of AWS users to create: " aws_user_count 
    if ! [[ "${aws_user_count}" =~ ^[1-9]+$ ]]; then
      echo -e "\e[31mInvalid input.\e[0m"
      echo
    else 
      echo
      valid_count=true
    fi
  done  

  for count in $(seq 1 "${aws_user_count}"); do 
    valid_aws_user=false
    
    while ! ${valid_aws_user}; do
      read -p "Enter the name of the AWS user to create ($count): " AWS_USER
      echo "Creating AWS user ${AWS_USER}..."
      
      # Check the AWS user does not exist before creating it
      aws iam get-user --user-name "${AWS_USER}" \
        --profile "${AWS_PROFILE}" > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        echo -e "\e[31mUser already exists. Please specify another one.\e[0m"
        echo 
      else
        aws iam create-user --user-name "${AWS_USER}" \
          --profile "${AWS_PROFILE}" > /dev/null 2>&1
      
        # Check password meet company's Password Policy
        valid_password=false
        while ! ${valid_password}; do
          read -p "Enter the password. User will be prompt to change it: " \
            aws_user_password
          
          aws iam create-login-profile --user-name "${AWS_USER}" \
            --password "${aws_user_password}" \
            --password-reset-required \
            --profile "${AWS_PROFILE}" > /dev/null 2>&1

          if [ $? -ne 0 ]; then
            echo -e "\e[31mPassword doesn't meet company password policy." \
            "Please try again.\e[0m"
          else
            valid_password=true  
          fi  
        done

        echo "Adding ${AWS_USER} to group ${AWS_GROUP}..."
        echo 
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

        valid_aws_user=true
        echo "User ${AWS_USER} successfully created."
        echo
      fi  
    done
  done
  rm /tmp/policy.json
}

clear;
validate_aws_cli;
set_aws_cli_profile;
get_aws_account;
create_aws_group;
create_aws_users;