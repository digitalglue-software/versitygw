#!/usr/bin/env bats

# check if object exists both on S3 and locally
# param:  object path
# 0 for yes, 1 for no, 2 for error
object_exists_remote_and_local() {
  if [ $# -ne 1 ]; then
    echo "object existence check requires single name parameter"
    return 2
  fi
  object_exists "aws" "$1" || local exist_result=$?
  if [[ $exist_result -eq 2 ]]; then
    echo "Error checking if object exists"
    return 2
  fi
  if [[ $exist_result -eq 1 ]]; then
    echo "Error:  object doesn't exist remotely"
    return 1
  fi
  if [[ ! -e "$LOCAL_FOLDER"/"$1" ]]; then
    echo "Error:  object doesn't exist locally"
    return 1
  fi
  return 0
}

# check if object doesn't exist both on S3 and locally
# param:  object path
# return 0 for doesn't exist, 1 for still exists, 2 for error
object_not_exists_remote_and_local() {
  if [ $# -ne 1 ]; then
    echo "object non-existence check requires single name parameter"
    return 2
  fi
  object_exists "aws" "$1" || local exist_result=$?
  if [[ $exist_result -eq 2 ]]; then
    echo "Error checking if object doesn't exist"
    return 2
  fi
  if [[ $exist_result -eq 0 ]]; then
    echo "Error:  object exists remotely"
    return 1
  fi
  if [[ -e "$LOCAL_FOLDER"/"$1" ]]; then
    echo "Error:  object exists locally"
    return 1
  fi
  return 0
}

# check if a bucket doesn't exist both on S3 and on gateway
# param: bucket name
# return:  0 for doesn't exist, 1 for does, 2 for error
bucket_not_exists_remote_and_local() {
  if [ $# -ne 1 ]; then
    echo "bucket existence check requires single name parameter"
    return 2
  fi
  bucket_exists "aws" "$1" || local exist_result=$?
  if [[ $exist_result -eq 2 ]]; then
    echo "Error checking if bucket exists"
    return 2
  fi
  if [[ $exist_result -eq 0 ]]; then
    echo "Error:  bucket exists remotely"
    return 1
  fi
  if [[ -e "$LOCAL_FOLDER"/"$1" ]]; then
    echo "Error:  bucket exists locally"
    return 1
  fi
  return 0
}

# check if a bucket exists both on S3 and on gateway
# param: bucket name
# return:  0 for yes, 1 for no, 2 for error
bucket_exists_remote_and_local() {
  if [ $# -ne 1 ]; then
    echo "bucket existence check requires single name parameter"
    return 2
  fi
  bucket_exists "aws" "$1" || local exist_result=$?
  if [[ $exist_result -eq 2 ]]; then
    echo "Error checking if bucket exists"
    return 2
  fi
  if [[ $exist_result -eq 1 ]]; then
    echo "Error:  bucket doesn't exist remotely"
    return 1
  fi
  if [[ ! -e "$LOCAL_FOLDER"/"$1" ]]; then
    echo "Error:  bucket doesn't exist locally"
    return 1
  fi
  return 0
}