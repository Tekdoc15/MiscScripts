#!/bin/bash
## Updating/rewriting our old check script which was written pre vuln patches 3/5/24 - jgra351

## Script coming back with "No log4j found on this machine." is not a garantee that system is
## fully secure and due diligence should still be followed in patching systems


## Current minimum version required per CISA (as of 3/5/24)
## https://github.com/cisagov/log4j-affected-db
required_version=2.17.1

## Ensure we are root

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root"
   exit 1
fi

## Verify that we have needed/required tools

which unzip
z=$?
if [ $z -ne 0 ]; then
                echo "unzip not found"
                echo "please install unzip"
                exit 1
        else
                echo "unzip found proceeding"
fi

# Function to compare versioning (maj.min.patch)
ver_compare()
{
  if [[ "$1" == "$2" ]]
  then
    # Versions are equal
    echo "equal"
    exit
  fi

  # Converts parameters to arrays
  # 0 - Major
  # 1 - Minor
  # 2 - Patch

  local _version_1=()
  local _version_2=()
  IFS='.' read -ra _version_1 <<< "${1}"
  local _version_2=()
  IFS='.' read -ra _version_2 <<< "${2}"
  local i
  unset IFS

  for ((i=0; i<${#_version_2[@]}; i++))
  do
    if [ "${_version_1[$i]}" -gt "${_version_2[$i]}" ]
    then
      echo "greater"
      exit
    fi
    if [ "${_version_1[$i]}" -lt "${_version_2[$i]}" ]
    then
      echo "less"
      exit
    fi
  done

}

# Store all top level directories on the system in a variable
system_directories=$(df -l -P | tail -n +2 | awk '{print $6}' | tr '\n' ' ')

# Find all files matching log4j-core-2*.jar in system directories
log4j_jars=$(find $system_directories -xdev -type f -name 'log4j-core-2*jar')

# Create a variable to track if we find any vulnerable files
vulnerabilities_found=0

if [ "$log4j_jars" != '' ]; then
  # Iterate over the files found
  while IFS= read -r log4j_fullpath
  do
    # Get the file name
    log4j_filename=$(awk -F"/" '{print $NF}' <<< "${log4j_fullpath}")
    # Get the log4j version
    log4j_version=$(awk -F"-" '{print $NF}' <<< "${log4j_filename::${#log4j_filename}-4}")
    # Compare versions
    version_cmp=$(ver_compare "$log4j_version" "$required_version")

    # Check if it is a vulnerable version.
    case $version_cmp in
      # Versions are equal
      equal) echo "$log4j_fullpath is PATCHED";;
      # log4j_version is higher than required_version
      greater) echo "$log4j_fullpath is PATCHED";;
      # log4j_version is lower than required_version
      less)
        # Test if the vulnerable version has JndiLookup.class
        if /usr/bin/unzip -l "$log4j_fullpath" | grep -q org/apache/logging/log4j/core/lookup/JndiLookup.class; then
          echo "$log4j_fullpath is VULNERABLE"
          vulnerabilities_found=1
        else
          echo "$log4j_fullpath is PATCHED"
        fi
        ;;
      *) echo "failed to compare versions";;
    esac

  done  < <(printf '%s\n' "$log4j_jars")

  exit $vulnerabilities_found

else
  echo "No log4j found on this machine.";
  exit $vulnerabilities_found
fi
