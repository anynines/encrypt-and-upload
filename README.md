# Encrypt and upload

This script does several things:

  1. It finds a set of files in directory using a RegEx
  1. It encrypts these files using configurable encryption method.
  1. It uploads the encrypted files to a configurable location using a configurable tranfer method (rsync, S3)

The script does the encryption and upload in parallel to maximize the usage of available computing resources.