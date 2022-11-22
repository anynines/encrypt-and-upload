# Encrypt and upload

## Overview

This script does several things:

  1. It identifies a set of files in a configurable directory using a [Regular Expression](https://en.wikipedia.org/wiki/Glob_(programming))
  1. It encrypts these files using a configurable encryption method. (Default: [Ccrypt](https://en.wikipedia.org/wiki/Ccrypt))
  1. It uploads the encrypted files to a configurable location using a configurable tranfer method (rsync, S3)

The script does the encryption and upload in parallel to maximize the usage of available computing resources.

## Authors

* [Khaled Blah](https://github.com/khaledavarteq)
* [Maximilian Müller](https://github.com/mmueller-a9s)

## License

See [LICENSE](./LICENSE)
