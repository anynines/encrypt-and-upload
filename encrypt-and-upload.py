#!/usr/bin/env python

import argparse
import datetime
import fnmatch
import logging
import logging.handlers
import multiprocessing
import os
import pwd
import random
import shutil
import subprocess
import sys
import tarfile
import time
import yaml

from glob import glob
from multiprocessing import Pool, TimeoutError
from subprocess import call

def findfiles(directory, pattern):
  return [y for x in os.walk(directory) for y in glob(os.path.join(x[0], pattern))]

class Encrypter(multiprocessing.Process):
  def __init__(self, config, queue_encrypt, queue_uploads):
    multiprocessing.Process.__init__(self)
    self.config = config
    self.queue_encrypt = queue_encrypt
    self.queue_uploads = queue_uploads

  def run(self):
    logger = logging.getLogger("main")
    proc_name = self.name
    while True:
      next_file = self.queue_encrypt.get()

      if next_file is None:
        logger.info('%s: Done' % proc_name)
        self.queue_encrypt.task_done()
        break

      next_file = os.path.realpath(next_file)
      queue_file = next_file

      command = []
      if config['encrypt']['type'] == 'none':
        logger.info("Not encrypting: %s (%s)" % (next_file, proc_name))
        if not config['dry_run']:
          # ugly hack: for some reason this "sleep" is needed, otherwise we'll
          # run into a race condition/timing issue with the "queue_uploads"
          # queue
          time.sleep(random.random() * 0.1)

      if config['encrypt']['type'] == 'ccrypt':
        queue_file += config['encrypt']['suffix']
        logger.info("Encrypting: %s (%s)" % (next_file, proc_name))
        command = [
          'ccrypt',
          '--encrypt',
          '--keyfile',
          config['encrypt']['keyfile'],
          '--suffix',
          config['encrypt']['suffix'],
          next_file
        ]
        logger.debug('%s: %s' % (proc_name, ' '.join(command)))

      if not config['dry_run']:
        if len(command) > 0:
          process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
          output, _ = process.communicate()
          logger.info(output)
      else:
        time.sleep(random.random() * 0.1)

      self.queue_encrypt.task_done()
      self.queue_uploads.put(queue_file)
    return

class Uploader(multiprocessing.Process):
  def __init__(self, config, queue_uploads):
    multiprocessing.Process.__init__(self)
    self.config = config
    self.queue_uploads = queue_uploads

  def run(self):
    logger = logging.getLogger("main")
    proc_name = self.name
    while True:
      next_file = self.queue_uploads.get()

      if next_file is None:
        logger.info('%s: Done' % proc_name)
        self.queue_uploads.task_done()
        break

      logger.info("Uploading: %s (%s)" % (next_file, proc_name))

      command = []
      if config['upload']['type'] == 'rsync':
        rsh_string = "--rsh=/usr/bin/sshpass -f %s ssh -o StrictHostKeyChecking=no -l %s" % (config['upload']['rsync']['password_file'], config['upload']['rsync']['username'])
        command = [
          'rsync',
          rsh_string,
          next_file
        ]

        dest_string = config['upload']['rsync']['host'] + ':'
        if 'prefix' in config['upload']['rsync'].keys():
          dest_string += config['upload']['rsync']['prefix']

        dest_string += '/' + os.path.basename(next_file)
        command.append(dest_string)

      if config['upload']['type'] == 's3':
        command = [
          '/usr/local/bin/aws',
          '--profile',
          config['upload']['s3']['profile'],
          's3',
          'cp',
          next_file
        ]

        dest_string = 's3://' + config['upload']['s3']['profile'] + '/'
        if 'prefix' in config['upload']['s3'].keys():
          dest_string += config['upload']['s3']['prefix'] + '/'

        dest_string += os.path.basename(next_file)
        command.append(dest_string)

      if config['upload']['type'] == 'copy':
        dest_file = os.path.join(config['upload']['copy']['path'], os.path.basename(next_file))
        logger.info("Copying file '%s' to '%s'" % (next_file, dest_file))
        if not config['dry_run']:
          shutil.copyfile(next_file, dest_file)

        if not config['dry_run'] and 'owner' in config['upload']['copy'].keys():
          uid = pwd.getpwnam(config['upload']['copy']['owner']).pw_uid
          gid = pwd.getpwnam(config['upload']['copy']['owner']).pw_gid
          os.chown(dest_file, uid, gid)

        if not config['dry_run'] and 'mode' in config['upload']['copy'].keys():
          mode = config['upload']['copy']['mode']
          if type(config['upload']['copy']['mode']) is str:
            mode = int(config['upload']['copy']['mode'], 8)
          os.chmod(dest_file, mode)

      logger.debug('%s: %s' % (proc_name, ' '.join(command)))
      if not config['dry_run']:
        if len(command) > 0:
          process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
          output, _ = process.communicate()
          logger.info(output)
      else:
        time.sleep(random.random() * 0.1)

      self.queue_uploads.task_done()
    return

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description = 'Read configuration')
  parser.add_argument('--config', required=True, dest='config',
                      help='path to configuration file (YAML)')
  parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                      default=False,
                      help='If specified, commands will not executed')

  args = parser.parse_args()

  files = []
  with open(args.config, 'r') as stream:
    try:
      config = yaml.load(stream)

      for dir_conf in config['directories']:
        files += findfiles(dir_conf['path'], dir_conf['regex'])
    except yaml.YAMLError as exc:
      print(exc)

  config['dry_run'] = args.dry_run

  if not 'log_file' in config.keys():
    config['log_file'] = '/var/log/encrypt-and-upload.log'

  if not 'log_level' in config.keys():
    config['log_level'] = 'DEBUG'

  # The logger object for this scripts
  logger = logging.getLogger("main")
  logger.setLevel(config['log_level'])

  # create the logging file handler
  needRoll = os.path.isfile(config['log_file'])
  fh = logging.handlers.RotatingFileHandler(config['log_file'], backupCount=50)
  fh.setLevel(config['log_level'])

  formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
  fh.setFormatter(formatter)
  logger.addHandler(fh)
  if needRoll:
    logger.handlers[0].doRollover()

  if len(files) == 0:
    logger.info("No files were found in any of the directories!")
    sys.exit(0)

  if 'encrypt' not in config.keys() or 'type' not in config['encrypt'].keys():
    logger.fatal("No encryption configuration specified!")
    sys.exit(1)

  if config['encrypt']['type'] == 'ccrypt':
    for var in ['keyfile', 'suffix']:
      if var not in config['encrypt'].keys():
        logger.fatal("Encryption with ccrypt requested but %s not specified!" % var)
        sys.exit(1)

  if 'upload' not in config.keys() or 'type' not in config['upload'].keys():
    logger.fatal("No upload configuration specified!")
    sys.exit(2)

  if config['upload']['type'] == 'rsync' and 'rsync' not in config['upload'].keys():
    logger.fatal("No rsync configuration specified!")
    sys.exit(2)

  if config['upload']['type'] == 'rsync':
    for var in ['host', 'username', 'password_file']:
      if var not in config['upload']['rsync'].keys():
        logger.fatal("Upload using rsync requested but '%s' not specified!" % var)
        sys.exit(2)

  if config['upload']['type'] == 's3' and 's3' not in config['upload'].keys():
    logger.fatal("No s3 configuration specified!")
    sys.exit(2)

  if config['upload']['type'] == 's3':
    for var in ['profile', 'bucket']:
      if var not in config['upload']['s3'].keys():
        logger.fatal("Upload using s3 requested but '%s' not specified!" % var)
        sys.exit(2)

  if config['upload']['type'] == 'copy' and 'copy' not in config['upload'].keys():
    logger.fatal("No copy configuration specified!")
    sys.exit(2)

  if config['upload']['type'] == 'copy':
    for var in ['path']:
      if var not in config['upload']['copy'].keys():
        logger.fatal("Upload using copy requested but '%s' not specified!" % var)
        sys.exit(2)

  queue_encrypt = multiprocessing.JoinableQueue()
  queue_uploads = multiprocessing.JoinableQueue()
  num_consumers = min(4, multiprocessing.cpu_count() - 2)

  encrypters = [ Encrypter(config, queue_encrypt, queue_uploads)
                for i in xrange(num_consumers) ]
  for w in encrypters:
    w.start()

  uploaders = [ Uploader(config, queue_uploads)
                for i in xrange(num_consumers) ]
  for w in uploaders:
    w.start()

  for file_path in files:
    queue_encrypt.put(file_path)

  for i in xrange(num_consumers):
    queue_encrypt.put(None)
  queue_encrypt.join()

  for i in xrange(num_consumers):
    queue_uploads.put(None)
  queue_uploads.join()
