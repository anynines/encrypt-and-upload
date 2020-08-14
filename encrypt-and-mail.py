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
import smtplib
import subprocess
import sys
import tarfile
import time
import yaml

from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from multiprocessing import Pool, TimeoutError
from subprocess import call

class CertificateManager():
  def __init__(self, config):
    self.config = config
  
  def run(self):
    logger = logging.getLogger("main")
    proc_name = self.name
    domain_objects = []
    for domain in config['certificates']['domains']:
      full_cert_path = os.path.join(config['certificates']['file_path'], domain, 'cert.pem')
      cert_file = open(full_cert_path, mode='r')
      cert_pem = cert_file.read()
      cert_file.close()

      cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
      cert_fingerprint = cert.fingerprint(hashes.SHA256())

      sent_file_path_full = os.path.join(config['certificates']['sent_file_path'], cert_fingerprint)
      if not os.path.isfile(sent_file_path_full):
        logger.info("Sending certificate for domain: %s" % domain)
        domain_objects.push({'domain': domain, 'fingerprint': cert_fingerprint})
    return domain_objects

class Encrypter():
  def __init__(self, config, domain_objects):
    self.config = config
    self.domain_objects = domain_objects

  def run(self):
    logger = logging.getLogger("main")
    proc_name = self.name

    zip_paths = []
    for domain_object in domain_objects:
      if config['encrypt']['type'] == 'none':
        logger.info("Not encrypting: %s (%s)" % (domain_object['domain'], proc_name))
        if not config['dry_run']:
          # ugly hack: for some reason this "sleep" is needed, otherwise we'll
          # run into a race condition/timing issue with the "queue_uploads"
          # queue
          time.sleep(random.random() * 0.1)

      if config['encrypt']['type'] == '7zip':
        tar_command = [
          '/bin/tar',
          'cpvfh',
          "%s.tar" % domain_object['domain'],
          domain_object['domain']
        ]
        logger.debug("%s: execute '%s'" % (proc_name, ' '.join(tar_command)))

        if not config['dry_run']:
          if len(tar_command) > 0:
            process = subprocess.Popen(
              tar_command,
              cwd=config['certificates']['file_path'],
              stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT
            )
            output, _ = process.communicate()
            logger.info(output)
            if process.returncode > 0:
              logger.fatal("Creating the TAR archive failed for domain: %s" % domain_object['domain'])
              sys.exit(3)
        else:
          time.sleep(random.random() * 0.1)

        full_tar_path = os.path.join(config['certificates']['file_path'], "%s.tar" % domain_object['domain'])
        logger.info("Encrypting: %s (%s)" % (full_tar_path, proc_name))
        zip_command = [
          '/usr/bin/7z',
          'a',
          '-mx=9',
          '-mhe',
          '-t7z',
          "-p%s" % config['encrypt']['key'],
          "%s.7z" % domain_object['domain'],
          "%s.tar" % domain_object['domain']
        ]
        logger.debug("%s: execute '%s'" % (proc_name, ' '.join(zip_command)))

        if not config['dry_run']:
          if len(zip_command) > 0:
            process = subprocess.Popen(
              zip_command,
              cwd=config['certificates']['file_path'],
              stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT
            )
            output, _ = process.communicate()
            logger.info(output)
            if process.returncode > 0:
              logger.fatal("Encrypting the TAR archive failed for domain: %s" % domain_object['domain'])
              sys.exit(3)
            
            full_zip_path = os.path.join(config['certificates']['file_path'], "%s.7z" % domain_object['domain'])
            zip_paths.push({
              'domain': domain_object['domain'],
              'fingerprint': domain_object['fingerprint'],
              'zip_path': full_zip_path
            })

          if os.path.exists(full_tar_path):
            os.remove(full_tar_path)
        else:
          time.sleep(random.random() * 0.1)
    return zip_paths

class Uploader():
  def __init__(self, config, zip_paths):
    self.config = config
    self.zip_paths = zip_paths

  def run(self):
    logger = logging.getLogger("main")
    proc_name = self.name

    for zip_path in zip_paths:
      logger.info("Uploading: %s (%s)" % (zip_path['domain'], proc_name))
      if config['upload']['type'] == 'email':
        msg = MIMEMultipart()
        msg['From'] = config['upload']['email']['sender']
        msg['To'] = COMMASPACE.join(config['upload']['email']['recipients'])
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = "New certificate for domain: %s" % zip_path['domain']

        msg.attach(MIMEText("Find the latest SSL/TLS certificate for domain '%s' attached to this email and encrypted with the agreed upon key\n\n" %s zip_path['domain']))

        with open(zip_path['zip_path'], "rb") as fil:
          part = MIMEApplication(
            fil.read(),
            Name=basename(zip_path['zip_path'])
          )
        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(zip_path['zip_path'])
        msg.attach(part)

        try:
          if not config['dry_run']:
            smtp = smtplib.SMTP(config['upload']['email']['host'])
            if config['upload']['email']['use_tls']:
              smtp.starttls()
            if config['upload']['email']['user'] and config['upload']['email']['password']:
              smtp.login(config['upload']['email']['user'], config['upload']['email']['password'])
            smtp.sendmail(
              config['upload']['email']['sender'],
              COMMASPACE.join(config['upload']['email']['recipients']),
              msg.as_string()
            )
            smtp.close()

            # create the "sent file" for this certificate (ID'd by fingerprint)
            # which - if it exists - indicates that the certificate has already
            # been sent
            sent_file_path_full = os.path.join(config['certificates']['sent_file_path'], zip_path['fingerprint'])
            open(sent_file_path_full, 'a').close()
        except SMTPAuthenticationError:
          logger.fatal("Authenticating towards server '%s' failed" %s config['upload']['email']['host'])
        finally:
          if os.path.exists(zip_path['zip_path']):
            os.remove(zip_path['zip_path'])
    return

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description = 'Read configuration')
  parser.add_argument('--config', required=True, dest='config',
                      help='path to configuration file (YAML)')
  parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                      default=False,
                      help='If specified, commands will not executed')

  args = parser.parse_args()
  config['dry_run'] = args.dry_run

  if not 'log_file' in config.keys():
    config['log_file'] = '/var/log/encrypt-and-mail.log'

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

  if 'certificates' not in config.keys():
    logger.fatal("No certificates configuration specified!")
    sys.exit(1)

  for var in ['domains', 'file_path', 'sent_file_path']:
    if var not in config['certificates'].keys():
      logger.fatal("The configuration of 'certificates' is missing key: '%s'" % var)
      sys.exit(2)

  if 'encrypt' not in config.keys() or 'type' not in config['encrypt'].keys():
    logger.fatal("No encryption configuration specified!")
    sys.exit(1)

  if config['encrypt']['type'] == '7zip':
    for var in ['key']:
      if var not in config['encrypt'].keys():
        logger.fatal("Encryption with 7zip requested but %s not specified!" % var)
        sys.exit(1)

  if 'upload' not in config.keys() or 'type' not in config['upload'].keys():
    logger.fatal("No upload configuration specified!")
    sys.exit(2)

  if config['upload']['type'] == 'email' and 'email' not in config['upload'].keys():
    logger.fatal("No email configuration specified!")
    sys.exit(2)

  if config['upload']['type'] == 'email':
    for var in ['host', 'sender', 'recipients', 'use_tls']:
      if var not in config['upload']['email'].keys():
        logger.fatal("Upload using email requested but '%s' not specified!" % var)
        sys.exit(2)

  certificatemanager = CertificateManager(config)
  domain_objects = certificatemanager.run()

  encrypter = Encrypter(config, domain_objects)
  zip_paths = encrypter.run()

  uploader = Uploader(config, zip_paths)
  uploader.run()
