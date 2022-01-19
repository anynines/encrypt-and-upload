#!/usr/bin/env python2

import argparse
from ast import Not
import binascii
import datetime
import fnmatch
import json
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
    domain_objects = []
    for domain in config['certificates']['domains']:
      full_cert_path = os.path.join(config['certificates']['file_path'], domain, 'cert.pem')
      cert_file = open(full_cert_path, mode='r')
      cert_pem = cert_file.read()
      cert_file.close()

      cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
      cert_fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode('ascii')

      sent_file_path_full = os.path.join(config['certificates']['sent_file_path'], cert_fingerprint)
      if not os.path.isfile(sent_file_path_full):
        logger.info("Sending certificate for domain: %s" % domain)
        domain_objects.append({'domain': domain, 'fingerprint': cert_fingerprint})
      else:
        logger.info("Certificate for domain: '%s' with fingerprint '%s' already sent" % (domain, cert_fingerprint))
    return domain_objects

class Encrypter():
  def __init__(self, config, domain_objects):
    self.config = config
    self.domain_objects = domain_objects

  def run(self):
    logger = logging.getLogger("main")

    enc_file_paths = []
    for domain_object in domain_objects:
      if config['encrypt']['type'] == 'none':
        logger.info("Not encrypting: %s" % domain_object['domain'])
        if not config['dry_run']:
          # ugly hack: for some reason this "sleep" is needed, otherwise we'll
          # run into a race condition/timing issue with the "queue_uploads"
          # queue
          time.sleep(random.random() * 0.1)

      if config['encrypt']['type'] == '7zip':
        tar_command = [
          config['binaries']['tar'], 
          'cpvfh',
          "%s.tar" % domain_object['domain'],
          domain_object['domain']
        ]
        logger.info("Executing command: '%s'" % ' '.join(tar_command))

        if not config['dry_run']:
          if len(tar_command) > 0:
            process = subprocess.Popen(
              tar_command,
              cwd=config['certificates']['file_path'],
              stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT
            )
            output, stderr = process.communicate()
            if process.returncode > 0:
              logger.fatal("Creating the TAR archive failed for domain: '%s'. Stderr: %s" % (domain_object['domain'], stderr))
              sys.exit(3)

            logger.info('Success')
        else:
          time.sleep(random.random() * 0.1)

        full_tar_path = os.path.join(config['certificates']['file_path'], "%s.tar" % domain_object['domain'])
        logger.info("Encrypting: '%s'" % full_tar_path)
        zip_command = [
          config['binaries']['7z'],
          'a',
          '-mx=9',
          '-mhe',
          '-t7z',
          "-p%s" % config['encrypt']['key'],
          "%s.7z" % domain_object['domain'],
          "%s.tar" % domain_object['domain']
        ]
        logger.info("Executing command: '%s'" % ' '.join(zip_command))

        if not config['dry_run']:
          if len(zip_command) > 0:
            process = subprocess.Popen(
              zip_command,
              cwd=config['certificates']['file_path'],
              stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT
            )
            output, stderr = process.communicate()
            if process.returncode > 0:
              logger.fatal("Encrypting the TAR archive failed for domain: '%s'. Stderr: %s" % (domain_object['domain'], stderr))
              sys.exit(3)

            logger.info('Success')
            full_enc_file_path = os.path.join(config['certificates']['file_path'], "%s.7z" % domain_object['domain'])
            enc_file_paths.append({
              'domain': domain_object['domain'],
              'fingerprint': domain_object['fingerprint'],
              'enc_file_path': full_enc_file_path
            })

          if os.path.exists(full_tar_path):
            os.remove(full_tar_path)
        else:
          time.sleep(random.random() * 0.1)
    return domain_objects, enc_file_paths

class Uploader():
  def __init__(self, config, domain_objects, enc_file_paths):
    self.config = config
    self.domain_objects = domain_objects
    self.enc_file_paths = enc_file_paths

  def run(self):
    logger = logging.getLogger("main")

    uploaded_objects_urls = []
    for enc_file_path in enc_file_paths:
      if config['upload']['type'] == 'email':
        logger.info("Sending certificate for domain via email: '%s'" % enc_file_path['domain'])
        msg = MIMEMultipart()
        msg['From'] = config['upload']['email']['sender']
        msg['To'] = COMMASPACE.join(config['upload']['email']['recipients'])
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = "New certificate for domain: %s" % enc_file_path['domain']

        msg.attach(MIMEText("Find the latest SSL/TLS certificate for domain '%s' attached to this email and encrypted with the agreed upon key\n\n" % enc_file_path['domain']))

        with open(enc_file_path['enc_file_path'], "rb") as fil:
          part = MIMEApplication(
            fil.read(),
            Name=basename(enc_file_path['enc_file_path'])
          )
        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(enc_file_path['enc_file_path'])
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
            logger.info("Email server accepted email for domain: '%s'" % enc_file_path['domain'])

            # create the "sent file" for this certificate (ID'd by fingerprint)
            # which - if it exists - indicates that the certificate has already
            # been sent
            sent_file_path_full = os.path.join(config['certificates']['sent_file_path'], enc_file_path['fingerprint'])
            open(sent_file_path_full, 'a').close()
        except smtplib.SMTPAuthenticationError:
          logger.fatal("Authenticating towards server '%s' failed" % config['upload']['email']['host'])
        finally:
          if os.path.exists(enc_file_path['enc_file_path']):
            os.remove(enc_file_path['enc_file_path'])

      command = []
      if config['upload']['type'] == 's3':
        logger.info("Uploading certificate to S3 bucket for domain: '%s'" % enc_file_path['domain'])
        command = [
          config['binaries']['aws'],
          '--profile',
          config['upload']['s3']['profile'],
          's3',
          'cp',
          '--acl',
          'public-read',
          enc_file_path['enc_file_path']
        ]

        dest_string = 's3://' + config['upload']['s3']['bucket'] + '/'
        if 'prefix' in config['upload']['s3'].keys():
          dest_string += config['upload']['s3']['prefix'] + '/'

        dest_string += os.path.basename(enc_file_path['enc_file_path'])
        command.append(dest_string)

        # URL scheme for S3 objects:
        # https://<bucket name>.s3.<region name>.amazonaws.com/<prefix>/<object name>
        dest_url = 'https://' + config['upload']['s3']['bucket'] + '.s3.' + config['upload']['s3']['region'] + '.amazonaws.com/' + config['upload']['s3']['prefix'] + '/' + os.path.basename(enc_file_path['enc_file_path'])
        uploaded_objects_urls.append(dest_url)

      if not config['dry_run']:
        if len(command) > 0:
          process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
          output, _ = process.communicate()
          logger.info(output)
      else:
        time.sleep(random.random() * 0.1)
    return domain_objects, enc_file_paths, uploaded_objects_urls

class Notifier():
  def __init__(self, config, domain_objects, enc_file_paths, uploaded_objects_urls):
    self.config = config
    self.domain_objects = domain_objects
    self.enc_file_paths = enc_file_paths
    self.uploaded_objects_urls = uploaded_objects_urls

  def run(self):
    logger = logging.getLogger("main")

    if len(domain_objects) == 0:
      logger.debug("No files available for uploaded")
      return

    logger.debug("domain objects: %s" % json.dumps(domain_objects))
    logger.debug("encrypted files paths: %s" % json.dumps(enc_file_paths))
    logger.debug("uploaded objects: %s" % json.dumps(uploaded_objects_urls))

    if config['notification']['type'] == 'email':
      logger.info("Sending certificate for domain via email: '%s'" % domain_objects[0]['domain'])

      message = "To whom it may concern,\n\n"
      message += "This message is meant to notify you that a new TLS/SSL\n"
      message += "certificate was uploaded for domain " + domain_objects[0]['domain'] + "\n"
      message += "to the following locations:\n\n"
      for uploaded_object in self.uploaded_objects_urls:
        message += "\n".join(self.uploaded_objects_urls)
      message += "\n\n"
      message += "The file is encrypted using an agreed upon private key."
      message += "\n\n"
      message += "Regards,\nEnterprise-Rails/a9s Managed Services team"

      logger.debug("Notification to be sent: %s" % message)
      msg = MIMEMultipart()
      msg['From'] = config['notification']['email']['sender']
      msg['To'] = COMMASPACE.join(config['notification']['email']['recipients'])
      msg['Date'] = formatdate(localtime=True)
      msg['Subject'] = "A new TLS/SSL certificate was uploaded"
      msg.attach(MIMEText(message))

      try:
        if not config['dry_run']:
          smtp = smtplib.SMTP(config['notification']['email']['host'])
          if config['notification']['email']['use_tls']:
            smtp.starttls()
          if config['notification']['email']['user'] and config['notification']['email']['password']:
            smtp.login(config['notification']['email']['user'], config['notification']['email']['password'])
          smtp.sendmail(
            config['notification']['email']['sender'],
            COMMASPACE.join(config['notification']['email']['recipients']),
            msg.as_string()
          )
          smtp.close()
          logger.info("Email server accepted email for domain: '%s'" % domain_objects[0]['domain'] + "\n")

          # create the "sent file" for this certificate (ID'd by fingerprint)
          # which - if it exists - indicates that the certificate has already
          # been sent
          sent_file_path_full = os.path.join(config['certificates']['sent_file_path'], domain_objects[0]['fingerprint'])
          open(sent_file_path_full, 'a').close()
      except smtplib.SMTPAuthenticationError:
        logger.fatal("Authenticating towards server '%s' failed" % config['notification']['email']['host'])
      finally:
        if os.path.exists(enc_file_paths[0]['enc_file_path']):
          os.remove(enc_file_paths[0]['enc_file_path'])

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description = 'Read configuration')
  parser.add_argument('--config', required=True, dest='config',
                      help='path to configuration file (YAML)')
  parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                      default=False,
                      help='If specified, commands will not executed')

  args = parser.parse_args()
  with open(args.config, 'r') as config_file:
    try:
      config = yaml.safe_load(config_file)
    except yaml.YAMLError as exc:
      print(exc)
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

    if 'binaries' not in config.keys() or 'tar' not in config['binaries'].keys():  
      logger.fatal("Path to 'tar' binary is missing in configuration!")
      sys.exit(2)

    if 'binaries' not in config.keys() or '7z' not in config['binaries'].keys():  
      logger.fatal("Path to '7z' binary is missing in configuration!")
      sys.exit(2)

  if 'upload' not in config.keys() or 'type' not in config['upload'].keys():
    logger.fatal("No upload configuration specified!")
    sys.exit(2)

  if config['upload']['type'] == 'email' and 'email' not in config['upload'].keys():
    logger.fatal("No email configuration specified!")
    sys.exit(2)

  if config['upload']['type'] == 's3':
    if 'binaries' not in config.keys() or 'aws' not in config['binaries'].keys():  
      logger.fatal("Path to 'aws CLI' binary is missing in configuration!")
      sys.exit(2)

  if config['upload']['type'] == 'email':
    for var in ['host', 'sender', 'recipients', 'use_tls']:
      if var not in config['upload']['email'].keys():
        logger.fatal("Upload using email requested but '%s' not specified!" % var)
        sys.exit(2)

  certificatemanager = CertificateManager(config)
  domain_objects = certificatemanager.run()

  encrypter = Encrypter(config, domain_objects)
  domain_objects, enc_file_paths = encrypter.run()

  uploader = Uploader(config, domain_objects, enc_file_paths)
  domain_objects, enc_file_paths, uploaded_objects_urls = uploader.run()

  notifier = Notifier(config, domain_objects, enc_file_paths, uploaded_objects_urls)
  notifier.run()
