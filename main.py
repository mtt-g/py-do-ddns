#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dynamic DNS for DigitalOcean

Utilises the DigitalOcean API to ensure DNS records are configured with the
public IP address of the device executing this script.
"""

__author__ = "Matthew Gee"
__version__ = "0.1.0"
__license__ = "MIT"

from logzero import logger
import argparse
import json
import requests
import yaml

def main(args):

	global config
	global public_ip

	config    = get_config()
	domains   = get_domains()
	public_ip = get_public_ip()

	for domain in domains:

		logger.info('Processing domain: %s' % (domain))

		process_domains( domain, domains[domain] )

def process_domains( domain, subdomains ):

	records = get_all_domain_records( domain )

	process_domain_records(
		domain,
		records,
		subdomains
	)

def process_domain_records( domain, records, subdomains ):

	for record in records:
		if record['name'] in subdomains:

		  id        = record['id']
		  subdomain = record['name']
		  ip        = record['data']

		  process_domain_record(
			id,
			domain,
			subdomain,
			ip,
		  )

def process_domain_record( id, domain, subdomain, ip ):
    logger.info( 'Processing subdomain: %s' % subdomain )
    if public_ip != ip:
        logger.info('IP address mismatch, updating DNS' )
        update_domain_record( domain, id )
    else:
        logger.info( 'IP addresses match, nothing to do.' )

def get_all_domain_records( domain ):

    url     = 'https://api.digitalocean.com/v2/domains/{}/records'.format( domain )
    headers = get_do_api_headers()

    try:
        response        = requests.get(url, headers=headers)
        json_response   = response.json()
        result          = json_response['domain_records']
    except Exception as e:
        logger.exception(e)

    if response.status_code == 200:
        logger.info('Located DNS records')
        return result
    else:
        logger.error('Failed to update DNS record')

def get_api_key():
	return config.get('api_key')

def get_config():
    try:
        with open(args.config, 'r') as f:
            return yaml.load(f, Loader=yaml.FullLoader)
    except Exception as e:
        logger.exception(e)


def get_do_api_headers():

	headers = {
		'Content-Type' : 'application/json',
		'Authorization' : 'Bearer {}'.format(get_api_key())
	}
	return headers

def get_domains():
	return config.get('domains')

def get_public_ip():

	response = requests.get( get_public_ip_api_uri() )
	ip = response.text

	logger.info('Current public IP address: %s' % ip)

	return ip

def get_public_ip_api_uri():
	return config.get('public_ip_api_uri')

def update_domain_record( domain, subdomain_id ):

    url = 'https://api.digitalocean.com/v2/domains/{}/records/{}'.format(domain, subdomain_id)

    data = {
        'data' : '%s' % public_ip
    }

    try:
        response        = requests.put(url, headers=get_do_api_headers(), data=json.dumps(data))
        json_response   = response.json()
    except Exception as e:
        logger.exception(e)

    if response.status_code == 200:
        logger.info('Successfully updated DNS record')
    else:
        logger.error('Failed to update DNS record')

if __name__ == "__main__":

	parser = argparse.ArgumentParser()

	parser.add_argument(
		"-c",
		"--config",
		action="store",
		dest="config",
        default="/etc/py-do-ddns.yaml",
        help='full path to the config file (default: %(default)s)'
	)

	args = parser.parse_args()

	main(args)
