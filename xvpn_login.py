#!/usr/bin/env python3

import argparse
import getpass
import json
import sys
import requests
from login_protocol import login_message, encode, decode, parse_rpc_frame

DEFAULT_ENDPOINT = 'https://xvpn.io/HermesClientApi'

def attempt(username, password):
    wire = encode(login_message({}, username, password))
    # One POST only; do not follow redirects carrying account data.
    response = requests.post(DEFAULT_ENDPOINT, data=wire,
        headers={'Content-Type':'image/jpeg'}, timeout=(10,25), allow_redirects=False)
    info = {'http_status':response.status_code,
            'content_type':response.headers.get('Content-Type',''),
            'response_bytes':len(response.content)}
    if response.status_code != 200:
        info['state']='http_error'
        info['server_message']=response.content[:1200].decode('utf-8','replace')
        return info, None
    try:
        payload = parse_rpc_frame(decode(response.content))
    except Exception as error:
        info.update(state='protocol_error',error=str(error))
        return info, None
    if not isinstance(payload,dict):
        info.update(state='protocol_error',error='RPC envelope is not an object')
        return info, None
    if payload.get('RpcErr') is not None:
        info.update(state='rpc_error',rpc_error=payload['RpcErr'])
        return info, None
    if not isinstance(payload.get('Out'),dict) or not payload['Out']:
        info.update(state='unverified_response',error='No nonempty Out object; not declaring login success')
        return info, None
    # Do not equate a structurally valid response with a verified authenticated session.
    info.update(state='rpc_out_received',out_fields=list(payload['Out']),
                note='Out received; authenticated-session semantics still require validation')
    return info, payload['Out']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--username', required=True, help='Your own account email')
    p.add_argument('--send', action='store_true', help='Send one login request (otherwise no network request)')
    a=p.parse_args()
    if not a.send:
        print('No request sent. Add --send to log in once.')
        return 0
    username=a.username.strip()
    if not username:
        p.error('username cannot be empty')
    password=getpass.getpass('Password (not saved): ')
    if not password:
        p.error('password cannot be empty')
    try:
        status,out=attempt(username,password)
    except (requests.RequestException,ValueError) as e:
        print(json.dumps({'state':'request_failed','error':str(e)},ensure_ascii=False,indent=2))
        return 2
    if out is not None:
        status['Out'] = out
    print(json.dumps(status,ensure_ascii=False,indent=2))
    return 0 if status['state'] == 'rpc_out_received' else 1

if __name__=='__main__':sys.exit(main())
