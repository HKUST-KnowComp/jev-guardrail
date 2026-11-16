import json
import os
import urllib.request
from urllib.parse import urlsplit
from .core.protocol import validate_prediction

class EndpointModel:
    def __init__(self, endpoint, expected_model='jev-v3.2-2b', key_env='JEV_API_KEY'):
        parsed=urlsplit(endpoint)
        if parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','localhost','::1')):
            raise ValueError('Use HTTPS, or HTTP on loopback for an SSH tunnel')
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Use an endpoint URL without credentials, query or fragment')
        self.endpoint=endpoint.rstrip('/');self.expected_model=expected_model;self.key_env=key_env
    def request(self,path,data=None):
        key=os.environ.get(self.key_env,'')
        try:
            from agent.secret_scope import get_secret
            key=get_secret(self.key_env) or key
        except ImportError:pass
        headers={'Content-Type':'application/json'}
        if key:headers['Authorization']='Bearer '+key
        req=urllib.request.Request(self.endpoint+path,None if data is None else json.dumps(data).encode(),headers)
        with urllib.request.urlopen(req,timeout=25) as f:return json.load(f)
    def predict(self,prompt,options,mode='single',safety=False):
        r=self.request('/predict',{'input':prompt,'options':options,'mode':mode,'safety_applicable':safety})
        return validate_prediction(r,options,mode,safety,self.expected_model)
    def choice(self,prompt,options,media=None):
        if media and media.get('image_count'):raise ValueError('Text-only endpoint')
        r=self.predict(prompt,options);return [r['probabilities'][x] for x in options]
