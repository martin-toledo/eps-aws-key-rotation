# pipeline helper
import os
import argparse
import logging
import json
import zeep
from termcolor import colored
from signal import signal, SIGINT


def quit_gracefully():
    """
    Capture SIGINT and exit
    :return:
    """
    logging.info("Detected CTRL^C ...will exit now ")
    exit(0)

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.ERROR)

signal(SIGINT, quit_gracefully)

parser = argparse.ArgumentParser(description="EPS Query Your Secret", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("--url", required=True, help="URL to EPS")
parser.add_argument("--domain", required=True, help="Domain of your EPS account")
parser.add_argument("--secret", required=True, help="AWS secret name")

args = parser.parse_args()

EPS_USER_NAME = os.getenv("EPS_USER_NAME", None)
EPS_USER_PASSWORD = os.getenv("EPS_USER_PASSWORD", None)
EPS_URL_SERVER = args.url
EPS_USER_DOMAIN = args.domain
EPS_SECRET_NAME = args.secret

try:
    logging.info(colored("[LOGIN]", "yellow"))

    if not EPS_USER_NAME:
        raise ValueError("Environment variable EPS_USER_NAME cannot be empty")

    if not EPS_USER_PASSWORD:
        raise ValueError("Environment variable EPS_USER_PASSWORD cannot be empty")

    settings = zeep.Settings(strict=False, xml_huge_tree=True)
    client = zeep.Client(EPS_URL_SERVER, settings=settings)

    with client.settings():

        response = client.service.Authenticate(username=EPS_USER_NAME,
                                               password=EPS_USER_PASSWORD,
                                               domain=EPS_USER_DOMAIN)
        token = response.Token

        if not token:
            raise RuntimeError("EPS authentication failed. Either username or password incorrect")

        secrets = client.service.SearchSecrets(token=token)

        items = list(filter(lambda secret: secret.SecretTypeName == "AWS Credentials"
                                           and secret.SecretName == EPS_SECRET_NAME,
                            secrets.SecretSummaries.SecretSummary))

        if not len(items):
            raise RuntimeError("Could not found any secret with such name %s" % EPS_SECRET_NAME)

        item = items[0]
        secret = client.service.GetSecret(token=token, secretId= item.SecretId)

        aws_credentials = list(map(lambda x: x.Value, secret.Secret.Items.SecretItem))[0:]
        aws_access_key = aws_credentials[0]
        aws_secret_key = aws_credentials[1]

        print(json.dumps({"secret": EPS_SECRET_NAME, "aws_access_key": aws_access_key, "aws_secret_key": aws_secret_key }))

except BaseException as e:
    logging.error(e)
    exit(1)

