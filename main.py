import os
import zeep
import argparse
import getpass
import logging
import colorama
import boto3
from termcolor import colored
from terminaltables import AsciiTable
from signal import signal, SIGINT


def quit_gracefully():
    """
    Capture SIGINT and exit
    :return:
    """
    logging.info("Detected CTRL^C ...will exit now ")
    exit(0)


def process_key_rotation(arg_aws_access_key_id=None, arg_aws_secret_access_key=None):

    # create iam instance
    iam = boto3.resource("iam", aws_access_key_id=arg_aws_access_key_id,
                         aws_secret_access_key=arg_aws_secret_access_key)

    # get owner's key identity
    current_user_name = iam.CurrentUser().user_name
    current_user = iam.User(current_user_name)

    # get previous active used access key
    previous_access_key = iam.AccessKey(user_name=current_user_name, id=arg_aws_access_key_id)

    # hard delete key (we have a constraint of having max. two keys so we likely go ahead and delete it
    # instead of update it with inactive status
    previous_access_key.delete()

    # generate new key pair
    # save it to local file system for reference
    current_access_key = current_user.create_access_key_pair()
    return current_access_key.id, current_access_key.secret


def get_aws_credential_items(arg_secret=None):

    item_aws_access_key_id = None
    item_aws_secret_access_key = None

    items = [k for k in arg_secret.Secret.Items.SecretItem]

    for i in items:
        if i.FieldName == "AWS Access Key Id":
            item_aws_access_key_id = i.Value

        if i.FieldName == "AWS Secret Key":
            item_aws_secret_access_key = i.Value

    return item_aws_access_key_id, item_aws_secret_access_key


def set_aws_credential_item(arg_items=None, arg_aws_access_key_id=None, arg_aws_secret_access_key=None):

    items = [k for k in arg_items]

    for i in items:
        if i.FieldName == "AWS Access Key Id":
            i.Value = arg_aws_access_key_id

        if i.FieldName == "AWS Secret Key":
            i.Value = arg_aws_secret_access_key

    return items


signal(SIGINT, quit_gracefully)

colorama.init(autoreset=True)

PATH_AGENT_LOG_FILE = os.path.join(os.path.abspath(os.sep), "tmp",  __file__ + ".log")

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO,
                    filename=PATH_AGENT_LOG_FILE)

parser = argparse.ArgumentParser(description="EPS Update Your Secrets", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("--url", required=True, help="URL to EPS")
parser.add_argument("--domain", required=True, help="Domain of your EPS account")
args = parser.parse_args()

EPS_USER_NAME = os.getenv("EPS_USER_NAME", None)
EPS_USER_PASSWORD = os.getenv("EPS_USER_PASSWORD", None)
EPS_URL_SERVER = args.url
EPS_USER_DOMAIN = args.domain

try:
    print(colored("[LOGIN]", "yellow"))
    print("")

    if not EPS_USER_NAME:
        EPS_USER_NAME = input(colored("EPS username:  ", "yellow"))
        if not EPS_USER_NAME:
            raise ValueError("EPS username cannot be empty")
    else:
        print(colored("  * Using environment variable EPS_USER_NAME", "yellow"))

    if not EPS_USER_PASSWORD:
        EPS_USER_PASSWORD = getpass.getpass(prompt=colored("EPS password:  ", "yellow"))
        if not EPS_USER_PASSWORD:
            raise ValueError("EPS password cannot be empty")
    else:
        print(colored("  * Using environment variable EPS_USER_PASSWORD", "yellow"))

    settings = zeep.Settings(strict=False, xml_huge_tree=True)

    logging.info("EPS url: %s" % EPS_URL_SERVER)
    logging.info("EPS username: %s" % EPS_USER_NAME)
    logging.info("EPS settings: %s" % str(settings))

    client = zeep.Client(EPS_URL_SERVER, settings=settings)

    with client.settings():

        response = client.service.Authenticate(username=EPS_USER_NAME,
                                               password=EPS_USER_PASSWORD,
                                               domain=EPS_USER_DOMAIN)
        token = response.Token

        if not token:
            raise RuntimeError("EPS authentication failed. Either username or password incorrect")

        logging.info("EPS authentication token: %s" % token)

        identity = client.service.WhoAmI(token=token)
        logging.info("EPS identity: %s" % str(identity))

        # return available secrets
        secrets = client.service.SearchSecrets(token=token,
                                               searchTerm="aws",
                                               includeDeleted=False,
                                               includeRestricted=False)

        EPS_USER_SECRET_DATA = [["Secret", "ID", "Secret Type Name"]]

        for secret in secrets.SecretSummaries.SecretSummary:

            EPS_USER_SECRET_DATA.append([colored(secret.SecretName, "green"), secret.SecretId, secret.SecretTypeName])

        EPS_FORMATTED_USER_SECRET = AsciiTable(table_data=EPS_USER_SECRET_DATA)
        EPS_FORMATTED_USER_SECRET.padding_left = 4
        EPS_FORMATTED_USER_SECRET.padding_right = 4
        EPS_FORMATTED_USER_SECRET.inner_row_border = True

        print(colored("\n[SECRETS]\n", "yellow"))
        print("\n".join(["User: %s" % identity.DisplayName, "Domain: %s" % identity.DomainName]))
        print("\n" + EPS_FORMATTED_USER_SECRET.table + "\n")
        print(colored("[DETAILS]\n", "yellow"))

        while True:

            try:
                user_secret_id = input(colored("? Enter ID of secret you want to rotate keys (or press [ENTER] to quit): ", "green"))

                if not user_secret_id:
                    break

                secret = client.service.GetSecret(token=token, secretId=user_secret_id)

                logging.info(secret)

                if secret.SecretError:
                    raise RuntimeError(str(secret.SecretError))

                if secret.Secret:

                    aws_access_key_id, aws_secret_access_key = get_aws_credential_items(arg_secret=secret)

                    aws_access_key_id, aws_secret_access_key = process_key_rotation(
                        arg_aws_access_key_id=aws_access_key_id,
                        arg_aws_secret_access_key=aws_secret_access_key)

                    secret.Secret.Items.SecretItem = \
                        set_aws_credential_item(arg_items=secret.Secret.Items.SecretItem,
                                                arg_aws_access_key_id=aws_access_key_id,
                                                arg_aws_secret_access_key=aws_secret_access_key)

                    client.service.UpdateSecret(token=token, secret=secret.Secret)

                    EPS_AWS_SECRET_DATA = [["Secret", "ID", "AWS Access Key ID", "AWS Secret Access Key"]]

                    EPS_AWS_SECRET_DATA.append([

                        colored(secret.Secret.Name, "green"),secret.Secret.Id,aws_access_key_id,aws_secret_access_key])

                    EPS_FORMATTED_AWS_SECRET = AsciiTable(table_data=EPS_AWS_SECRET_DATA)

                    EPS_FORMATTED_AWS_SECRET.padding_left = 4
                    EPS_FORMATTED_AWS_SECRET.padding_right = 4
                    EPS_FORMATTED_AWS_SECRET.inner_row_border = True

                    print("\n" + EPS_FORMATTED_AWS_SECRET.table + "\n")

            except BaseException as e:

                logging.error(e)

                print(colored(e, "red"))
        exit(0)
except BaseException as e:
    logging.error(e)
    print(colored(e, "red"))
