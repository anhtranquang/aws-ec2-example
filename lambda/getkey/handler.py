from json import loads
from os import getenv
import urllib3
import boto3
from botocore.exceptions import ClientError
from xml.etree.ElementTree import fromstring, ElementTree
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    lambdaConfig = loads(getenv("lambda_config"))
    secret_name = lambdaConfig.get("secretName")
    fwSecret =  retrieve_firewall_info(secret_name, lambdaConfig.get("region"))
    instanceIp  = retrieve_instance_ip(event["detail"]["EC2InstanceId"], lambdaConfig.get("region"))
    if instanceIp == "":
        logger.error("Cannot get Instance IP")
        raise Exception("Cannot get Instance IP")
    url =  lambdaConfig.get("apiUrl")
    fullUrl = "{}?type=keygen&user={}&password={}".format(url, fwSecret["user"], fwSecret["password"])
    try:
        http = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False)
        r = http.request('GET', fullUrl)
        if r.status == 200 :
            logger.info("Get API Key Success")
            tree = ElementTree(fromstring(r.data))
            root = tree.getroot()
            apiKeyInfo = {
                "apiKey" : root[0][0].text,
                "instanceIp" : instanceIp
            }
            return apiKeyInfo
        else:
            logger.error("Error while calling API: {}".format(r.reason))
    except urllib3.exceptions.HTTPError as e:
        logger.error("Error while get the API Key: {}".format(e))
        raise e

def retrieve_firewall_info(secret_name, regionName):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=regionName
    )

    try:
        secretResponse = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        logger.error("Error while getting secret: {}".format(e))
        raise e

    # get vault information from secret manager.
    fwDict = secretResponse["SecretString"]
    return loads(fwDict)

def retrieve_instance_ip(instanceId, regionName):
    instanceIp = ""
    # Create a EC2 client
    session = boto3.session.Session()
    client = session.client(
        service_name="ec2",
        region_name=regionName
    )
    try:
        instanceInfo = client.describe_instances(
            InstanceIds=[instanceId]
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        logger.error("Error while getting instance information: {}".format(e))
        raise e

    # get vault information from ec2
    enis = instanceInfo["Reservations"][0]["Instances"][0]["NetworkInterfaces"]
    for eni in enis:
        if eni["Attachment"]["DeviceIndex"] == 1:
            instanceIp = eni["PrivateIpAddress"]
            break
    return instanceIp
