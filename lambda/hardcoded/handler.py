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
    # apiKey = event["apiKey"]
    apiKey = "_AQ__KoZOkgS9LDV3iivsbjTEyNPhIW"
    instanceIp = event["instanceIp"]
    http = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False)
    lambdaConfig = loads(getenv("lambda_config"))
    secretName = lambdaConfig.get("secretName")
    fwLicense =  retrieve_license_manager(secretName, lambdaConfig.get("region"))
    url =  lambdaConfig.get("apiUrl")
    serial = retrieve_instance_serial(instanceIp, url, http, apiKey)
    cmd = "<request><plugins><sw_fw_license><deactivate><devices><member>{}</member></devices><license-manager>{}</license-manager></deactivate></sw_fw_license></plugins></request>".format(serial, fwLicense["licenseManager"])
    fullUrl = "{}?type=op&cmd={}&key={}".format(url, cmd, apiKey)
    try:
        r = http.request('GET', fullUrl)
        logger.info(fullUrl)
        if r.status == 200 :
            logger.info("Deactive device success")
            print(r.data)
            return r.data
        else:
            logger.error("Error while calling API: {}".format(r.reason))
    except urllib3.exceptions.HTTPError as e:
        logger.error("Error while get the API Key: {}".format(e))
        raise e

def retrieve_license_manager(secretName, regionName):
    # Load secrets value
    regionName = regionName

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionName
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secretName
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        logger.error("Error while getting secret: {}".format(e))
        raise e

    # get vault information from secret manager.
    fwDict = get_secret_value_response['SecretString']
    return loads(fwDict)
    
def retrieve_instance_serial(instanceIp, url, http, apiKey):
    cmd = "<show><plugins><sw_fw_license><devices><all></all></devices></sw_fw_license></plugins></show>"
    fullUrl = "{}?type=op&cmd={}&key={}".format(url, cmd, apiKey)
    serial = ""
    try:
        r = http.request('GET', fullUrl)
        if r.status == 200 :
            logger.info("Get license information success")
            tree = ElementTree(fromstring(r.data))
            root = tree.getroot()
            print(root.tag)
            try:
                for devices in root.iter("devices"):
                    for entries in devices:
                        for entry in entries:
                            if entry.tag == "serial":
                                serial = entry.text
                            if entry.tag != "ip":
                                continue
                            if entry.text == instanceIp:
                                logger.info("tag {}, text {}".format(entry.tag,entry.text))
                                logger.info("Serial is: {}".format(serial))
                                return serial
            except Exception as e:
                logger.error("Error while get the iterate: {}".format(e))
        else:
            logger.error("Error while calling API: {}".format(r.reason))
    except urllib3.exceptions.HTTPError as e:
        logger.error("Error while get the XML response: {}".format(e))
        raise e
