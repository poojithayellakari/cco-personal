
from django.http import JsonResponse
from .models import Custom_user
from rest_framework.views import APIView
import boto3
from rest_framework import status
import csv
from rest_framework.response import Response
from django.http import HttpResponse
import os
import json
import argparse
import dateutil.relativedelta as dateutil
import datetime
import os
import sys
from rest_framework.permissions import AllowAny,AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import HttpResponse
import boto3
import botocore.exceptions
from django.conf import settings
from datetime import datetime, timedelta , date,timezone
from django.shortcuts import render
import csv
import smtplib
from json import JSONEncoder
from botocore.exceptions import NoCredentialsError
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.mime.multipart import MIMEMultipart
from api_v2.serializers import *
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password,check_password
from .forms import AWSConfigForm
import re
class AWSConfigure(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def post(self, request):
            access_key = request.data.get('Access Key')
            secret_key = request.data.get('Secret Key')

            # Check if access_key and secret_key are provided
            if access_key and secret_key:
                try:
                    # Attempt to validate access_key and secret_key using regular expressions
                    if re.match(r'^[A-Z0-9]{20}$', access_key) and re.match(r'^[A-Za-z0-9/+=]{40}$', secret_key):
                        # Try to create an IAM client with the provided credentials
                        iam_client = boto3.client(
                            'iam',
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key,
                        )
                        sts_client = boto3.client(
                        'sts',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        )
                        account_id = sts_client.get_caller_identity()["Account"]
                        email=sts_client.get_caller_identity()['Arn']
                        
                        
                        response = iam_client.list_users()

                        
                        settings.AWS_ACCESS_KEY_ID = access_key
                        settings.AWS_SECRET_ACCESS_KEY = secret_key

                        
                        response_data = {
                        'status': 'success',
                        'message': 'AWS credentials configured successfully',
                        'account_id': account_id,
                        'iam_user': email.split('/')[-1],
                    }
                    return Response(response_data, status=status.HTTP_200_OK)

                except (NoCredentialsError, Exception) as e:
                    # An exception occurred, indicating invalid credentials or other error
                    error_message = f"Invalid or missing access_key and secret_key. Error: {str(e)}"
                    return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)

            # Return an error response for invalid or missing keys
            return Response({"error": "Invalid or missing access_key and secret_key"}, status=status.HTTP_400_BAD_REQUEST)         
class Registeruser(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def post(self,request):
        serializer=UserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'status':403,'errors':serializer.errors})
        password = make_password(request.data['password'])
        serializer.validated_data['password'] = password		
        serializer.save()
        
        # user=User.objects.get(username=serializer.data['username'])
        # token_obj,_=Token.objects.get_or_create(user=user)
        return Response({'status':200 ,'payload':serializer.data,'message':'succesfully registered'})
#User
class LoginView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid()
        username = request.data["username"]
        password = request.data["password"]
        validation = User.objects.filter(username=username)

        if validation:
            user = User.objects.get(username=serializer.data['username'])
            # Check if the provided password matches the hashed password in the database
            if check_password(password, user.password):
                refresh = RefreshToken.for_user(user)
                return Response({
                    'message':'Successfully logged in',
                    'access': str(refresh.access_token)
                })
            else:
                return Response({"message": "Invalid email or password"}, status.HTTP_403_FORBIDDEN)
        else:
            return Response({"message": "Invalid email or password"}, status.HTTP_403_FORBIDDEN)
    def get(self,request):
        users=User.objects.all()
        user_serializer=UserSerializer(users,many=True)
        return Response(user_serializer.data)

class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class EC2_Memory_utilization(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get_last_activity_time(self, instance_state, launch_time):
        if instance_state == 'running':
            return datetime.utcnow()
        elif instance_state == 'stopped':
            # Use the instance's launch time as an estimate for last activity time
            return launch_time
        else:
            # Handle other states as needed
            return None

    def get(self, request):

        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            all_utilization_info = []

            regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]

            for region_name in regions:
                ec2_client = session.client('ec2', region_name=region_name)

                response = ec2_client.describe_instances()

                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        instance_type = instance['InstanceType']
                        state = instance['State']['Name']
                        launch_time = instance['LaunchTime']

                        last_activity_time = self.get_last_activity_time(state, launch_time)

                        cloudwatch_client = session.client('cloudwatch', region_name=region_name)

                        end_time = datetime.utcnow()
                        # units_str = request.GET.get('units')
                        # if units_str is not None and units_str.isdigit():
                        #     days = int(units_str)
                        time_range=request.GET.get('time-range')
                        # Calculate start time based on the time range provided by the user
                        if time_range == "1 Week":
                            start_time = end_time - timedelta(weeks=1)
                        elif time_range == "15 Days":
                            start_time = end_time - timedelta(days=15)
                    
                        elif time_range == "1 Month":
                            start_time = end_time - timedelta(weeks=4 * 1)
                        
                        elif time_range == "3 Months":
                            start_time = end_time - timedelta(weeks=4 * 3)
                        elif time_range == "6 Months":
                            start_time = end_time - timedelta(weeks=4 * 6)
                        

                        # Query for memory utilization
                        response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[
                                {
                                    'Id': 'mem_utilization',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': 'CWAgent',
                                            'MetricName': 'mem_used_percent',
                                            'Dimensions': [
                                                {
                                                    'Name': 'InstanceId',
                                                    'Value': instance_id
                                                },
                                            ]
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average',
                                    },
                                    'ReturnData': True,
                                },
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                        )

                        # Query for CPU utilization
                        cpu_response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[
                                {
                                    'Id': 'cpu_utilization',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': 'AWS/EC2',
                                            'MetricName': 'CPUUtilization',
                                            'Dimensions': [
                                                {
                                                    'Name': 'InstanceId',
                                                    'Value': instance_id
                                                },
                                            ]
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average',
                                    },
                                    'ReturnData': True,
                                },
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                        )

                        # Query for disk utilization
                        disk_response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[
                                {
                                    'Id': 'disk_utilization',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': 'CWAgent',
                                            'MetricName': 'disk_used_percent',
                                            'Dimensions': [
                                                {
                                                    'Name': 'InstanceId',
                                                    'Value': instance_id
                                                },
                                                {
                                                    'Name': 'device',
                                                    'Value': 'xvda1'
                                                },
                                                {
                                                    'Name': 'fstype',
                                                    'Value': 'ext4'
                                                },
                                                {
                                                    'Name': 'path',
                                                    'Value': '/'
                                                }
                                            ]
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average',
                                    },
                                    'ReturnData': True,
                                },
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                        )

                        if 'MetricDataResults' in response:
                            for metric_result in response['MetricDataResults']:
                                if 'Values' in metric_result:
                                    utilization_info = metric_result['Values']
                                    if utilization_info:
                                        average_value = round(sum(utilization_info) / len(utilization_info), 2)
                                        all_utilization_info.append({
                                            'region':region_name,
                                            'instance_id': instance_id,
                                            'instance_type': instance_type,
                                            'state': state,
                                            'metric_type': 'memory',
                                            'average_utilization': average_value,
                                            'region': region_name,
                                            'last_activity_time': last_activity_time,
                                        })

                        if 'MetricDataResults' in cpu_response:
                            for metric_result in cpu_response['MetricDataResults']:
                                if 'Values' in metric_result:
                                    utilization_info = metric_result['Values']
                                    if utilization_info:
                                        average_value = round(sum(utilization_info) / len(utilization_info), 2)
                                        all_utilization_info.append({
                                            'region':region_name,
                                            'instance_id': instance_id,
                                            'instance_type': instance_type,
                                            'state': state,
                                            'metric_type': 'cpu',
                                            'average_utilization': average_value,
                                            'region': region_name,
                                            'last_activity_time': last_activity_time,
                                        })
                        
                        if 'MetricDataResults' in disk_response:
                            for metric_result in disk_response['MetricDataResults']:
                                if 'Values' in metric_result:
                                    utilization_info = metric_result['Values']
                                    if utilization_info:
                                        average_value = round(sum(utilization_info) / len(utilization_info), 2)
                                        all_utilization_info.append({
                                            'region':region_name,
                                            'instance_id': instance_id,
                                            'instance_type': instance_type,
                                            'state': state,
                                            'metric_type': 'disk',
                                            'average_utilization': average_value,
                                            'region': region_name,
                                            'last_activity_time': last_activity_time,
                                        })

            all_utilization_info.sort(key=lambda x: (x['state'], x['last_activity_time'] or datetime.min))
            for instance_info in all_utilization_info:
                if instance_info['last_activity_time']:
                    instance_info['last_activity_time'] = str(instance_info['last_activity_time']).split("T")[0]
            response_json = json.dumps(all_utilization_info, indent=4, cls=CustomJSONEncoder)

            response = HttpResponse(response_json, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)


class RDSData(APIView):
    authentication_classes = [JWTAuthentication]  # Replace with the correct import path
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            cloudwatch_namespace = 'AWS/RDS'
            cpu_metric_name = 'CPUUtilization'
            freeable_memory_metric_name = 'FreeableMemory'
            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]

            # Load instance memory information from the CSV file into a dictionary
            instance_memory_info = {}
            with open('rds_instance_types.csv', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    instance_type = row['Instance type']
                    memory = row['Memory']
                    instance_memory_info[instance_type] = memory

            # Initialize an empty list to store instance details
            instances_list = []

            # Loop through each region
            for region in regions:
                # Initialize session client for RDS in the current region
                rds_client_region = boto3.client('rds', region_name=region)
                # Initialize session client for CloudWatch
                cloudwatch_client = boto3.client('cloudwatch', region_name=region)

                # Fetch RDS instances in the region
                instances = rds_client_region.describe_db_instances()['DBInstances']

                # Loop through each RDS instance and gather details
                for instance in instances:
                    db_identifier = instance['DBInstanceIdentifier']
                    engine = instance['Engine']
                    db_instance_class = instance['DBInstanceClass']
                    status = instance['DBInstanceStatus']
                    instance_type = instance['DBInstanceClass']
                    db_connections_read_write = instance.get('ReadReplicaSourceDBInstanceIdentifier', 'N/A')

                    storage = instance.get('AllocatedStorage', 'N/A')
                    allocated_storage = instance['AllocatedStorage']
                    end_time = datetime.utcnow()
                    time_range = request.GET.get('time-range')
                    # Calculate start time based on the time range provided by the user
                    if time_range == "1 Week":
                        start_time = end_time - timedelta(weeks=1)
                    elif time_range == "15 Days":
                        start_time = end_time - timedelta(days=15)
                    elif time_range == "1 Month":
                        start_time = end_time - timedelta(weeks=4 * 1)
                    elif time_range == "3 Months":
                        start_time = end_time - timedelta(weeks=4 * 3)
                    elif time_range == "6 Months":
                        start_time = end_time - timedelta(weeks=4 * 6)

                    # Load memory information based on matching instance type
                    memory = instance_memory_info.get(instance_type, 'N/A')

                    # Fetch CPU utilization metric
                    cpu_metric = cloudwatch_client.get_metric_statistics(
                        Namespace=cloudwatch_namespace,
                        MetricName=cpu_metric_name,
                        Dimensions=[
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': db_identifier
                            },
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=7200,  # 1 hour intervals
                        Statistics=['Average']
                    )

                    # Fetch Freeable Memory metric
                    freeable_memory_metric = cloudwatch_client.get_metric_statistics(
                        Namespace=cloudwatch_namespace,
                        MetricName=freeable_memory_metric_name,
                        Dimensions=[
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': db_identifier
                            },
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=7200,  # 1 hour intervals
                        Statistics=['Average']
                    )

                    # Get the latest data point for each metric
                    cpu_utilization = cpu_metric['Datapoints'][-1]['Average'] if cpu_metric['Datapoints'] else 'N/A'
                    freeable_memory = freeable_memory_metric['Datapoints'][-1]['Average'] if freeable_memory_metric[
                        'Datapoints'] else 'N/A'
                    freeable_memory_gb = freeable_memory / (1024 ** 3) if freeable_memory != 'N/A' else 'N/A'
                    free_memory=round(freeable_memory_gb, 2)
                    used_memory = int(memory)-free_memory
                    utilized_memory_in_percentage=(used_memory/int(memory))*100
                    # Create a dictionary for the current instance
                    instance_details = {
                        'DBInstanceIdentifier': db_identifier,
                        'Engine': engine,
                        'Status': status,
                        'DBInstanceClass': db_instance_class,
                        'Memory (GB)': memory,
                        'CPUUtilization (%)': round(cpu_utilization, 2),
                        'utilized_memory_in_percentage':utilized_memory_in_percentage,
                        'UsedMemoryGB': used_memory,
                        'FreeMemory':free_memory,
                        'Storage': storage,
                        'AllocatedStorage': allocated_storage,
                        'ConnectionsRW': db_connections_read_write,
                        
                    }

                    # Append the dictionary to the list
                    instances_list.append(instance_details)

            # Convert the list of dictionaries to a JSON-formatted string
            RDS_data = json.dumps(instances_list, indent=4)

            response = HttpResponse(RDS_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Secrets_data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]

            all_secrets = []

            for region in regions:
                

                # Create a session client for the AWS Secrets Manager service in the current region
                secrets_manager_client = session.client('secretsmanager', region_name=region)

                # List all secrets in the current region
                response = secrets_manager_client.list_secrets()

                secrets = response['SecretList']
                
                for secret in secrets:
                    secret_name = secret['Name']
                    secret_arn = secret['ARN']

                    total_secrets = len(secrets)
                    all_secrets.append({
                        'Region': region,
                        'Secret Name': secret_name,
                        'Secret ARN': secret_arn,
                        'Resource_count':total_secrets,
                    })

            
            response_json = json.dumps(all_secrets, indent=4)
            response = HttpResponse(response_json, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
def get_ecr_repositories(ecr_client):
    response = ecr_client.describe_repositories()
    return response['repositories']
def get_repository_images(ecr_client, repository_name):
    response = ecr_client.describe_images(repositoryName=repository_name)
    return response['imageDetails']
def fetch_ecr_data_for_regions(request):
    access_key = settings.AWS_ACCESS_KEY_ID
    secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
    if not access_key or not secret_key:
        return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
    session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
    ecr_data_list = []
    regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
    for region in regions:
        ecr_client = session.client('ecr', region_name=region)
        repositories = get_ecr_repositories(ecr_client)
        
        for repository in repositories:
            repository_name = repository['repositoryName']
            images = get_repository_images(ecr_client, repository_name)
            ecr_data = {
                "Region": region,
                "Repository": repository_name,
                "Images": []
            }
            for image in images:
                image_pushedtime = image.get('imagePushedAt').isoformat() if image.get('imagePushedAt') else None
                image_lastpulltime = image.get('lastRecordedPullTime').isoformat() if image.get('lastRecordedPullTime') else None
                
                image_tags = image.get('imageTags', ['<no tags>'])
                image_size = image['imageSizeInBytes']
                image_size_mb = image_size / (1024 * 1024)
                ecr_data_image = {
                    
                    "Tags": image_tags,
                    "Size_in_mb": image_size_mb,
                    "lastpulltime": image_lastpulltime,
                    "pushedAtTime": image_pushedtime,
                }
                ecr_data["Images"].append(ecr_data_image)

            ecr_data_list.append(ecr_data)
    
    response_json = json.dumps(ecr_data_list, indent=4)
    response = HttpResponse(response_json, content_type='application/json')
    
    return response

class Get_ECR_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            return fetch_ecr_data_for_regions(request)
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
class Get_S3_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            s3_client = session.client('s3')

            three_days_ago = datetime.now() - timedelta(days=3)
            date = three_days_ago.strftime('%Y-%m-%d')

            # Get list of all S3 buckets
            response = s3_client.list_buckets()

            # Create a list to store bucket data
            bucket_data = []

            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                try:
                    # Get bucket size and last modified date
                    bucket_objects = s3_client.list_objects_v2(Bucket=bucket_name)
                    total_size = 0
                    last_modified = None
                    object_count = 0
                    storage_class = None

                    if 'Contents' in bucket_objects:
                        object_count = len(bucket_objects['Contents'])
                        for obj in bucket_objects['Contents']:
                            storage_class = obj['StorageClass']
                            total_size += obj['Size']
                            if last_modified is None or obj['LastModified'] > last_modified:
                                last_modified = obj['LastModified']

                    # Convert last modified date to a readable format without time
                    formatted_last_modified = last_modified.strftime(
                        '%Y-%m-%d') if last_modified else 'N/A'
                    
                    # Check if the bucket's last modified date is earlier than the specified date
                    if formatted_last_modified < date:
                        bucket_info = {
                            "Bucket": bucket_name,
                            "Total Storage Size (Bytes)": total_size,
                            "Last Modified Date": formatted_last_modified,
                            "Storage Class": storage_class,
                            "Object Count": object_count
                        }
                        bucket_data.append(bucket_info)
                except Exception as e:
                    print("Error:", e)

            # Convert the bucket_data list to JSON format
            json_data = json.dumps(bucket_data, indent=4)

            response = HttpResponse(json_data, content_type='application/json')
            
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
def fetch_lambda_metrics(self,request,lambda_function_name):
    try:
        access_key = settings.AWS_ACCESS_KEY_ID
        secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
        if not access_key or not secret_key:
            return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
        session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
        cloudwatch_client = session.client('cloudwatch')
        end_time = datetime.utcnow()
        time_range=request.GET.get('time-range')
                        # Calculate start time based on the time range provided by the user
        if time_range == "1 Week":
            start_time = end_time - timedelta(weeks=1)
        elif time_range == "15 Days":
            start_time = end_time - timedelta(days=15)
        
        elif time_range == "1 Month":
            start_time = end_time - timedelta(weeks=4 * 1)
        
        elif time_range == "3 Months":
            start_time = end_time - timedelta(weeks=4 * 3)
        elif time_range == "6 Months":
            start_time = end_time - timedelta(weeks=4 * 6)
        response = cloudwatch_client.get_metric_data(
            MetricDataQueries=[
                {
                    'Id': 'invocations',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/Lambda',
                            'MetricName': 'Invocations',
                            'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
                        },
                        'Period': 3600,
                        'Stat': 'Sum'
                    }
                },
                {
                    'Id': 'duration',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/Lambda',
                            'MetricName': 'Duration',
                            'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
                        },
                        'Period': 3600,
                        'Stat': 'Average'
                    }
                },
                {
                    'Id': 'concurrent_executions',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/Lambda',
                            'MetricName': 'ConcurrentExecutions',
                            'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
                        },
                        'Period': 3600,
                        'Stat': 'Average'
                    }
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
        )

        invocations = response['MetricDataResults'][0]['Values']
        avg_duration = response['MetricDataResults'][1]['Values']
        concurrent_executions = response['MetricDataResults'][2]['Values']

        return invocations, avg_duration, concurrent_executions

    except Exception as e:
        print(f"An error occurred while fetching metrics for {lambda_function_name}: {e}")
        return None, None, None

class LambdaMetricsView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            cloudwatch_client = session.client('cloudwatch')
            lambda_client = session.client('lambda')

            end_time = datetime.utcnow()
            units_str = request.GET.get('units')  # Default to 30 if 'units' not provided
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            

            functions = lambda_client.list_functions()
            metrics_data = []

            for function in functions['Functions']:
                lambda_function_name = function['FunctionName']
                region = function['FunctionArn'].split(':')[3]
                response = cloudwatch_client.get_metric_data(
                    MetricDataQueries=[
                        {
                            'Id': 'invocations',
                            'MetricStat': {
                                'Metric': {
                                    'Namespace': 'AWS/Lambda',
                                    'MetricName': 'Invocations',
                                    'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
                                },
                                'Period': 3600,
                                'Stat': 'Sum'
                            }
                        },
                        {
                            'Id': 'duration',
                            'MetricStat': {
                                'Metric': {
                                    'Namespace': 'AWS/Lambda',
                                    'MetricName': 'Duration',
                                    'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
                                },
                                'Period': 3600,
                                'Stat': 'Average'
                            }
                        },
                        {
                            'Id': 'concurrent_executions',
                            'MetricStat': {
                                'Metric': {
                                    'Namespace': 'AWS/Lambda',
                                    'MetricName': 'ConcurrentExecutions',
                                    'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
                                },
                                'Period': 3600,
                                'Stat': 'Average'
                            }
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                )

                invocations = response['MetricDataResults'][0]['Values']
                avg_duration = response['MetricDataResults'][1]['Values']
                concurrent_executions = response['MetricDataResults'][2]['Values']

                metrics_data.append({
                    "region":region,
                    "Function": lambda_function_name,
                    "Invocations": invocations,
                    "AvgDuration": avg_duration,
                    "ConcurrentExecutions": concurrent_executions
                })

            response_json = json.dumps(metrics_data, indent=4)
            return HttpResponse(response_json, content_type='application/json')

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
def get_month_year(date):
    return date.strftime('%b-%y')
class FetchAWSCostView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            client = session.client('ce', region_name='us-east-1')  # Using the Cost Explorer client

        
            # Initialize 'start_time' with a default value
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            response = client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',  # Monthly data
                Metrics=['UnblendedCost'],  # Cost data
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    },
                    {
                        'Type': 'DIMENSION',
                        'Key': 'REGION'
                    }
                ]
            )

            cost_data = response['ResultsByTime']
            current_date = datetime.now().strftime("%Y-%m-%d")
            dynamic_filename = f"cost_details_{current_date}.csv"
            response = HttpResponse(content_type='text/csv')
            

            writer = csv.writer(response)
            writer.writerow(['Date', 'Service', 'Region', 'Amount', 'Unit'])

            total_cost = 0

            for entry in cost_data:
                date = entry['TimePeriod']['Start']
                groups = entry['Groups']

                for group in groups:
                    service = group['Keys'][0]
                    region = group['Keys'][1]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])

                    total_cost += cost

                    writer.writerow([get_month_year(datetime.strptime(date, '%Y-%m-%d')), service, region, cost, 'USD'])

            writer.writerow(['Total', '', '', total_cost, 'USD'])

            return response

        except Exception as e:
            return HttpResponse(f"An error occurred: {e}")
import tempfile
def send_email(subject, message, to_email,attachment_path):
    try:
        # Configure SMTP server settings
        smtp_server = settings.EMAIL_HOST
        smtp_port = settings.EMAIL_PORT
        smtp_username = settings.EMAIL_HOST_USER
        smtp_password = settings.EMAIL_HOST_PASSWORD

        # Create an SMTP connection
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)

        # Create the email message
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach the message to the email
        msg.attach(MIMEText(message, 'plain'))

        # Attach the CSV file as an attachment
        with open(attachment_path, 'rb') as csv_file:
            attachment = MIMEBase('application', 'octet-stream')
            attachment.set_payload(csv_file.read())
            encoders.encode_base64(attachment)
            attachment.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
            msg.attach(attachment)

        # Send the email
        server.sendmail(smtp_username, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        return ("Email sending error:", str(e))

class Send_cost_Email(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def post(self, request):
        try:
            recipient_email = request.data.get('recipient_email')  # Get recipient email from frontend
            if recipient_email:
                subject = "AWS Cost Report"
                current_date = datetime.now().strftime("%Y-%m-%d")
                # Call the get method of FetchAWSCostView to retrieve the cost report
                cost_report_response = FetchAWSCostView().get(request)
                custom_file_name_prefix = f"AWS_Cost_Report{current_date}"
                if cost_report_response.status_code == 200:
                    # Generate a temporary CSV file and write the cost report content to it
                    temp_csv_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.csv',prefix=custom_file_name_prefix)
                    temp_csv_file.write(cost_report_response.content.decode('utf-8'))
                    temp_csv_file.close()
                    
                    # Create the email message
                    message = f"Please find the attached AWS cost report."
                    send_email(subject, message, recipient_email, temp_csv_file.name)
                    
                    # Remove the temporary CSV file after sending the email
                    os.unlink(temp_csv_file.name)
                    
                    return JsonResponse({'message': 'Email sent successfully'})
                else:
                    return JsonResponse({'error': 'Failed to generate the cost report'}, status=500)
            else:
                return JsonResponse({'error': 'Recipient email address not provided'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
class Get_VPCData(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get (self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            aws_regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]

    # Create a dictionary to store information for each region
            region_info = {}

            # Iterate through each region
            for region in aws_regions:
                ec2_client_region = session.client('ec2', region_name=region)
                region_info[region] = []

                # Retrieve VPC details for the current region
                vpcs_response = ec2_client_region.describe_vpcs()

                # Collect VPC details for the current region
                for vpc in vpcs_response['Vpcs']:
                    vpc_data = {
                        'VPC ID': vpc['VpcId'],
                        'CIDR Block': vpc['CidrBlock'],
                        'Subnets': [],
                        'Internet Gateways': [],
                        'NAT Gateways': []
                    }

                    # Retrieve Subnet details associated with the VPC
                    subnets_response = ec2_client_region.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
                    for subnet in subnets_response['Subnets']:
                        vpc_data['Subnets'].append({
                            'Subnet ID': subnet['SubnetId'],
                            'Location': subnet['AvailabilityZone'],
                            'CIDR Block': subnet['CidrBlock']
                        })

                    # Retrieve Internet Gateways associated with the VPC
                    internet_gateways_response = ec2_client_region.describe_internet_gateways()
                    for igw in internet_gateways_response['InternetGateways']:
                        vpc_ids = [attachment['VpcId'] for attachment in igw.get('Attachments', [])]
                        if vpc_ids:
                            VPC_ids = ", ".join(vpc_ids)
                        else:
                            VPC_ids = "Unattached"
                        vpc_data['Internet Gateways'].append({
                            'IGW ID': igw['InternetGatewayId'],
                            'VPC IDs': VPC_ids
                        })

                    # Retrieve NAT Gateways associated with the VPC
                    nat_gateways_response = ec2_client_region.describe_nat_gateways()
                    for nat_gw in nat_gateways_response['NatGateways']:
                        vpc_data['NAT Gateways'].append({
                            'NAT Gateway ID': nat_gw['NatGatewayId'],
                            'Subnet': nat_gw.get('SubnetId', 'Unattached'),
                            'Elastic IP allocation ID': nat_gw['NatGatewayAddresses'][0]['AllocationId']
                        })

                    region_info[region].append(vpc_data)

            # Convert the result to JSON
            response_json = json.dumps(region_info, indent=4)

            # Create an HttpResponse with JSON content
            response = HttpResponse(response_json, content_type='application/json')
            
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.strftime('%Y-%m-%d %H:%M:%S')
        return super().default(o)
class Get_ECS_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get (self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            cloudwatch_client = session.client('cloudwatch')

    # Get a list of all AWS regions
            ec2_client = session.client('ec2', region_name='us-east-1')  # You can use any region to get the list of regions
            all_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

            all_region_data = []  # List to store data for all regions

            # Loop through all AWS regions
            for region in all_regions:
                region_data = {'Region': region, 'Clusters': []}

                # Initialize ECS client for the current region
                ecs_client = session.client('ecs', region_name=region)

                # List all ECS clusters
                response = ecs_client.list_clusters()

                for cluster_arn in response['clusterArns']:
                    cluster_name = cluster_arn.split('/')[-1]
                    cluster_data = {'Cluster': cluster_name, 'Services': []}

                    # List all services in the cluster
                    services_response = ecs_client.list_services(cluster=cluster_name)

                    for service_arn in services_response['serviceArns']:
                        service_name = service_arn.split('/')[-1]
                        service_data = {'Service': service_name, 'Metrics': []}

                        # Describe the service to get detailed information
                        service_details = ecs_client.describe_services(cluster=cluster_name, services=[service_name])

                        if 'services' in service_details and len(service_details['services']) > 0:
                            service = service_details['services'][0]
                            service_info = {
                                "Status": service['status'],
                                "Desired Count": service['desiredCount'],
                                "Running Count": service['runningCount'],
                                "Pending Count": service['pendingCount'],
                                "Task Definition": service['taskDefinition'],
                                "Created At": service['createdAt']
                            }

                            service_data['Service Info'] = service_info

                            metric_names = ["NetworkRxBytes", "NetworkTxBytes", "CpuUtilized", "MemoryUtilized"]
                            namespace = "ECS/ContainerInsights"
                            dimensions = [
                                {
                                    "Name": "ClusterName",
                                    "Value": cluster_name
                                },
                                {
                                    "Name": "ServiceName",
                                    "Value": service_name
                                }
                            ]

                            service_metrics = []

                            for metric_name in metric_names:
                                response = cloudwatch_client.get_metric_data(
                                    MetricDataQueries=[
                                        {
                                            "Id": "ecs_metrics",
                                            "MetricStat": {
                                                "Metric": {
                                                    "Namespace": namespace,
                                                    "MetricName": metric_name,
                                                    "Dimensions": dimensions
                                                },
                                                "Period": 3600,
                                                "Stat": "Average"
                                            },
                                        }
                                    ],
                                    StartTime=start_time,
                                    EndTime=end_time,
                                )

                                values = response['MetricDataResults'][0].get('Values', [])
                                if values:
                                    service_metrics.append({metric_name: values[0]})
                                else:
                                    service_metrics.append({metric_name: "No data available"})

                            service_data['Metrics'] = service_metrics
                            cluster_data['Services'].append(service_data)

                    region_data['Clusters'].append(cluster_data)

                all_region_data.append(region_data)

            # Convert the data to JSON format
            response_json = json.dumps(all_region_data, indent=4,cls=DateTimeEncoder)
            response = HttpResponse(response_json, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
from statistics import mean
class Get_load_balancer_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            cloudwatch_client = session.client('cloudwatch')
            namespace = 'AWS/ApplicationELB'
            response_period = 3600  # You can adjust the period as needed
            
            metrics = [
            {'Name': 'TargetResponseTime', 'Statistic': 'Average'},
            {'Name': 'ActiveConnectionCount', 'Statistic': 'Average'},
            {'Name': 'NewConnectionCount', 'Statistic': 'Sum'}
            ]
            # Metrics to retrieve

            # Get a list of available regions
            ec2_client = session.client('ec2')
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            result = []
            
            lb_metrics_list = []
# Iterate through each region
            for aws_region in regions:
                # Initialize the Elastic Load Balancing client for the region
                elbv2_client = session.client('elbv2', region_name=aws_region)

                # Describe load balancers to get their names and ARNs
                load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']

                # Iterate through each load balancer
                for lb in load_balancers:
                    load_balancer_arn = lb['LoadBalancerArn']
                    load_balancer_name = load_balancer_arn.split('loadbalancer/')[-1]
                    lb_metrics = []

                    # Iterate through each metric and retrieve statistics
                    for metric in metrics:
                        metric_name = metric['Name']
                        statistic = metric['Statistic']

                        # Get metric statistics data
                        response = cloudwatch_client.get_metric_statistics(
                            Namespace=namespace,
                            MetricName=metric_name,
                            Dimensions=[{'Name': 'LoadBalancer', 'Value': load_balancer_name}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,  # Adjust as needed
                            Statistics=[statistic],
                        )

                        # Extract values from response
                        data_points = response['Datapoints']

                        values = []
                        for point in data_points:
                            if statistic in point:
                                values.append(point[statistic])
                                

                        # Calculate average or sum
                        if statistic == 'Average':
                            metric_value = mean(values) if values else None
                        elif statistic == 'Sum':
                            metric_value = sum(values) if values else None
                        else:
                            metric_value = None
                        metric_data = {
                            'MetricName': metric_name,
                            'Statistic': statistic,
                            'MetricValue': metric_value,
                        }
                        lb_metrics.append(metric_data)

            # Add load balancer metrics to the result list
                    lb_metrics_list.append({
                        'Region': aws_region,
                        'LoadBalancerName': load_balancer_name,
                        'Metrics': lb_metrics,
                    })
                    
            response_json = json.dumps(lb_metrics_list, indent=4)
            response = HttpResponse(response_json, content_type='application/json')
            
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_EBS_Data(APIView):
        authentication_classes=[JWTAuthentication]
        permission_classes=[AllowAny]

        def get(self, request):
            try:
                access_key = settings.AWS_ACCESS_KEY_ID
                secret_key = settings.AWS_SECRET_ACCESS_KEY

                # Check if AWS credentials are configured
                if not access_key or not secret_key:
                    return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

                # Configure the AWS client with the stored credentials
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                )
                end_time = datetime.utcnow()
                time_range=request.GET.get('time-range')
                                # Calculate start time based on the time range provided by the user
                if time_range == "1 Week":
                    start_time = end_time - timedelta(weeks=1)
                elif time_range == "15 Days":
                    start_time = end_time - timedelta(days=15)
                
                elif time_range == "1 Month":
                    start_time = end_time - timedelta(weeks=4 * 1)
                
                elif time_range == "3 Months":
                    start_time = end_time - timedelta(weeks=4 * 3)
                elif time_range == "6 Months":
                    start_time = end_time - timedelta(weeks=4 * 6)
                ec2_client = session.client('ec2')
                cloudwatch_client = session.client('cloudwatch')

                # Get a list of available regions
                regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

                # Initialize a list to store volume data across regions
                all_volume_data = []

                # Define the metric names for disk activity
                metric_names = ['VolumeReadOps', 'VolumeWriteOps']

                for aws_region in regions:
                    ec2_client = session.client('ec2', region_name=aws_region)
                    response = ec2_client.describe_volumes()

                    # Iterate through each EBS volume
                    for volume in response['Volumes']:
                        volume_id = volume['VolumeId']
                        volume_type = volume['VolumeType']
                        size_gb = volume['Size']
                        Iops = volume.get('Iops', None)  # Handle the case where 'Iops' may not be present

                        # Initialize a dictionary to store metrics for this volume
                        volume_metrics = {'VolumeId': volume_id, 'VolumeType': volume_type, 'SizeGB': size_gb, 'Iops': Iops}

                        # Retrieve and add I/O metrics for this volume
                        for metric_name in metric_names:
                            for stat in ['Average', 'Sum']:
                                metric_data = cloudwatch_client.get_metric_statistics(
                                    Namespace='AWS/EBS',
                                    MetricName=metric_name,
                                    Dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
                                    StartTime=start_time,
                                    EndTime=end_time,
                                    Period=3600,  # Adjust as needed
                                    Statistics=[stat],
                                )

                                # Extract and add the metric value to the volume_metrics dictionary
                                data_points = metric_data['Datapoints']
                                metric_value = None

                                if data_points:
                                    metric_value = data_points[0][stat]

                                volume_metrics[f'{stat} {metric_name}'] = metric_value

                        # Get information about the EC2 instance associated with the volume
                        if 'Attachments' in volume:
                            attachments = volume['Attachments']
                            if attachments:
                                # Assuming a volume is attached to one instance (for simplicity)
                                instance_id = attachments[0]['InstanceId']
                                volume_metrics['InstanceId'] = instance_id

                        # Append the volume_metrics dictionary to the all_volume_data list
                        all_volume_data.append(volume_metrics)

                response_json = json.dumps(all_volume_data, indent=4)
                response = HttpResponse(response_json, content_type='application/json')
                current_date = datetime.now().strftime("%Y-%m-%d")
                dynamic_filename = f"EBS_data_{current_date}.json"
                response['Content-Disposition'] = f'attachment; filename="{dynamic_filename}"'
                return response
            except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_WAF_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get (self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            wafv2_client = session.client('wafv2')
            ec2_client = session.client('ec2')
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

            # Initialize an empty list to store JSON objects
            json_response = []

            try:
                for aws_region in regions:
                    cloudwatch_client = session.client('cloudwatch', region_name=aws_region)  # Initialize CloudWatch client per region
                    response = wafv2_client.list_web_acls(Scope='CLOUDFRONT')
                    
                    for acl in response['WebACLs']:
                        acl_id = acl['Id']
                        name = acl['Name']

                        metric_name = 'AllowedRequests'
                        namespace = 'AWS/WAFV2'
                        rule_name = 'ALL'  # Specify 'ALL' to fetch data for all rules within the Web ACL
                        
                        dimensions = [
                            {
                                'Name': 'WebACL',
                                'Value': name,
                            },
                            {
                                'Name': 'Rule',
                                'Value': rule_name,
                            }
                        ]

                        
                        
                        cloudwatch_response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[
                                {
                                    'Id': 'm1',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': namespace,
                                            'MetricName': metric_name,
                                            'Dimensions': dimensions,
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average',
                                    },
                                },
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                            ScanBy='TimestampAscending',
                        )

                        if 'MetricDataResults' in cloudwatch_response:
                            for data_result in cloudwatch_response['MetricDataResults']:
                                if 'Values' in data_result:
                                    values = data_result['Values']
                                    
                                    # Create a dictionary with the collected information
                                    data_dict = {
                                        'AWS Region': aws_region,
                                        'Web ACL ID': acl_id,
                                        'Name': name,
                                        'Metric Name': metric_name,
                                        'Metric Values': values
                                    }
                                    
                                    # Append the dictionary to the JSON response list
                                    json_response.append(data_dict)
                        
            except Exception as e:
                return(f'Error: {str(e)}')

            # Serialize the JSON response list to a JSON string
            json_response_str = json.dumps(json_response, indent=4)
            response = HttpResponse(json_response_str, content_type='application/json')
            
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
def run_df_command(instance_id, ssm_client):
    # Specify the command to run
    commands = ['df -hT && lsblk -o NAME,KNAME,SIZE,MOUNTPOINT,TYPE']

    # Send the command to the instance
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': commands},
    )

    # Wait for the command to complete
    command_id = response['Command']['CommandId']
    ssm_client.get_waiter('command_executed').wait(CommandId=command_id, InstanceId=instance_id)

    # Retrieve the command output
    output = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
    return output
def parse_df_output(df_output):
    parsed_data = {}
    current_section = None

    for line in df_output:
        if line.startswith("Filesystem"):
            current_section = "Filesystem"
            parsed_data[current_section] = []
            parsed_data[current_section].append(line.strip())  # Add the header
        elif line.startswith("NAME"):
            current_section = "NAME"
            parsed_data[current_section] = []
            parsed_data[current_section].append(line.strip())  # Add the header
        elif current_section:
            if line.strip():
                parsed_data[current_section].append(line.strip())

    return parsed_data

class Get_Detailed_usage_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
    # Initialize AWS clients
            ssm_client = session.client('ssm')
            ec2_client_global = session.client('ec2', region_name='us-east-1')  # You can choose any region to list all regions
            regions = [region['RegionName'] for region in ec2_client_global.describe_regions()['Regions']]

            response_data = []  # To store the response data

            for region_name in regions:
                ec2_client = session.client('ec2', region_name=region_name)

                # Describe all instances in the current region
                instances = ec2_client.describe_instances()

                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']

                        # Check if the instance is running
                        if instance['State']['Name'] == 'running':
                            output = run_df_command(instance_id, ssm_client)
                            
                            # Split the output into lines
                            lines = output['StandardOutputContent'].strip().split('\n')
                            
                            instance_info = {
                                "Region": region_name,
                                "InstanceID": instance_id,
                            }
                            
                            parsed_data = parse_df_output(lines)
                            instance_info.update(parsed_data)
                            
                            response_data.append(instance_info)

            json_response_str = json.dumps(response_data, indent=4)
            response = HttpResponse(json_response_str, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_Elastic_Ip(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ec2 = session.client('ec2')

            # Get a list of all AWS regions
            regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

            elastic_ips_data = []

            # Iterate through all regions
            for region in regions:
                # Create an EC2 client for the specific region
                ec2_client = session.client('ec2', region_name=region)

                # Use the describe_addresses method to get information about Elastic IPs in the region
                response = ec2_client.describe_addresses()

                # Iterate through the Elastic IPs in the region
                for elastic_ip_info in response['Addresses']:
                    allocation_id = elastic_ip_info['AllocationId']
                    instance_id = elastic_ip_info.get('InstanceId', 'Unattached')

                    # Append Elastic IP data to the list
                    elastic_ips_data.append({
                        'Region': region,
                        'AllocationId': allocation_id,
                        'InstanceId': instance_id
                    })

            # Return the Elastic IP data as a JSON response
            json_response_str = json.dumps(elastic_ips_data, indent=4)
            response = HttpResponse(json_response_str, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
from io import BytesIO
import pandas as pd


class GetTotalBill(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            client = session.client('ce', region_name='us-east-1')

            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)

            response = client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    },
                    {
                        'Type': 'DIMENSION',
                        'Key': 'REGION'
                    }
                ]
            )

            cost_data = response['ResultsByTime']

            data = []
            for entry in cost_data:
                date = entry['TimePeriod']['Start']
                groups = entry['Groups']
                for group in groups:
                    service = group['Keys'][0]
                    region = group['Keys'][1]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    data.append([date, service, region, cost])

            df = pd.DataFrame(data, columns=['Date', 'Service', 'Region', 'Cost'])

            # Prepare and return cost data as a list of dictionaries
            chart_data = []
            for date, service, cost in zip(df['Date'], df['Service'], df['Cost']):
                chart_data.append({'Date': date, 'Service': service, 'Cost': cost})

            return JsonResponse({'chart_data': chart_data})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
import concurrent.futures
class Get_APIGateway(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            cloudwatch_client = session.client('cloudwatch')
            cache_hit_count_metric_name = 'CacheHitCount'
            count_metric_name = 'Count'
            latency_metric_name = 'Latency'
            regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            print(time_range)
            print(start_time)
            api_metrics_data = []
            for region in regions:
                apigateway_client = session.client('apigateway', region_name=region)
                api_gateways = apigateway_client.get_rest_apis()['items']

                
                for api_gateway in api_gateways:
                    api_name = api_gateway['name']

                    
                    api_gateway_data = {
                        'Region': region,
                        'ApiName': api_name,
                    }

                    
                    cache_hit_count_metrics = cloudwatch_client.get_metric_data(
                        MetricDataQueries=[
                            {
                                'Id': 'cache_hit_count',
                                'MetricStat': {
                                    'Metric': {
                                        'Namespace': 'AWS/ApiGateway',
                                        'MetricName': cache_hit_count_metric_name,
                                        'Dimensions': [{'Name': 'ApiName', 'Value': api_name}],
                                    },
                                    'Period': 3600,  
                                    'Stat': 'Sum',
                                },
                                'ReturnData': True,
                            },
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                    )

                    if 'MetricDataResults' in cache_hit_count_metrics:
                        metric_data = cache_hit_count_metrics['MetricDataResults'][0]
                        if 'Values' in metric_data:
                            api_gateway_data[cache_hit_count_metric_name] = metric_data['Values']

                    
                    count_metrics = cloudwatch_client.get_metric_data(
                        MetricDataQueries=[
                            {
                                'Id': 'count',
                                'MetricStat': {
                                    'Metric': {
                                        'Namespace': 'AWS/ApiGateway',
                                        'MetricName': count_metric_name,
                                        'Dimensions': [{'Name': 'ApiName', 'Value': api_name}],
                                    },
                                    'Period': 3600,  
                                    'Stat': 'Sum',
                                },
                                'ReturnData': True,
                            },
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                    )

                    if 'MetricDataResults' in count_metrics:
                        metric_data = count_metrics['MetricDataResults'][0]
                        if 'Values' in metric_data:
                            api_gateway_data[count_metric_name] = metric_data['Values']

                    
                    latency_metrics = cloudwatch_client.get_metric_data(
                        MetricDataQueries=[
                            {
                                'Id': 'latency',
                                'MetricStat': {
                                    'Metric': {
                                        'Namespace': 'AWS/ApiGateway',
                                        'MetricName': latency_metric_name,
                                        'Dimensions': [{'Name': 'ApiName', 'Value': api_name}],
                                    },
                                    'Period': 3600,  # Adjust the period as needed
                                    'Stat': 'Average',
                                },
                                'ReturnData': True,
                            },
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                    )

                    if 'MetricDataResults' in latency_metrics:
                        metric_data = latency_metrics['MetricDataResults'][0]
                        if 'Values' in metric_data:
                            api_gateway_data[latency_metric_name] = metric_data['Values']

                    
                    api_metrics_data.append(api_gateway_data)
            json_response_str = json.dumps(api_metrics_data, indent=4)
            response = HttpResponse(json_response_str, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_Snapshot_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ec2_client = session.client('ec2')
            snapshot_data = []

            # Get a list of all AWS regions
            ec2_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

            for region in ec2_regions:
                ec2_client = session.client('ec2', region_name=region)
                snapshots = ec2_client.describe_snapshots(OwnerIds=['self'])

                for snapshot in snapshots['Snapshots']:
                    snapshot_details = {
                        "Region":region,
                        "SnapshotID": snapshot['SnapshotId'],
                        "VolumeID": snapshot['VolumeId'],
                        "Description": snapshot['Description'],
                        "SizeGiB": snapshot['VolumeSize'],
                        "StartTime": snapshot['StartTime'].isoformat(),
                        "Progress": snapshot['Progress'],
                        "OwnerID": snapshot['OwnerId']
                    }
                    snapshot_data.append(snapshot_details)

            # Convert the list of dictionaries to a JSON string
            json_data = json.dumps(snapshot_data, indent=4)

            response = HttpResponse(json_data, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
                


from io import BytesIO
import pandas as pd


class GetTotalBill(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            client = session.client('ce', region_name='us-east-1')

            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)

            response = client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    },
                    {
                        'Type': 'DIMENSION',
                        'Key': 'REGION'
                    }
                ]
            )

            cost_data = response['ResultsByTime']

            data = []
            for entry in cost_data:
                date = entry['TimePeriod']['Start']
                groups = entry['Groups']
                for group in groups:
                    service = group['Keys'][0]
                    region = group['Keys'][1]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    data.append([date, service, region, cost])

            df = pd.DataFrame(data, columns=['Date', 'Service', 'Region', 'Cost'])

            # Prepare and return cost data as a list of dictionaries
            chart_data = []
            for date, service, cost in zip(df['Date'], df['Service'], df['Cost']):
                chart_data.append({'Date': date, 'Service': service, 'Cost': cost})

            return JsonResponse({'chart_data': chart_data})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

from decimal import Decimal
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return super(DecimalEncoder, self).default(obj)
class EC2_instance_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]
    
    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            units_str = request.GET.get("units")
            time_range = request.GET.get("time-range")

            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_ec2 = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['Amazon Elastic Compute Cloud - Compute']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_ec2,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)
            
            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)
class S3_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)

            filter_s3 = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['Amazon Simple Storage Service']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_s3,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)
class ECR_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_ecr = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['Amazon Elastic Container Registry']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_ecr,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)
class Lambda_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_lambda = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['AWS Lambda']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_lambda,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)
        
class ECS_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_ecs = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['Amazon Elastic Container Service']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_ecs,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)


class WAF_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_waf = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['AWS WAF']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_waf,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)
class APIGateway_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_api_gateway = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['AmazonApiGateway']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_api_gateway,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)
class VPC_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_vpc = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['Amazon Virtual Private Cloud']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_vpc,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)

class SecretsManager_cost_data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_secrets = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['AWS Secrets Manager']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_secrets,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)
class RDS_Cost_Data(APIView):
    def get(self, request, *args, **kwargs):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            end_time = datetime.utcnow()
            time_range=request.GET.get('time-range')
                            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=4 * 6)
            else:
                # Handle the case when units_str is not provided or not a digit
                return JsonResponse({'error': 'Invalid units parameter'}, status=400)

            filter_rds = {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['Amazon Relational Database Service']
                }
            }

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter_rds,
                Metrics=['UnblendedCost']
            )

            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)

            response_data = json.dumps({
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)
            
            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, content_type='application/json', status=500)


overall_unused_data = []
overall_unused_data_count=[]
class AWSResourceManager(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        access_key = settings.AWS_ACCESS_KEY_ID
        secret_key = settings.AWS_SECRET_ACCESS_KEY

        # Check if AWS credentials are configured
        if not access_key or not secret_key:
            raise ValueError('AWS credentials are not configured')

        # Configure the AWS client with the stored credentials
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        self.lambda_client = self.session.client('lambda')
        self.ec2_client = self.session.client('ec2')
        self.ecr_client = self.session.client('ecr')
        self.ecs_client = self.session.client('ecs')
        self.rds_client = self.session.client('rds')
        self.s3_client = self.session.client('s3')
        self.secrets_manager_client = self.session.client('secretsmanager')
        self.wafv2_client = self.session.client('wafv2')
        self.cloudwatch_logs_client = self.session.client('logs')
        self.utc_now = datetime.utcnow().replace(tzinfo=timezone.utc)

    def get(self, request):
        try:
            end_time = datetime.utcnow()
            time_range = request.GET.get('time-range')

            # Calculate start time based on the time range provided by the user
            if time_range == "1 Week":
                start_time = 7  # 1 week in days
            elif time_range == "15 Days":
                start_time = 15
            
            elif time_range == "1 Month":
                start_time = 30  # 1 month in days
            
            elif time_range == "3 Months":
                start_time = 90  # 3 months in days
            elif time_range == "6 Months":
                start_time = 180  # 6 months in days
            else:
                raise ValueError('Invalid time range')
            

            self.get_lambda_functions(start_time)
            self.get_ec2_instances(start_time)
            self.get_ecr_repositories(start_time)
            self.get_unused_ecs_clusters(start_time)
            self.get_rds_databases(start_time)
            self.get_unused_s3_buckets(start_time)
            self.get_unused_secrets(start_time)
            self.get_unused_waf_webacls(start_time)

            sum_overall_count = sum(overall_unused_data_count)
            json_response = json.dumps({"unused_data": overall_unused_data, "unused_data_count": sum_overall_count},
                                       default=str)
            response = HttpResponse(json_response, content_type='application/json')
            overall_unused_data.clear()
            overall_unused_data_count.clear()
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, content_type='application/json', status=500)

    def get_lambda_functions(self, start_time):
        response = self.lambda_client.list_functions()
        functions = response['Functions']

        all_functions = []

        for function in functions:
            function_name = function['FunctionName']
            last_modified_time_str = function['LastModified']
            last_activity_time = datetime.strptime(last_modified_time_str, '%Y-%m-%dT%H:%M:%S.%f%z')
            
            # Append data as a dictionary
            all_functions.append({
                'function_name': function_name,
                'last_activity_time': last_activity_time
            })

        unused_functions = [
            {
                'function_name': function['function_name'],
                'last_activity_time': function['last_activity_time']
            }
            for function in all_functions
            if function['last_activity_time'] and function['last_activity_time'] >= (
                self.utc_now - timedelta(start_time)).replace(tzinfo=timezone.utc)
        ]

        unused_functions.sort(key=lambda x: (x['last_activity_time'] is None, x['last_activity_time']))

        total_functions = len(all_functions)
        total_unused_functions = len(unused_functions)

        unused_data = {
            "all_functions": all_functions,
            "unused_functions": unused_functions,
            "total_functions": total_functions,
            "total_unused_functions": total_unused_functions
        }
        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(total_unused_functions)


    def get_ec2_instances(self, start_time):
        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                   if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

        all_instances = []
        instance_prices = {}
        with open('ec2_instance_prices.csv', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                instance_type = row['Instance Type']
                instance_prices[instance_type] = {
                    'Instance Type': row['Instance Type'],
                    'Market': row['Market'],
                    'vCPU': row['vCPU'],
                    'RAM (GiB)': row['RAM (GiB)'],
                    'Price ($/m)': float(row['Price ($/m)'])  # Convert price to float
                }

        total_price = 0  # Initialize total price

        for region_name in regions:
            ec2_client = self.session.client('ec2', region_name=region_name)

            response = ec2_client.describe_instances()

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    state = instance['State']['Name']
                    launch_time = instance['LaunchTime']

                    if state == 'running':
                        last_activity_time = self.utc_now
                    elif state == 'stopped':
                        last_activity_time = launch_time.replace(tzinfo=timezone.utc)
                    else:
                        last_activity_time = None

                    instance_type = instance['InstanceType']
                    instance_info = instance_prices.get(instance_type, {})
                    price = instance_info.get('Price ($/m)')

                    # Append data as a dictionary
                    all_instances.append({
                        'instance_id': instance_id,
                        'state': state,
                        'last_activity_time': last_activity_time,
                        'instance_type': instance_info.get('Instance Type'),
                        'price (USD/month)': price 
                    })

                    # Accumulate the price for unused instances
                    if state == 'stopped' and last_activity_time and \
                            last_activity_time >= (self.utc_now - timedelta(start_time)).replace(tzinfo=timezone.utc) and \
                            instance_type in instance_prices:
                        total_price += price

        unused_instances = [
            {
                'instance_id': instance['instance_id'],
                'state': instance['state'],
                'last_activity_time': instance['last_activity_time'],
                'instance_type': instance['instance_type'],
                'price (USD/month)': instance['price (USD/month)']
            }
            for instance in all_instances
            if instance['state'] == 'stopped' and instance['last_activity_time'] and
            instance['last_activity_time'] >= (self.utc_now - timedelta(start_time)).replace(tzinfo=timezone.utc) and
            instance['instance_type'] in instance_prices
        ]

        unused_instances.sort(key=lambda x: (x['last_activity_time'] is None, x['last_activity_time']))

        total_ec2_instances = len(all_instances)
        total_unused_instances = len(unused_instances)

        unused_data = {
            "all_instances": all_instances,
            "unused_instances": unused_instances,
            "total_ec2_instances": total_ec2_instances,
            "total_unused_instances": total_unused_instances,
            "total_price (USD/month)": round(total_price,2)   # Add total price to the result
        }
        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(total_unused_instances)

    def get_ecr_repositories(self, start_time):
        response = self.ecr_client.describe_repositories()

        all_repositories = []
        unused_repositories = []

        for repository in response.get('repositories', []):
            repository_name = repository['repositoryName']
            image_count = repository.get('imageCount', 0)

            # Append data as a dictionary to all_repositories
            all_repositories.append({
                'repository_name': repository_name,
                'image_count': image_count
            })

            # Filter repositories with no images and append as a dictionary to unused_repositories
            if image_count == 0:
                unused_repositories.append({
                    'repository_name': repository_name,
                    'image_count': image_count
                })

        total_repositories = len(all_repositories)
        total_unused_repositories = len(unused_repositories)

        unused_data = {
            "all_repositories": all_repositories,
            "unused_repositories": unused_repositories,
            "total_repositories": total_repositories,
            "total_unused_repositories": total_unused_repositories
        }
        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(total_unused_repositories)

    def get_unused_ecs_clusters(self, start_time):
        unused_clusters_by_region = {}

        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']]

        for region in regions:
            current_ecs_client = self.session.client('ecs', region_name=region)

            clusters = current_ecs_client.list_clusters()['clusterArns']

            unused_clusters = []

            for cluster_arn in clusters:
                cluster_name = cluster_arn.split("/")[-1]
                cluster_info = current_ecs_client.describe_clusters(clusters=[cluster_name])['clusters'][0]

                if 'lastStatus' in cluster_info:
                    last_status_time = cluster_info['lastStatus'].get('updatedAt', cluster_info['createdAt'])
                    last_activity_time = datetime.strptime(last_status_time, "%Y-%m-%dT%H:%M:%S.%f%z")
                    if datetime.now() - last_activity_time > timedelta(start_time):
                        unused_clusters.append({
                            'cluster_name': cluster_name,
                            'last_activity_time': last_activity_time.strftime("%Y-%m-%d %H:%M:%S %Z")
                        })

            if unused_clusters:
                unused_clusters_by_region[region] = unused_clusters

        if unused_clusters_by_region:
            total_clusters = sum(len(clusters) for clusters in unused_clusters_by_region.values())

            unused_data = {
                "unused_clusters_by_region": unused_clusters_by_region,
                "total_clusters": total_clusters
            }
            overall_unused_data.append(unused_data)
            overall_unused_data_count.append(total_clusters)


    def get_rds_databases(self, start_time):
        regions = [region['RegionName'] for region in self.rds_client.describe_db_instances()['DBInstances']]
        all_databases = []

        for region_name in regions:
            rds_client = self.session.client('rds', region_name=region_name)
            response = rds_client.describe_db_instances()

            for db_instance in response['DBInstances']:
                db_instance_id = db_instance['DBInstanceIdentifier']
                db_instance_status = db_instance['DBInstanceStatus']
                instance_create_time = db_instance['InstanceCreateTime']

                if db_instance_status == 'available':
                    last_activity_time = self.utc_now
                elif db_instance_status == 'stopped':
                    last_activity_time = instance_create_time.replace(tzinfo=timezone.utc)
                else:
                    last_activity_time = None

                all_databases.append({
                    'db_instance_id': db_instance_id,
                    'db_instance_status': db_instance_status,
                    'last_activity_time': last_activity_time.strftime("%Y-%m-%d %H:%M:%S %Z") if last_activity_time else None
                })

        unused_databases = [db for db in all_databases
                            if db['db_instance_status'] == 'stopped' and db['last_activity_time'] and
                            db['last_activity_time'] >= (datetime.utcnow() - timedelta(start_time)).replace(tzinfo=timezone.utc)]

        unused_databases.sort(key=lambda x: (x['last_activity_time'] is None, x['last_activity_time']))

        total_rds_databases = len(all_databases)
        total_unused_databases = len(unused_databases)

        unused_data = {
            "all_databases": all_databases,
            "unused_databases": unused_databases,
            "total_rds_databases": total_rds_databases,
            "total_unused_databases": total_unused_databases
        }
        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(total_unused_databases)

    def get_unused_s3_buckets(self, start_time):
        buckets = self.s3_client.list_buckets()

        total_buckets = len(buckets['Buckets'])

        unused_buckets = []

        for bucket in buckets['Buckets']:
            bucket_name = bucket['Name']

            last_modified = self.s3_client.list_objects_v2(Bucket=bucket_name).get('Contents', [])

            if last_modified:
                last_modified_time = max(item['LastModified'].replace(tzinfo=timezone.utc) for item in last_modified)

                if datetime.utcnow().replace(tzinfo=timezone.utc) - last_modified_time > timedelta(start_time):
                    unused_buckets.append({
                        'bucket_name': bucket_name,
                        'last_modified_time': last_modified_time.strftime("%Y-%m-%d %H:%M:%S %Z") if last_modified_time else None
                    })
            else:
                unused_buckets.append({
                    'bucket_name': bucket_name,
                    'last_modified_time': None
                })

        unused_data = {
            "unused_buckets": unused_buckets,
            "total_buckets": total_buckets,
            "unused_buckets_count": len(unused_buckets)
        }
        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(len(unused_buckets))

    def get_unused_secrets(self, start_time):
        secrets_response = self.secrets_manager_client.list_secrets()

        all_secrets = []

        for secret in secrets_response['SecretList']:
            secret_name = secret['Name']
            log_group_name = f'/aws/secretsmanager/{secret_name}'

            log_events = self.cloudwatch_logs_client.describe_log_streams(logGroupName=log_group_name)['logStreams']

            last_log_event_time = self.get_last_log_event_time(log_events)
            all_secrets.append({
                'secret_name': secret_name,
                'last_log_event_time': last_log_event_time.strftime("%Y-%m-%d %H:%M:%S %Z") if last_log_event_time else None
            })

        unused_secrets = [secret for secret in all_secrets
                        if secret['last_log_event_time'] and secret['last_log_event_time'] >= (
                                datetime.utcnow() - timedelta(start_time)).replace(tzinfo=timezone.utc)]

        unused_secrets.sort(key=lambda x: (x['last_log_event_time'] is None, x['last_log_event_time']))

        total_secrets = len(all_secrets)
        total_unused_secrets = len(unused_secrets)

        unused_data = {
            "all_secrets": all_secrets,
            "unused_secrets": unused_secrets,
            "total_secrets": total_secrets,
            "total_unused_secrets": total_unused_secrets
        }
        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(total_unused_secrets)

    def get_last_log_event_time(self, log_events):
        if log_events:
            return log_events[0]['timestamp']
        else:
            return None

    def get_unused_waf_webacls(self, start_time):
        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']]

        unused_wafs_by_region = {}

        for region in regions:
            current_wafv2_client = self.session.client('wafv2', region_name=region)

            webacls = current_wafv2_client.list_web_acls(Scope='REGIONAL')['WebACLs']

            unused_wafs = []

            for webacl in webacls:
                webacl_id = webacl['Id']
                webacl_info = current_wafv2_client.get_web_acl(Name=webacl_id)['WebACL']

                if 'LastMigrated' in webacl_info:
                    last_modified_time = datetime.utcfromtimestamp(webacl_info['LastMigrated'])
                    if self.utc_now - last_modified_time > timedelta(days=start_time):
                        unused_wafs.append({
                            'webacl_id': webacl_id,
                            'last_modified_time': last_modified_time.strftime("%Y-%m-%d %H:%M:%S %Z")
                        })

            if unused_wafs:
                unused_wafs_by_region[region] = unused_wafs

        if unused_wafs_by_region:
            total_wafs = sum(len(wafs) for wafs in unused_wafs_by_region.values())

            waf_unused_data = {
                "unused_wafs_by_region": unused_wafs_by_region,
                "total_wafs": total_wafs
            }
            overall_unused_data.append(waf_unused_data)
            overall_unused_data_count.append(len(unused_wafs))


class EC2_Recommendations(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

                # Check if AWS credentials are configured
            if not access_key or not secret_key:
                    return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

                # Configure the AWS client with the stored credentials
            session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                )
            ec2 = session.client('ec2')


            ec2_regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

            instance_data = []

            for region_name in ec2_regions:
                ec2 = session.client('ec2', region_name=region_name)
                cloudwatch = session.client('cloudwatch', region_name=region_name)

                # Describe EC2 instances in the region
                instances = ec2.describe_instances()

                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        instance_type = instance['InstanceType']
                        platform = instance.get('Platform', 'Linux')

                        
                        end_time = datetime.utcnow()
                        time_range=request.GET.get('time-range')
                                        # Calculate start time based on the time range provided by the user
                        if time_range == "1 Week":
                            start_time = end_time - timedelta(weeks=1)
                        elif time_range == "15 Days":
                            start_time = end_time - timedelta(days=15)
                        
                        elif time_range == "1 Month":
                            start_time = end_time - timedelta(weeks=4 * 1)
                        
                        elif time_range == "3 Months":
                            start_time = end_time - timedelta(weeks=4 * 3)
                        elif time_range == "6 Months":
                            start_time = end_time - timedelta(weeks=4 * 6)
                        print(start_time)
                        response_cpu = cloudwatch.get_metric_data(
                            MetricDataQueries=[
                                {
                                    'Id': 'mem_utilization',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': 'CWAgent',
                                            'MetricName': 'mem_used_percent',
                                            'Dimensions': [
                                                {
                                                    'Name': 'InstanceId',
                                                    'Value': instance_id
                                                },
                                            ]
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average',
                                    },
                                    'ReturnData': True,
                                },
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                        )

                        # Describe volumes attached to the instance
                        volumes = ec2.describe_volumes(Filters=[
                            {'Name': 'attachment.instance-id', 'Values': [instance_id]}
                        ])
                        average_value_cpu = 0
                        if 'MetricDataResults' in response_cpu:
                            utilization_info = response_cpu['MetricDataResults'][0]['Values']
                            print(utilization_info)
                            if utilization_info:
                                average_value_cpu = round(sum(utilization_info) / len(utilization_info),3)
                            print(average_value_cpu)

                        # Extract volume information

                        if average_value_cpu > 0:
                                instance_data.append({
                                    'Region': region_name,
                                    'InstanceId': instance_id,
                                    'InstanceType': instance_type,
                                    'OperatingSystem': platform,
                                    'RAM_Utilization': average_value_cpu,
                                    'Volumes': [{'Size(GB)': vol['Size']} for vol in volumes['Volumes']],
                                })

            # Read CSV data into a dictionary for efficient lookup
            instance_prices = {}
            with open('ec2_instance_prices.csv', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    instance_type = row['Instance Type']
                    instance_prices[instance_type] = {
                        'Instance Type':row['Instance Type'],
                        'Market': row['Market'],
                        'vCPU': row['vCPU'],
                        'RAM (GiB)': row['RAM (GiB)'],
                    }
            csv_first_letters = set(instance_type[0] for instance_type in instance_prices.keys())
            # Process instance data
            for instance in instance_data:
                instance_type = instance['InstanceType']

                # Check if instance type exists in the CSV data
                if instance_type in instance_prices:
                    instance_price_data = instance_prices[instance_type]
                else:
                    # If not found, set default values
                    instance_price_data = {
                        'Instance Type':'N/A',
                        'Market': 'N/A',
                        'vCPU': 'N/A',
                        'RAM (GiB)': 'N/A',
                    }

                # Check if CPU utilization is less than 50%
                existing_data=[]
                matching_data=[]
                instance_type_first_letter = instance_type[0]
                if instance['RAM_Utilization'] < 50 and instance_type_first_letter in csv_first_letters:
                    # Calculate half RAM value
                    ram_value = instance_price_data['RAM (GiB)']
                    if ram_value != 'N/A':
                        half_ram = float(ram_value) / 2
                    else:
                        half_ram = 'N/A'

                    # Check if half RAM value matches any RAM values in CSV file
                    matching_ram_instances = [
                        instance_data for instance_data in instance_prices.values() if instance_data['RAM (GiB)'] == str(half_ram) and instance_data['Instance Type'][0] == instance_type_first_letter
                    ]

                    # Print instance data for matching RAM values
                    existing_data.append({"Region": instance['Region'], 
                                        "Instance ID": instance['InstanceId'], 
                                        "Instance Type": instance_type, 
                                        "Operating System": instance['OperatingSystem'], 
                                        "RAM_utilization" :instance['RAM_Utilization'] ,
                            " Suggestion": "this Instance utilizing less than 50%, so consider changing the RAM to lower."})

                    

                    for matching_instance in matching_ram_instances:
                        matching_data.append(matching_instance)
                    ec2_json_response = {
                        'instanceData :': existing_data,
                        'Matching Instance Data  :': matching_data,
                    }
                    response_json = json.dumps(ec2_json_response, indent=4)
                    recommendation_response = HttpResponse(response_json, content_type='application/json')
                    
                    return recommendation_response
                    

                else:
                    # Print instance data as it is
                    existing_data.append({"Region": instance['Region'], 
                                        "Instance ID": instance['InstanceId'], 
                                            "Instance Type": instance_type, 
                                            "Operating System": instance['OperatingSystem'],
                                            "RAM_utilization" :instance['RAM_Utilization'],
                                            "Suggestion": "No action needed." ,
                                            "Instance Price Data": instance_price_data})
                    ec2_json_response = {
                        'instanceData :': existing_data,
                        'Matching Instance Data  :': matching_data,
                    }
                    response_json = json.dumps(ec2_json_response, indent=4)
                    response = HttpResponse(response_json, content_type='application/json')
                    
                    return response
                    
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)

def get_last_activity_time(self, instance_state, launch_time):
    if instance_state == 'running':
        return datetime.utcnow()
    elif instance_state == 'stopped':
        # Use the instance's launch time as an estimate for last activity time
        return launch_time
    else:
        # Handle other states as needed
        return None

class EC2_Utilization(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get_last_activity_time(self, instance_state, launch_time):
        if instance_state == 'running':
            return datetime.utcnow()
        elif instance_state == 'stopped':
            return launch_time
        else:
            return None

    def get(self, request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            all_utilization_info = []

            regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]

            count = 0  # Initialize count

            for region_name in regions:
                ec2_client = session.client('ec2', region_name=region_name)

                response = ec2_client.describe_instances()

                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        instance_type = instance['InstanceType']
                        state = instance['State']['Name']
                        launch_time = instance['LaunchTime']

                        last_activity_time = self.get_last_activity_time(state, launch_time)

                        cloudwatch_client = session.client('cloudwatch', region_name=region_name)

                        end_time = datetime.utcnow()
                        time_range=request.GET.get('time-range')
                                        # Calculate start time based on the time range provided by the user
                        if time_range == "1 Week":
                            start_time = end_time - timedelta(weeks=1)
                        elif time_range == "15 Days":
                            start_time = end_time - timedelta(days=15)
                        
                        elif time_range == "1 Month":
                            start_time = end_time - timedelta(weeks=4 * 1)
                        
                        elif time_range == "3 Months":
                            start_time = end_time - timedelta(weeks=4 * 3)
                        elif time_range == "6 Months":
                            start_time = end_time - timedelta(weeks=4 * 6)

                        response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[
                                {
                                    'Id': 'mem_utilization',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': 'CWAgent',
                                            'MetricName': 'mem_used_percent',
                                            'Dimensions': [
                                                {
                                                    'Name': 'InstanceId',
                                                    'Value': instance_id
                                                },
                                            ]
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average',
                                    },
                                    'ReturnData': True,
                                },
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                        )

                        cpu_response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[
                                {
                                    'Id': 'cpu_utilization',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': 'AWS/EC2',
                                            'MetricName': 'CPUUtilization',
                                            'Dimensions': [
                                                {
                                                    'Name': 'InstanceId',
                                                    'Value': instance_id
                                                },
                                            ]
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average',
                                    },
                                    'ReturnData': True,
                                },
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                        )

                        if 'MetricDataResults' in response and 'MetricDataResults' in cpu_response:
                            for mem_metric_result, cpu_metric_result in zip(response['MetricDataResults'], cpu_response['MetricDataResults']):
                                if 'Values' in mem_metric_result and 'Values' in cpu_metric_result:
                                    mem_utilization_info = mem_metric_result['Values']
                                    cpu_utilization_info = cpu_metric_result['Values']

                                    if mem_utilization_info and cpu_utilization_info:
                                        mem_average_value = round(sum(mem_utilization_info) / len(mem_utilization_info), 2)
                                        cpu_average_value = round(sum(cpu_utilization_info) / len(cpu_utilization_info), 2)

                                        if 0 < mem_average_value <= 50 and 0 < cpu_average_value <= 50:
                                            count += 1

                                        all_utilization_info.append({
                                            'region': region_name,
                                            'instance_id': instance_id,
                                            'instance_type': instance_type,
                                            'state': state,
                                            'memory_average_utilization': mem_average_value,
                                            'cpu_average_utilization': cpu_average_value,
                                            'last_activity_time': last_activity_time,
                                        })

            print(f"Count of instances with memory and CPU utilization between 0% and 50%: {count}")

            # Continue with the rest of your code or return the response
            return JsonResponse({'utilization_info': all_utilization_info,
                                 'count':count})

        except Exception as e:
            # Handle exceptions appropriately
            return JsonResponse({'error': str(e)}, status=500)


class AWS_Unused_Resources(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        access_key = settings.AWS_ACCESS_KEY_ID
        secret_key = settings.AWS_SECRET_ACCESS_KEY

        # Check if AWS credentials are configured
        if not access_key or not secret_key:
            raise ValueError('AWS credentials are not configured')

        # Configure the AWS client with the stored credentials
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        self.lambda_client = self.session.client('lambda')
        self.ec2_client = self.session.client('ec2')
        self.ecr_client = self.session.client('ecr')
        self.ecs_client = self.session.client('ecs')
        self.rds_client = self.session.client('rds')
        self.s3_client = self.session.client('s3')
        self.secrets_manager_client = self.session.client('secretsmanager')
        self.wafv2_client = self.session.client('wafv2')
        self.cloudwatch_logs_client = self.session.client('logs')
        self.utc_now = datetime.utcnow().replace(tzinfo=timezone.utc)

    def get(self, request):
        try:
            
            self.get_lambda_functions()
            self.get_ec2_instances()
            self.get_ecr_repositories()
            self.get_unused_ecs_clusters()
            self.get_rds_databases()
            self.get_unused_s3_buckets()
            
            self.get_unused_waf_webacls()

            sum_overall_count = sum(overall_unused_data_count)
            json_response = json.dumps(
                {"unused_data": overall_unused_data, "unused_data_count": sum_overall_count},
                default=str)
            response = HttpResponse(json_response, content_type='application/json')
            overall_unused_data.clear()
            overall_unused_data_count.clear() 
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, content_type='application/json', status=500)

    def get_ec2_instances(self):
        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                   if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

        all_instances = []
        instance_prices = {}
        with open('ec2_instance_prices.csv', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                instance_type = row['Instance Type']
                instance_prices[instance_type] = {
                    'Instance Type': row['Instance Type'],
                    'Market': row['Market'],
                    'vCPU': row['vCPU'],
                    'RAM (GiB)': row['RAM (GiB)'],
                    'Price ($/m)': float(row['Price ($/m)'])  # Convert price to float
                }

        total_price = 0  # Initialize total price

        for region_name in regions:
            ec2_client = self.session.client('ec2', region_name=region_name)

            response = ec2_client.describe_instances()

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    state = instance['State']['Name']
                    launch_time = instance['LaunchTime']

                    if state == 'running':
                        last_activity_time = self.utc_now
                    elif state == 'stopped':
                        last_activity_time = launch_time.replace(tzinfo=timezone.utc)
                    else:
                        last_activity_time = None

                    instance_type = instance['InstanceType']
                    instance_info = instance_prices.get(instance_type, {})
                    price = instance_info.get('Price ($/m)')

                    # Calculate the unused duration dynamically
                    unused_duration = (self.utc_now - last_activity_time).days if last_activity_time else None

                    # Append data as a dictionary
                    all_instances.append({
                        'instance_id': instance_id,
                        'state': state,
                        'last_activity_time': last_activity_time,
                        'instance_type': instance_info.get('Instance Type'),
                        'price (USD/month)': price,
                        'unused_duration': unused_duration  # Add unused duration to the result
                    })

                    # Accumulate the price for unused instances
                    if state == 'stopped' and last_activity_time and \
                            instance_type in instance_prices:
                        total_price += price

        unused_instances = [
            {
                'instance_id': instance['instance_id'],
                'state': instance['state'],
                'last_activity_time': instance['last_activity_time'],
                'instance_type': instance['instance_type'],
                'price (USD/month)': instance['price (USD/month)'],
                'unused_duration': instance['unused_duration']
            }
            for instance in all_instances
            if instance['state'] == 'stopped' and instance['last_activity_time'] and
            instance['instance_type'] in instance_prices
        ]

        unused_instances.sort(key=lambda x: (x['last_activity_time'] is None, x['last_activity_time']))

        total_ec2_instances = len(all_instances)
        total_unused_instances = len(unused_instances)

        unused_data = {
            "all_instances": all_instances,
            "unused_instances": unused_instances,
            "total_ec2_instances": total_ec2_instances,
            "total_unused_instances": total_unused_instances,
            "total_price (USD/month)": round(total_price, 2)  # Add total price to the result
        }
        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(total_unused_instances)
    def get_lambda_functions(self):
        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

        all_functions_across_regions = []
        unused_functions_across_regions = []

        for region_name in regions:
            function_client = self.session.client('lambda', region_name=region_name)
            response = function_client.list_functions()
            functions = response['Functions']

            all_functions = []

            for function in functions:
                function_name = function['FunctionName']
                last_modified_time_str = function['LastModified']
                last_activity_time = datetime.strptime(last_modified_time_str, '%Y-%m-%dT%H:%M:%S.%f%z')

                # Calculate unused time dynamically
                unused_time = (self.utc_now - last_activity_time).days if last_activity_time else None

                # Append data as a dictionary for the current region
                all_functions.append({
                    'function_name': function_name,
                    'last_activity_time': last_activity_time,
                    'unused_time': unused_time
                })

            unused_functions = [
                {
                    'function_name': function['function_name'],
                    'last_activity_time': function['last_activity_time'],
                    'unused_time': function['unused_time']
                }
                for function in all_functions
                if function['unused_time'] is not None
            ]

            unused_functions.sort(key=lambda x: (x['last_activity_time'] is None, x['last_activity_time']))

            # Append data for the current region to the accumulative lists
            all_functions_across_regions.extend(all_functions)
            unused_functions_across_regions.extend(unused_functions)

        # Calculate totals for all regions
        total_functions_across_regions = len(all_functions_across_regions)
        total_unused_functions_across_regions = len(unused_functions_across_regions)

        # Create the final data dictionary for all regions
        unused_data_across_regions = {
            "all_functions": all_functions_across_regions,
            "unused_functions": unused_functions_across_regions,
            "total_functions": total_functions_across_regions,
            "total_unused_functions": total_unused_functions_across_regions
        }

        # Append the data for all regions to the overall lists
        overall_unused_data.append(unused_data_across_regions)
        overall_unused_data_count.append(total_unused_functions_across_regions)


    def get_ecr_repositories(self):
        all_repositories_across_regions = []
        unused_repositories_across_regions = []

        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

        for region_name in regions:
            ecr_client = self.session.client('ecr', region_name=region_name)
            response = ecr_client.describe_repositories()

            all_repositories = []
            unused_repositories = []

            for repository in response.get('repositories', []):
                repository_name = repository['repositoryName']
                image_count = repository.get('imageCount', 0)
                creation_time = repository.get('createdAt')

                # Calculate repository age dynamically
                repository_age = (self.utc_now - creation_time).days if creation_time else None

                # Append data as a dictionary to all_repositories
                all_repositories.append({
                    'repository_name': repository_name,
                    'image_count': image_count,
                    'repository_age': repository_age
                })

                # Filter repositories with no images and append as a dictionary to unused_repositories
                if image_count == 0:
                    unused_repositories.append({
                        'repository_name': repository_name,
                        'image_count': image_count,
                        'repository_age': repository_age
                    })

            # Append data for the current region to the accumulative lists
            all_repositories_across_regions.extend(all_repositories)
            unused_repositories_across_regions.extend(unused_repositories)

        # Calculate totals for all regions
        total_repositories_across_regions = len(all_repositories_across_regions)
        total_unused_repositories_across_regions = len(unused_repositories_across_regions)

        # Create the final data dictionary for all regions
        unused_data_across_regions = {
            "all_repositories": all_repositories_across_regions,
            "unused_repositories": unused_repositories_across_regions,
            "total_repositories": total_repositories_across_regions,
            "total_unused_repositories": total_unused_repositories_across_regions
        }

        # Append the data for all regions to the overall lists
        overall_unused_data.append(unused_data_across_regions)
        overall_unused_data_count.append(total_unused_repositories_across_regions)
        

    def get_unused_ecs_clusters(self):
        unused_clusters_by_region = {}

        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                   if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

        for region in regions:
            current_ecs_client = self.session.client('ecs', region_name=region)

            clusters = current_ecs_client.list_clusters()['clusterArns']

            unused_clusters = []

            for cluster_arn in clusters:
                cluster_name = cluster_arn.split("/")[-1]
                cluster_info = current_ecs_client.describe_clusters(clusters=[cluster_name])['clusters'][0]

                if 'lastStatus' in cluster_info:
                    last_status_time = cluster_info['lastStatus'].get('updatedAt', cluster_info['createdAt'])
                    last_activity_time = datetime.strptime(last_status_time, "%Y-%m-%dT%H:%M:%S.%f%z")
                    unused_time = (datetime.now() - last_activity_time).days

                    # Remove the condition related to timedelta(start_time)
                    unused_clusters.append({
                        'cluster_name': cluster_name,
                        'last_activity_time': last_activity_time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                        'unused_time': unused_time
                    })

            if unused_clusters:
                unused_clusters_by_region[region] = unused_clusters

        if unused_clusters_by_region:
            total_clusters = sum(len(clusters) for clusters in unused_clusters_by_region.values())

            unused_data = {
                "unused_clusters_by_region": unused_clusters_by_region,
                "total_clusters": total_clusters
            }
            overall_unused_data.append(unused_data)
            overall_unused_data_count.append(total_clusters)
    def get_rds_databases(self):
        regions =  [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                   if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]
        all_databases = []

        for region_name in regions:
            rds_client = self.session.client('rds', region_name=region_name)
            response = rds_client.describe_db_instances()
            

            for db_instance in response['DBInstances']:
                db_instance_id = db_instance['DBInstanceIdentifier']
                db_instance_status = db_instance['DBInstanceStatus']
                instance_create_time = db_instance['InstanceCreateTime']

                if db_instance_status == 'available':
                    last_activity_time = self.utc_now
                elif db_instance_status == 'stopped':
                    last_activity_time = instance_create_time.replace(tzinfo=timezone.utc)
                else:
                    last_activity_time = None

                unused_time = (self.utc_now - last_activity_time).days if last_activity_time else None

                all_databases.append({
                    'db_instance_id': db_instance_id,
                    'db_instance_status': db_instance_status,
                    'last_activity_time': last_activity_time.strftime("%Y-%m-%d %H:%M:%S %Z") if last_activity_time else None,
                    'unused_time': unused_time
                })

        unused_databases = [db for db in all_databases
                            if db['db_instance_status'] == 'stopped' and db['unused_time'] is not None]

        unused_databases.sort(key=lambda x: (x['last_activity_time'] is None, x['last_activity_time']))

        total_rds_databases = len(all_databases)
        total_unused_databases = len(unused_databases)

        unused_data = {
            "all_databases": all_databases,
            "unused_databases": unused_databases,
            "total_rds_databases": total_rds_databases,
            "total_unused_databases": total_unused_databases
        }
        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(total_unused_databases)
        
    def is_bucket_empty(self,bucket_name):
        # Create an S3 client
        

        # List the objects in the bucket
        objects = self.s3_client.list_objects_v2(Bucket=bucket_name)

        # Check if the bucket is empty
        return 'Contents' not in objects
    def get_unused_s3_buckets(self):
        buckets = self.s3_client.list_buckets()

        total_buckets = len(buckets['Buckets'])

        unused_buckets = []

        for bucket in buckets['Buckets']:
            if self.is_bucket_empty(bucket['Name']):

                    unused_buckets.append({
                        'bucket_name':bucket['Name'],
                        
                    })

        unused_data = {
            "unused_buckets": unused_buckets,
            "total_buckets": total_buckets,
            "unused_buckets_count": len(unused_buckets)
        }

        overall_unused_data.append(unused_data)
        overall_unused_data_count.append(len(unused_buckets))

    def get_last_modified_time(self, bucket_name):
        objects = self.s3_client.list_objects_v2(Bucket=bucket_name).get('Contents', [])
        
        if objects:
            last_modified_time = max(item['LastModified'].replace(tzinfo=timezone.utc) for item in objects)
            return last_modified_time

        return None
    def get_unused_secrets(self):
        all_secrets_across_regions = []
        unused_secrets_across_regions = []

        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

        for region_name in regions:
            secrets_manager_client = self.session.client('secretsmanager', region_name=region_name)
            cloudwatch_logs_client = self.session.client('logs', region_name=region_name)

            secrets_response = secrets_manager_client.list_secrets()

            all_secrets = []

            for secret in secrets_response['SecretList']:
                secret_name = secret['Name']
                log_group_name = f'/aws/secretsmanager/{secret_name}'

                
                log_events = cloudwatch_logs_client.describe_log_streams(logGroupName=log_group_name)['logStreams']
                

                last_log_event_time = self.get_last_log_event_time(log_events)
                unused_days = (self.utc_now - last_log_event_time).days if last_log_event_time else None

                all_secrets.append({
                    'secret_name': secret_name,
                    'last_log_event_time': last_log_event_time.strftime("%Y-%m-%d %H:%M:%S %Z") if last_log_event_time else None,
                    'unused_days': unused_days
                })

            # Append data for the current region to the accumulative lists
            all_secrets_across_regions.extend(all_secrets)
            unused_secrets_across_regions.extend([secret for secret in all_secrets if secret['unused_days'] is not None])

        # Calculate totals for all regions
        total_secrets_across_regions = len(all_secrets_across_regions)
        total_unused_secrets_across_regions = len(unused_secrets_across_regions)

        # Create the final data dictionary for all regions
        unused_data_across_regions = {
            "all_secrets": all_secrets_across_regions,
            "unused_secrets": unused_secrets_across_regions,
            "total_secrets": total_secrets_across_regions,
            "total_unused_secrets": total_unused_secrets_across_regions
        }

        # Append the data for all regions to the overall lists
        overall_unused_data.append(unused_data_across_regions)
        overall_unused_data_count.append(total_unused_secrets_across_regions)

    def get_last_log_event_time(self, log_events):
        if log_events:
            last_log_event = max(log_events, key=lambda x: x.get('timestamp', 0))
            last_event_timestamp = last_log_event.get('timestamp')

            if last_event_timestamp:
                last_log_event_time = datetime.utcfromtimestamp(last_event_timestamp / 1000.0)
                return last_log_event_time

        return None


    def get_unused_waf_webacls(self):
        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                   if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

        unused_wafs_by_region = {}

        for region in regions:
            current_wafv2_client = self.session.client('wafv2', region_name=region)

            webacls = current_wafv2_client.list_web_acls(Scope='REGIONAL')['WebACLs']

            unused_wafs = []

            for webacl in webacls:
                webacl_id = webacl['Id']
                webacl_info = current_wafv2_client.get_web_acl(Name=webacl_id)['WebACL']

                if 'LastMigrated' in webacl_info:
                    last_modified_time = datetime.utcfromtimestamp(webacl_info['LastMigrated'])
                    unused_days = (self.utc_now - last_modified_time).days

                    unused_wafs.append({
                        'webacl_id': webacl_id,
                        'last_modified_time': last_modified_time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                        'unused_days': unused_days
                    })

            if unused_wafs:
                unused_wafs_by_region[region] = unused_wafs

        if unused_wafs_by_region:
            total_wafs = sum(len(wafs) for wafs in unused_wafs_by_region.values())

            waf_unused_data = {
                "unused_wafs_by_region": unused_wafs_by_region,
                "total_wafs": total_wafs
            }
            overall_unused_data.append(waf_unused_data)
            overall_unused_data_count.append(total_wafs)


class RDS_Recommendation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY

            # Check if AWS credentials are configured
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            cloudwatch_namespace = 'AWS/RDS'
            cpu_metric_name = 'CPUUtilization'
            freeable_memory_metric_name = 'FreeableMemory'
            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]

            # Load instance memory information from the CSV file into a dictionary
            instance_memory_info = {}
            with open('rds_instance_types.csv', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    instance_type = row['Instance type']
                    memory = row['Memory']
                    instance_memory_info[instance_type] = memory

            # Initialize an empty list to store instance details
            instances_list = []

            # Loop through each region
            for region in regions:
                # Initialize session client for RDS in the current region
                rds_client_region = boto3.client('rds', region_name=region)
                # Initialize session client for CloudWatch
                cloudwatch_client = boto3.client('cloudwatch', region_name=region)

                # Fetch RDS instances in the region
                instances = rds_client_region.describe_db_instances()['DBInstances']

                # Loop through each RDS instance and gather details
                for instance in instances:
                    db_identifier = instance['DBInstanceIdentifier']
                    engine = instance['Engine']
                    db_instance_class = instance['DBInstanceClass']
                    status = instance['DBInstanceStatus']
                    instance_type = instance['DBInstanceClass']
                    db_connections_read_write = instance.get('ReadReplicaSourceDBInstanceIdentifier', 'N/A')

                    storage = instance.get('AllocatedStorage', 'N/A')
                    allocated_storage = instance['AllocatedStorage']
                    end_time = datetime.utcnow()
                    time_range = request.GET.get('time-range')
                    # Calculate start time based on the time range provided by the user
                    if time_range == "1 Week":
                        start_time = end_time - timedelta(weeks=1)
                    elif time_range == "15 Days":
                        start_time = end_time - timedelta(days=15)
                    elif time_range == "1 Month":
                        start_time = end_time - timedelta(weeks=4 * 1)
                    elif time_range == "3 Months":
                        start_time = end_time - timedelta(weeks=4 * 3)
                    elif time_range == "6 Months":
                        start_time = end_time - timedelta(weeks=4 * 6)

                    # Load memory information based on matching instance type
                    memory = instance_memory_info.get(instance_type, 'N/A')

                    # Fetch CPU utilization metric
                    cpu_metric = cloudwatch_client.get_metric_statistics(
                        Namespace=cloudwatch_namespace,
                        MetricName=cpu_metric_name,
                        Dimensions=[
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': db_identifier
                            },
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=7200,  # 1 hour intervals
                        Statistics=['Average']
                    )

                    # Fetch Freeable Memory metric
                    freeable_memory_metric = cloudwatch_client.get_metric_statistics(
                        Namespace=cloudwatch_namespace,
                        MetricName=freeable_memory_metric_name,
                        Dimensions=[
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': db_identifier
                            },
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=7200,  # 1 hour intervals
                        Statistics=['Average']
                    )

                    # Get the latest data point for each metric
                    cpu_utilization = cpu_metric['Datapoints'][-1]['Average'] if cpu_metric['Datapoints'] else 'N/A'
                    freeable_memory = freeable_memory_metric['Datapoints'][-1]['Average'] if freeable_memory_metric[
                        'Datapoints'] else 'N/A'
                    freeable_memory_gb = freeable_memory / (1024 ** 3) if freeable_memory != 'N/A' else 'N/A'
                    free_memory = round(freeable_memory_gb, 2)
                    used_memory = int(memory) - free_memory
                    utilized_memory_in_percentage = (used_memory / int(memory)) * 100
                    existing_data=[]
                    # Check if utilized memory is less than 50%
                    if utilized_memory_in_percentage < 50:
                        # Calculate the new memory value (half of the existing memory)
                        new_memory = float(memory) / 2

                        # Find matching instance types in instance_memory_info with exact match
                        matching_instance_types = [
                            {'instance_name': inst_type, 'memory': inst_memory}
                            for inst_type, inst_memory in instance_memory_info.items() if new_memory == float(inst_memory)
                        ]

                        if matching_instance_types:
                            # Update instance type and memory based on the suggestions
                            instance_type = matching_instance_types

                            # Print or log the suggestion
                            lesser_rds_instance_types = (
                                f"Suggestion: RDS instance {db_identifier} is utilizing less than 50%. "
                                f"You may consider switching to lower RDS instance types: {matching_instance_types}"
                            )

                            # Create a dictionary for the current instance
                            instance_details = {
                                'DBInstanceIdentifier': db_identifier,
                                'Engine': engine,
                                'Status': status,
                                'DBInstanceClass': db_instance_class,
                                'Memory (GB)': memory,
                                'CPUUtilization (%)': round(cpu_utilization, 2),
                                'utilized_memory_in_percentage': utilized_memory_in_percentage,
                                'UsedMemoryGB': used_memory,
                                'FreeMemory': free_memory,
                                'Storage': storage,
                                'AllocatedStorage': allocated_storage,
                                'ConnectionsRW': db_connections_read_write,
                                'Suggestion': f"RDS instance {db_identifier} is utilizing less than 50%. Consider changing the RAM to lower.",
                                'InstanceTypes': matching_instance_types,
                            }

                            # Append the dictionary to the list
                            existing_data.append(instance_details)

                            # Convert the list of dictionaries to a JSON-formatted string
                            RDS_data = json.dumps(existing_data, indent=4)

                            recommendation_response = HttpResponse(RDS_data, content_type='application/json')
                            return recommendation_response

                    # Rest of your code for the else block
                    else:
                        instance_details = {
                            'DBInstanceIdentifier': db_identifier,
                            'Engine': engine,
                            'Status': status,
                            'DBInstanceClass': db_instance_class,
                            'Memory (GB)': memory,
                            'CPUUtilization (%)': round(cpu_utilization, 2),
                            'utilized_memory_in_percentage': utilized_memory_in_percentage,
                            'UsedMemoryGB': used_memory,
                            'FreeMemory': free_memory,
                            'Storage': storage,
                            'AllocatedStorage': allocated_storage,
                            'ConnectionsRW': db_connections_read_write,
                        }

                        # Append the dictionary to the list
                        existing_data.append(instance_details)

                        # Convert the list of dictionaries to a JSON-formatted string
                        RDS_data = json.dumps(existing_data, indent=4)

                        response = HttpResponse(RDS_data, content_type='application/json')
                        return response


        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)