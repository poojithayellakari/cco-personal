

import boto3.session
from django.http import JsonResponse
from .models import CustomUser
from django.utils.timezone import make_aware
from .serializers import CustomUserSerializer, LoginSerializer, CustomTokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenVerifyView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.views import TokenObtainPairView
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
from rest_framework.permissions import AllowAny,AllowAny, IsAuthenticated
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
import requests
from rest_framework.generics import ListAPIView
import base64
import logging

logger = logging.getLogger(__name__)

            
class CheckAPI(APIView):
    # authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]
    def get(self,request):
        print("inside")
        print("Authenticated user:", request.user)
        return Response({"Hello":12})

class RegisterUser(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email')
            if CustomUser.objects.filter(email=email).exists():
                return Response({'error': 'User with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = CustomUserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AWSAccountAndCredentialManagerView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            serializer = AWSAccountAndCredentialManagerSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in AWSAccountAndCredentialManagerView: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AccountDetailsListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            queryset = AccountDetails.objects.filter(user=request.user)
            serializer = AccountDetailsSerializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error in AccountDetailsListView: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
class AWSAccountDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
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
            response_sts = sts_client.get_caller_identity()
            response_iam = iam_client.get_access_key_last_used(AccessKeyId=access_key)
            response_iam_user = iam_client.get_user(UserName=response_iam["UserName"])
            response_iam_access_keys = iam_client.list_access_keys(UserName=response_iam_user["User"]["UserName"])
            output_data = {}
            output_data["UserId"] = response_sts["UserId"]
            output_data["UserName"] = response_iam["UserName"]
            output_data["Account"] = response_sts["Account"]
            output_data["Arn"] = response_sts["Arn"]
            output_data["UserInfo"] = response_iam_user["User"]
            output_data["AccessKeyLastUsed"] = response_iam["AccessKeyLastUsed"]
            output_data["AccessKeys"] = response_iam_access_keys["AccessKeyMetadata"]
            return Response(output_data)
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
class AWSResourcesListCount(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            client = session.client('config')
            resources = [ "AWS::ECR::Repository","AWS::EC2::NetworkAcl","AWS::EC2::VPC","AWS::ECS::Cluster","AWS::EC2::EIP", "AWS::EC2::Instance",  "AWS::EC2::RouteTable", "AWS::EC2::Subnet", "AWS::EC2::Volume", "AWS::EC2::VPC", "AWS::ACM::Certificate", "AWS::RDS::DBInstance", "AWS::RDS::DBSnapshot",  "AWS::S3::Bucket", "AWS::ElasticLoadBalancing::LoadBalancer", "AWS::AutoScaling::AutoScalingGroup","AWS::DynamoDB::Table" , "AWS::Lambda::Function","AWS::SecretsManager::Secret"]
            response = client.get_discovered_resource_counts(resourceTypes=resources)
            return Response(response['resourceCounts'])
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
class AWSEC2Details(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )

            ec2_client = session.client('ec2')
            instances = ec2_client.describe_instances()['Reservations']
            ec2_description = []
            # return Response(instances)
            for info in instances:
                for detail in info['Instances']:
                    instance_detail = {}
                    instance_detail['InstanceId'] = detail['InstanceId']
                    instance_detail['InstanceType'] = detail['InstanceType']
                    instance_detail['AvailabilityZone'] = detail['Placement']['AvailabilityZone']
                    instance_detail['PrivateIpAddress'] = detail['PrivateIpAddress']
                    instance_detail['SubnetId'] = detail['SubnetId']
                    instance_detail['VpcId'] = detail['VpcId']
                    instance_detail['Ebs-VolumeId'] = [{ebs['Ebs']['VolumeId']:ebs['Ebs']['Status']} for ebs in detail['BlockDeviceMappings']]
                    instance_detail['PlatformDetails'] = detail['PlatformDetails']
                    instance_detail['CpuOptions'] = detail['CpuOptions']
                    ec2_description.append(instance_detail)
            return Response(ec2_description)
            
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)

class AWSS3Details(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            s3_client = session.client('s3')
            buckets = s3_client.list_buckets()
            bucket_details = []
            # bucket_lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket='demo-finops-indium')
                
            # return Response(object_details)
            for bucket_name in buckets['Buckets']:
                object_details = {}
                objects = s3_client.list_objects_v2(Bucket=bucket_name['Name'])
                object_details['BucketName'] = bucket_name['Name']
                object_details['No-Of-Objects'] = len(objects['Contents']) if 'Contents' in objects else 0
                # bucket_lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket='demo-finops-indium') 
                # object_details['bucket_lifecycle'] = bucket_lifecycle if 'Rules' in bucket_lifecycle else 'No Rule Defined'
                try:
                    bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name['Name'])
                    object_details['bucket-policy'] = bucket_policy['Policy'] if 'Policy' in bucket_policy else "No policy Defined"
                except Exception as e:
                    object_details['policy'] = 'No policy Defined'
                try:
                    bucket_lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket='demo-finops-indium')
                    object_details['bucket_lifecycle'] = bucket_lifecycle['Rules'] if 'Rules' in bucket_lifecycle else 'No Rule Defined'
                    
                except Exception as e:
                    object_details['bucket_lifecycle'] = 'No Rule Defined'
                bucket_details.append(object_details)
            return Response(bucket_details)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)


class AWSVpcDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            ec2_client = session.client('ec2')
            vpcs = ec2_client.describe_vpcs()
            return Response(vpcs)
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)


class AWSAllServiceCost(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            time_range = request.GET.get('time-range')
            financial_year = request.GET.get('financial-year')

            if not financial_year:
                return JsonResponse({'error': 'Financial year must be specified'}, status=400)
            
            try:
                fy_start_year = int(financial_year.split('-')[0])
                fy_end_year = fy_start_year + 1
                current_date = datetime.utcnow()

                # Determine the date range based on the specified quarter
                if time_range == "Q1":
                    start_time = datetime(fy_start_year, 4, 1)
                    end_time = datetime(fy_start_year, 7, 31)
                elif time_range == "Q2":
                    start_time = datetime(fy_start_year, 8, 1)
                    end_time = datetime(fy_start_year, 11, 30)
                elif time_range == "Q3":
                    start_time = datetime(fy_start_year, 12, 1)
                    end_time = datetime(fy_end_year, 3, 31)
                else:
                    return JsonResponse({'error': 'Invalid time range specified'}, status=400)

                # Adjust end_time to the current date if it exceeds it
                if end_time > current_date:
                    end_time = current_date

            except ValueError:
                return JsonResponse({'error': 'Invalid financial year specified'}, status=400)

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': (end_time + timedelta(days=1)).strftime('%Y-%m-%d')  # Increment end_time by 1 day to include the end date
                },
                Granularity='MONTHLY',
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    },
                ],
                Metrics=['UnblendedCost']
            )
            
            data = response['ResultsByTime']
            cost_info = {}

            for result in data:
                time_period = result['TimePeriod']
                start = time_period['Start']
                month = datetime.strptime(start, '%Y-%m-%d').strftime('%Y-%m')
                cost_group = result['Groups']
                total_monthly_cost = Decimal(0.0)
                for cost in cost_group:
                    monthly_cost = round(float(cost['Metrics']['UnblendedCost']['Amount']), 5)
                    total_monthly_cost += Decimal(monthly_cost)
                cost_info[month] = total_monthly_cost

            # Convert the monthly costs from scientific notation to normal decimal notation
            for month, cost in cost_info.items():
                cost_info[month] = format(cost, '.20f')

            return Response({
                'monthly_breakdown': cost_info
            })
            
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, content_type='application/json', status=500)

class AvailableServices(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
 
    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
           
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1',
            )
            ce_client = session.client('resourcegroupstaggingapi')
 
            resources = []
            pagination_token = ''
           
            while True:
                response = ce_client.get_resources(
                    PaginationToken=pagination_token,
                    ResourcesPerPage=50  # Adjust as needed
                )
               
                resources.extend(response.get('ResourceTagMappingList', []))
               
                pagination_token = response.get('PaginationToken', '')
                if not pagination_token:
                    break
 
            # Format the response data in a Postman-like style
            response_data = []
            for resource in resources:
                resource_arn = resource['ResourceARN']
                tags = resource['Tags']
                response_data.append({
                    "id": resource_arn,
                    "name": resource_arn,
                    "type": "AWS Resource",
                    "attributes": {
                        "ResourceARN": resource_arn,
                        "Tags": tags
                    }
                })
 
            return Response(response_data)
        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=500)
        
class Ec2_instance_usage_type(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
 
    def get_instance_usage_type(self, instance):
        instance_lifecycle = instance.get('InstanceLifecycle')
        # instance_state = instance.get('State', {}).get('Name')
        if instance_lifecycle:
            return instance_lifecycle
        else:
            return "On-Demand"
 
    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
           
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1',
            )
            client = session.client('ec2')
           
            # Describe instances
            response = client.describe_instances()
           
            instance_info = {}
           
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId')
                    instance_type = instance.get('InstanceType', 'Unknown')
                    usage_type = self.get_instance_usage_type(instance)
                   
                    instance_info[instance_id] = {
                        'InstanceType': instance_type,
                        'UsageType': usage_type
                    }
           
            return Response(instance_info, status=200)
       
        except Exception as e:
            return Response({"error": str(e)}, status=500)
class SES_Details(APIView):
        authentication_classes = [JWTAuthentication]
        permission_classes = [IsAuthenticated]
 
        def get(self, request, *args, **kwargs):
            try:
                account_id = request.GET.get('account_id')
                if not account_id:
                    return JsonResponse({'error': 'Account ID is required'}, status=400)
                access_key, secret_key = get_decrypted_credentials(account_id)
                if not access_key or not secret_key:
                    return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name='ap-south-1',
                )
                client = session.client('ses')
                ses_details = {}
 
                # Get Send Quota
                send_quota_response = client.get_send_quota()
                ses_details["SendQuota"] = send_quota_response
 
                # Get Send Statistics
                send_statistics_response = client.get_send_statistics()
                ses_details["SendStatistics"] = send_statistics_response['SendDataPoints']
 
                # List Verified Email Identities
                identities_response = client.list_identities(IdentityType='EmailAddress')
                ses_details["VerifiedEmailAddresses"] = identities_response['Identities']
 
                # List Verified Domains
                domains_response = client.list_identities(IdentityType='Domain')
                ses_details["VerifiedDomains"] = domains_response['Identities']
 
                return JsonResponse(ses_details, safe=False)
 
            except Exception as e:
                return Response({"error": f"An error occurred: {e}"}, status=500)

class UserListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        users = CustomUser.objects.all()
        print(users)
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)

class UserDeleteView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def delete(self, request, email):
        try:
            user = CustomUser.objects.get(email=email)
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)


class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class EC2_Memory_utilization(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
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
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            all_utilization_info = []
            client = session.client('ec2')
            data = client.describe_regions()
            print(data)
            regions = [region['RegionName'] for region in data['Regions']]
            
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
                        last_activity_time_format = last_activity_time.replace(tzinfo=timezone.utc)
                        # Get the current time in UTC.
                        current_time = datetime.now(timezone.utc)
                        inactive_duration= current_time - last_activity_time_format
                        inactive_duration_days = inactive_duration.total_seconds() / (24 * 3600)

                    # Convert the timedelta object to a number of days (rounded to the nearest integer).
                        inactive_days = round(inactive_duration_days)
                        cloudwatch_client = session.client('cloudwatch', region_name=region_name)

                        end_time = datetime.utcnow()
                        # units_str = request.GET.get('units')
                        # if units_str is not None and units_str.isdigit():
                        #     days = int(units_str)
                        time_range=request.GET.get('time-range')
                        start_time=0
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
                                            'Inactive': inactive_days
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
                                            'Inactive': inactive_days
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
                                            'Inactive': inactive_days
                                        })

            all_utilization_info.sort(key=lambda x: (x['state'], x['last_activity_time'] or datetime.min))
            for instance_info in all_utilization_info:
                if instance_info['last_activity_time']:
                    instance_info['last_activity_time'] = str(instance_info['last_activity_time']).split("T")[0]
            response_json = json.dumps(all_utilization_info, indent=4, cls=CustomJSONEncoder)

            service_name = "ec2"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(response_json)

            
            response = HttpResponse(response_json, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)


class RDSData(APIView):
    authentication_classes = [JWTAuthentication]  
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            cloudwatch_namespace = 'AWS/RDS'
            cpu_metric_name = 'CPUUtilization'
            freeable_memory_metric_name = 'FreeableMemory'
            regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]

            # Load instance memory information from the CSV file into a dictionary
            instance_memory_info = {}
            with open('rds_instance_types.csv', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    instance_type = row['Instance type']
                    memory = row['Memory']
                    instance_memory_info[instance_type] = float(memory) if memory != 'N/A' else None

            
            end_time = datetime.utcnow()
            units_str = request.GET.get('units')
            start_time = 0
            days = 0
            if units_str is not None and units_str.isdigit():
                days = int(units_str)
            time_range = request.GET.get('time-range')
            if time_range == "days":
                start_time = end_time - timedelta(days=days)
            elif time_range == "weeks":
                start_time = end_time - timedelta(weeks=days)
            elif time_range == "months":
                start_time = end_time - timedelta(weeks=4 * days)
            # Initialize an empty list to store instance details
            instances_list = []
            loop = 0
            # Loop through each region
            for region in regions:
                # Initialize session client for RDS in the current region
                rds_client_region = session.client('rds', region_name=region)
                # Initialize session client for CloudWatch
                cloudwatch_client = session.client('cloudwatch', region_name=region)

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
                    
                    # Load memory information based on matching instance type
                    memory = instance_memory_info.get(instance_type, None)

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
                        # Period=3600,
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
                        # Period=3600,
                        Statistics=['Average']
                    )

                    if loop==0:
                        print(cpu_metric)
                        print("\n\n")
                        print(freeable_memory_metric)
                        loop = loop+1

                    # Get the latest data point for each metric
                    cpu_utilization = cpu_metric['Datapoints'][-1]['Average'] if cpu_metric['Datapoints'] else 'N/A'
                    freeable_memory = freeable_memory_metric['Datapoints'][-1]['Average'] if freeable_memory_metric['Datapoints'] else 'N/A'
                    # bytes to gigabyte - 1024 bytes in one kilobyte (1024 ** 1), 1024 kilobytes in one megabyte (1024 ** 2), and 1024 megabytes in one gigabyte (1024 ** 3)
                    freeable_memory_gb = freeable_memory / (1024 ** 3) if freeable_memory != 'N/A' else 'N/A'
                    free_memory = freeable_memory_gb if freeable_memory != 'N/A' else 'N/A'
                    used_memory = memory - free_memory if memory is not None and free_memory != 'N/A' else 'N/A'
                    utilized_memory_in_percentage = (used_memory / memory) * 100 if memory is not None and used_memory != 'N/A' else 'N/A'
                    
                    # Create a dictionary for the current instance
                    instance_details = {
                        'DBInstanceIdentifier': db_identifier,
                        'Engine': engine,
                        'Status': status,
                        'DBInstanceClass': db_instance_class,
                        'Memory (GB)': memory,
                        'CPUUtilization (%)': cpu_utilization,
                        'utilized_memory_in_percentage': utilized_memory_in_percentage,
                        'UsedMemoryGB': used_memory,
                        'FreeMemory': free_memory,
                        'Storage': storage,
                        'AllocatedStorage': allocated_storage,
                        'ConnectionsRW': db_connections_read_write,
                        
                    }

                    # Append the dictionary to the list
                    instances_list.append(instance_details)

            # Convert the list of dictionaries to a JSON-formatted string
            RDS_data = json.dumps(instances_list, indent=4)

            # Set the response content type to JSON
            response = HttpResponse(RDS_data, content_type='application/json')

            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)

            
class Secrets_data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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
            service_name = "secrets"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(response_json)

            
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
    account_id = request.GET.get('account_id')
    if not account_id:
        return JsonResponse({'error': 'Account ID is required'}, status=400)
    access_key, secret_key = get_decrypted_credentials(account_id)
    if not access_key or not secret_key:
        return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
    session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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
    service_name = "ecr"  
    filename = f"{service_name}_data.json"

            
    output_directory = "api_v2/aws_cost_accelerator_response" 
    os.makedirs(output_directory, exist_ok=True)

            
    output_file_path = os.path.join(output_directory, filename)
    with open(output_file_path, 'w') as f:
        f.write(response_json)

            
    response = HttpResponse(response_json, content_type='application/json')
    return response

class Get_ECR_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self, request):
        try:
            return fetch_ecr_data_for_regions(request)
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
class Get_S3_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            s3_client = session.client('s3')

            three_days_ago = datetime.now() - timedelta(days=30)
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

            service_name = "s3"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(json_data)

            
            response = HttpResponse(json_data, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
def fetch_lambda_metrics(self,request,lambda_function_name):
    try:
        account_id = request.GET.get('account_id')
        if not account_id:
            return JsonResponse({'error': 'Account ID is required'}, status=400)
        access_key, secret_key = get_decrypted_credentials(account_id)
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
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            lambda_client = session.client('lambda')

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
                start_time = end_time - timedelta(weeks=4)  # Default to 1 month

            regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
            metrics_data = []

            for region in regions:
                lambda_client = session.client('lambda', region_name=region)
                functions = lambda_client.list_functions()['Functions']
                for function in functions:
                    cloudwatch_client = session.client('cloudwatch', region_name=region)
                    response = cloudwatch_client.get_metric_data(
                        MetricDataQueries=[
                            {
                                'Id': 'invocations',
                                'MetricStat': {
                                    'Metric': {
                                        'Namespace': 'AWS/Lambda',
                                        'MetricName': 'Invocations',
                                        'Dimensions': [{'Name': 'FunctionName', 'Value': function['FunctionName']}]
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
                                        'Dimensions': [{'Name': 'FunctionName', 'Value': function['FunctionName']}]
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
                                        'Dimensions': [{'Name': 'FunctionName', 'Value': function['FunctionName']}]
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
                        "Region": region,
                        "Function": function['FunctionName'],
                        "Invocations": invocations,
                        "AvgDuration": avg_duration,
                        "ConcurrentExecutions": concurrent_executions
                    })


            response_json = json.dumps(metrics_data, indent=4)
            response = HttpResponse(response_json, content_type='application/json')
            return response

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
def get_month_year(date):
    return date.strftime('%b-%y')
class FetchAWSCostView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
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
            start_time = end_time - timedelta(days=1)
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
            output_directory = "api_v2/aws_cost_accelerator_response"
            os.makedirs(output_directory,exist_ok=True)
            output_file_path = os.path.join(output_directory,dynamic_filename)
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

            with open(output_file_path,'w') as f:
                f.write(response.content.decode('utf-8'))
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
    permission_classes=[IsAuthenticated]
    def post(self, request):
        try:
            recipient_email = request.data.get('recipient-email')  # Get recipient email from frontend
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
    permission_classes=[IsAuthenticated]
    def get (self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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
            service_name = "vpc"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(response_json)

            
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
    permission_classes=[IsAuthenticated]
    def get (self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            end_time = datetime.utcnow()
            start_time = 0
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
            service_name = "ecs"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(response_json)

            
            response = HttpResponse(response_json, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
from statistics import mean
class Get_load_balancer_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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
            service_name = "load_balancer"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(response_json)

            
            response = HttpResponse(response_json, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_EBS_Data(APIView):
        authentication_classes=[JWTAuthentication]
        permission_classes=[IsAuthenticated]

        def get(self, request):
            try:
                account_id = request.GET.get('account_id')
                if not account_id:
                    return JsonResponse({'error': 'Account ID is required'}, status=400)
                access_key, secret_key = get_decrypted_credentials(account_id)
                if not access_key or not secret_key:
                    return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
                # Configure the AWS client with the stored credentials
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name='ap-south-1'
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
                        volume_metrics = {'VolumeId': volume_id, 'VolumeType': volume_type, 'SizeGB': size_gb, 'Iops': Iops,'attached':False}

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
                                volume_metrics['attached']= True
                        

                        # Append the volume_metrics dictionary to the all_volume_data list
                        all_volume_data.append(volume_metrics)

                response_json = json.dumps(all_volume_data, indent=4)
                service_name = "ebs"  
                filename = f"{service_name}_data.json"

                
                output_directory = "api_v2/aws_cost_accelerator_response" 
                os.makedirs(output_directory, exist_ok=True)

                
                output_file_path = os.path.join(output_directory, filename)
                with open(output_file_path, 'w') as f:
                    f.write(response_json)

                
                response = HttpResponse(response_json, content_type='application/json')
                return response
            except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
           
class Get_WAF_Data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)

            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )

            end_time = datetime.utcnow()
            time_range = request.GET.get('time-range')
            
            if time_range == "1 Week":
                start_time = end_time - timedelta(weeks=1)
            elif time_range == "15 Days":
                start_time = end_time - timedelta(days=15)
            elif time_range == "1 Month":
                start_time = end_time - timedelta(weeks=4)
            elif time_range == "3 Months":
                start_time = end_time - timedelta(weeks=12)
            elif time_range == "6 Months":
                start_time = end_time - timedelta(weeks=24)
            else:
                return JsonResponse({'error': 'Invalid time range specified'}, status=400)

            wafv2_client = session.client('wafv2')
            ec2_client = session.client('ec2')
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

            json_response = []

            for aws_region in regions:
                cloudwatch_client = session.client('cloudwatch', region_name=aws_region)
                try:
                    # Use 'REGIONAL' scope for regional resources
                    response = wafv2_client.list_web_acls(Scope='REGIONAL')
                except ClientError as e:
                    return JsonResponse({'error': f'Error listing Web ACLs: {e.response["Error"]["Message"]}'}, status=500)

                for acl in response['WebACLs']:
                    acl_id = acl['Id']
                    name = acl['Name']
                    metric_name = 'AllowedRequests'
                    namespace = 'AWS/WAFV2'
                    rule_name = 'ALL'

                    dimensions = [
                        {'Name': 'WebACL', 'Value': name},
                        {'Name': 'Rule', 'Value': rule_name}
                    ]

                    try:
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
                    except ClientError as e:
                        return JsonResponse({'error': f'Error fetching metric data: {e.response["Error"]["Message"]}'}, status=500)

                    if 'MetricDataResults' in cloudwatch_response:
                        for data_result in cloudwatch_response['MetricDataResults']:
                            if 'Values' in data_result:
                                values = data_result['Values']
                                data_dict = {
                                    'AWS Region': aws_region,
                                    'Web ACL ID': acl_id,
                                    'Name': name,
                                    'Metric Name': metric_name,
                                    'Metric Values': values
                                }
                                json_response.append(data_dict)

            response = HttpResponse(json.dumps(json_response, indent=4), content_type='application/json')
            return response

        except NoCredentialsError:
            return JsonResponse({'error': 'Credentials not available'}, status=400)
        except PartialCredentialsError:
            return JsonResponse({'error': 'Incomplete credentials provided'}, status=400)
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
    permission_classes=[IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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
    permission_classes=[IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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
                print(response)
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
            service_name = "eip"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(json_response_str)

            
            response = HttpResponse(json_response_str, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
from io import BytesIO
import pandas as pd


class GetTotalBill(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
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
    permission_classes = [IsAuthenticated]

    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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
            service_name = "api_gateway"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(json_response_str)

            
            response = HttpResponse(json_response_str, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_Snapshot_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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

            service_name = "snapshot"  
            filename = f"{service_name}_data.json"

            
            output_directory = "api_v2/aws_cost_accelerator_response" 
            os.makedirs(output_directory, exist_ok=True)

            
            output_file_path = os.path.join(output_directory, filename)
            with open(output_file_path, 'w') as f:
                f.write(json_data)

            
            response = HttpResponse(json_data, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        

from decimal import Decimal
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return super(DecimalEncoder, self).default(obj)
 
overall_unused_data = []
overall_unused_data_count=[]
logger = logging.getLogger(__name__)

class AWSResourceManager(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def is_bucket_empty(self, bucket_name):
        """
        Check if an S3 bucket is empty.
        """
        response = self.s3_client.list_objects_v2(Bucket=bucket_name)
        return 'Contents' not in response
    
    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        print("Setup called")
        account_id = request.GET.get('account_id')
        if not account_id:
            raise ValueError('Account ID is required')
        access_key, secret_key = get_decrypted_credentials(account_id)
        if not access_key or not secret_key:
            raise ValueError('AWS credentials are not configured')
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
            time_range = request.GET.get('time-range')
            days_mapping = {
                "1 Week": 7,
                "15 Days": 15,
                "1 Month": 30,
                "3 Months": 90,
                "6 Months": 180
            }
            start_time = days_mapping.get(time_range)
            if start_time is None:
                raise ValueError('Invalid time range')

            overall_unused_data = []
            overall_unused_data_count = []
            
            self.get_lambda_functions(start_time, overall_unused_data, overall_unused_data_count)
            self.get_ec2_instances(start_time, overall_unused_data, overall_unused_data_count)
            self.get_ecr_repositories(start_time, overall_unused_data, overall_unused_data_count)
            self.get_unused_ecs_clusters(start_time, overall_unused_data, overall_unused_data_count)
            self.get_rds_databases(start_time, overall_unused_data, overall_unused_data_count)
            self.get_unused_s3_buckets(start_time, overall_unused_data, overall_unused_data_count)
            self.get_unused_waf_webacls(start_time, overall_unused_data, overall_unused_data_count)

            sum_overall_count = sum(overall_unused_data_count)
            json_response = json.dumps({"unused_data": overall_unused_data, "unused_data_count": sum_overall_count},
                                       default=str)
            return HttpResponse(json_response, content_type='application/json')
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, content_type='application/json', status=500)
        
    def get_lambda_functions(self, start_time, overall_unused_data, overall_unused_data_count):
        try:
        
            response = self.lambda_client.list_functions()
            functions = response.get('Functions', [])

            all_functions = []

            for function in functions:
                function_name = function.get('FunctionName', 'Unknown')
                last_modified_time_str = function.get('LastModified', '')
                try:
                    last_activity_time = datetime.strptime(last_modified_time_str, '%Y-%m-%dT%H:%M:%S.%f%z')
                except ValueError:
                    last_activity_time = None
                
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
                if function['last_activity_time'] and function['last_activity_time'] < (
                    self.utc_now - timedelta(days=start_time)).replace(tzinfo=timezone.utc)
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
            
        except Exception as e:
            print(f"Error in get_lambda_functions: {e}")
            raise


    def get_ec2_instances(self, start_time, overall_unused_data, overall_unused_data_count):
        try:
            regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                    if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

            all_instances = []
            instance_prices = {}
            with open('ec2_instance_prices.csv', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    instance_type = row.get('Instance Type', 'Unknown')
                    instance_prices[instance_type] = {
                        'Instance Type': row.get('Instance Type', 'Unknown'),
                        'Market': row.get('Market', 'Unknown'),
                        'vCPU': row.get('vCPU', '0'),
                        'RAM (GiB)': row.get('RAM (GiB)', '0'),
                        'Price ($/m)': float(row.get('Price ($/m)', '0'))  # Convert price to float
                    }

            total_price = 0  # Initialize total price

            for region_name in regions:
                ec2_client = self.session.client('ec2', region_name=region_name)
                response = ec2_client.describe_instances()

                for reservation in response.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_id = instance.get('InstanceId', 'Unknown')
                        state = instance.get('State', {}).get('Name', 'Unknown')
                        launch_time = instance.get('LaunchTime', datetime.utcnow())

                        if state == 'running':
                            last_activity_time = self.utc_now
                        elif state == 'stopped':
                            last_activity_time = launch_time.replace(tzinfo=timezone.utc)
                        else:
                            last_activity_time = None

                        instance_type = instance.get('InstanceType', 'Unknown')
                        instance_info = instance_prices.get(instance_type, {})
                        price = instance_info.get('Price ($/m)', 0.0)

                        all_instances.append({
                            'instance_id': instance_id,
                            'state': state,
                            'last_activity_time': last_activity_time,
                            'instance_type': instance_info.get('Instance Type'),
                            'price (USD/month)': price 
                        })

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
                instance['last_activity_time'] < (self.utc_now - timedelta(days=start_time)).replace(tzinfo=timezone.utc) and
                instance['instance_type'] in instance_prices
            ]
            
            total_price = sum(instance['price (USD/month)'] for instance in unused_instances if instance['price (USD/month)'])

            unused_instances.sort(key=lambda x: (x['last_activity_time'] is None, x['last_activity_time']))

            total_ec2_instances = len(all_instances)
            total_unused_instances = len(unused_instances)

            unused_data = {
                "all_instances": all_instances,
                "unused_instances": unused_instances,
                "total_ec2_instances": total_ec2_instances,
                "total_unused_instances": total_unused_instances,
                "total_price (USD/month)": round(total_price,2)
            }
            overall_unused_data.append(unused_data)
            overall_unused_data_count.append(total_unused_instances)
        except Exception as e:
            print(f"Error in get_ec2_instances: {e}")
            raise

    def get_ecr_repositories(self, start_time, overall_unused_data, overall_unused_data_count):
        response = self.ecr_client.describe_repositories()

        all_repositories = []
        unused_repositories = []

        for repository in response.get('repositories', []):
            repository_name = repository['repositoryName']
            image_count = repository.get('imageCount', 0)

            all_repositories.append({
                'repository_name': repository_name,
                'image_count': image_count
            })

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

    def get_unused_ecs_clusters(self, start_time, overall_unused_data, overall_unused_data_count):

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
                    if datetime.now() - last_activity_time > timedelta(days=start_time):
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
            print("hi8")


    def get_rds_databases(self, start_time, overall_unused_data, overall_unused_data_count):
        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
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

                all_databases.append({
                    'db_instance_id': db_instance_id,
                    'db_instance_status': db_instance_status,
                    'last_activity_time': last_activity_time.strftime("%Y-%m-%d %H:%M:%S %Z") if last_activity_time else None
                })

        unused_databases = [db for db in all_databases
                            if db['db_instance_status'] == 'stopped' and db['last_activity_time'] and
                            db['last_activity_time'] > (datetime.utcnow() - timedelta(days=start_time)).replace(tzinfo=timezone.utc)]

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

    def get_unused_s3_buckets(self, start_time, overall_unused_data, overall_unused_data_count):
        print("hi11")
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
        print("hi12")

    def get_unused_secrets(self, start_time, overall_unused_data, overall_unused_data_count):
        print("hi13")
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
        print("hi14")

    def get_last_log_event_time(self, log_events):
        if log_events:
            return log_events[0]['timestamp']
        else:
            return None

    def get_unused_waf_webacls(self, start_time, overall_unused_data, overall_unused_data_count):
        try:
            print("hi15")
            regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                       if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

            unused_wafs_by_region = {}

            for region in regions:
                try:
                    current_wafv2_client = self.session.client('wafv2', region_name=region)
                    response = current_wafv2_client.list_web_acls(Scope='REGIONAL')
                    webacls = response.get('WebACLs', [])

                    unused_wafs = []

                    for webacl in webacls:
                        webacl_id = webacl['Id']
                        try:
                            webacl_info = current_wafv2_client.get_web_acl(Id=webacl_id, Scope='REGIONAL')['WebACL']
                            last_migrated = webacl_info.get('LastMigrated')

                            if last_migrated:
                                last_modified_time = datetime.utcfromtimestamp(last_migrated)
                                if self.utc_now - last_modified_time > timedelta(days=start_time):
                                    unused_wafs.append({
                                        'webacl_id': webacl_id,
                                        'last_modified_time': last_modified_time.strftime("%Y-%m-%d %H:%M:%S %Z")
                                    })
                        except Exception as e:
                            logger.error(f"Error fetching WebACL info for ID {webacl_id}: {e}")

                    if unused_wafs:
                        unused_wafs_by_region[region] = unused_wafs

                except Exception as e:
                    logger.error(f"Error processing region {region}: {e}")

            if unused_wafs_by_region:
                total_wafs = sum(len(wafs) for wafs in unused_wafs_by_region.values())

                waf_unused_data = {
                    "unused_wafs_by_region": unused_wafs_by_region,
                    "total_wafs": total_wafs
                }
                overall_unused_data.append(waf_unused_data)
                overall_unused_data_count.append(total_wafs)
                print("hi16")

        except Exception as e:
            logger.error(f"Error in get_unused_waf_webacls: {e}")
            raise




class AWS_Unused_Resources(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            print("i2")
            # Request-specific setup
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ec2_client = session.client('ec2')
            s3_client = session.client('s3')
            # Add other clients here

            # Call your existing methods
            self.get_ec2_instances(ec2_client, session)
            self.get_lambda_functions(session)
            self.get_ecr_repositories(session)
            self.get_unused_ecs_clusters(session)
            self.get_rds_databases(session)
            self.get_unused_s3_buckets(s3_client)
            self.get_unused_secrets(session)
            self.get_unused_waf_webacls(session)

            sum_overall_count = sum(overall_unused_data_count)
            json_response = json.dumps(
                {"unused_data": overall_unused_data, "unused_data_count": sum_overall_count},
                default=str
            )
            response = HttpResponse(json_response, content_type='application/json')
            overall_unused_data.clear()
            overall_unused_data_count.clear()
            return response

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
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
        try:
            # Fetch all regions except excluded ones
            regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
                    if region['RegionName'] not in ['cn-north-1', 'cn-northwest-1']]

            unused_wafs_by_region = {}

            for region in regions:
                current_wafv2_client = self.session.client('wafv2', region_name=region)

                # List all WebACLs
                try:
                    webacls = current_wafv2_client.list_web_acls(Scope='REGIONAL')['WebACLs']
                except Exception as e:
                    print(f"Error listing WebACLs in region {region}: {e}")
                    continue

                unused_wafs = []

                for webacl in webacls:
                    webacl_id = webacl['Id']
                    try:
                        webacl_info = current_wafv2_client.get_web_acl(Id=webacl_id, Scope='REGIONAL')['WebACL']
                    except Exception as e:
                        print(f"Error fetching WebACL info for ID {webacl_id}: {e}")
                        continue

                    # Ensure 'LastMigrated' is available and in timestamp format
                    if 'LastMigrated' in webacl_info:
                        try:
                            last_modified_time = datetime.utcfromtimestamp(webacl_info['LastMigrated'])
                            unused_days = (self.utc_now - last_modified_time).days

                            unused_wafs.append({
                                'webacl_id': webacl_id,
                                'last_modified_time': last_modified_time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                                'unused_days': unused_days
                            })
                        except Exception as e:
                            print(f"Error processing last_modified_time for WebACL ID {webacl_id}: {e}")
                            continue

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
        except Exception as e:
            print(f"Error fetching unused WAF WebACLs: {e}")



class EC2_Recommendations(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
                # Configure the AWS client with the stored credentials
            session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name='ap-south-1'
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
                        start_time = 0
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
                            if utilization_info:
                                average_value_cpu = round(sum(utilization_info) / len(utilization_info),3)
        
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
            print(instance_data)
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
            print(csv_first_letters)
            # Process instance data
            response_result_updated = []
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
                    # ec2_json_response = {
                    #     'instanceData :': existing_data,
                    #     'Matching Instance Data  :': matching_data,
                    # }
                    # response_json = json.dumps(ec2_json_response, indent=4)
                    # recommendation_response = HttpResponse(response_json, content_type='application/json')
                    
                    # return recommendation_response
                    

                else:
                    # Print instance data as it is
                    existing_data.append({"Region": instance['Region'], 
                                        "Instance ID": instance['InstanceId'], 
                                            "Instance Type": instance_type, 
                                            "Operating System": instance['OperatingSystem'],
                                            "RAM_utilization" :instance['RAM_Utilization'],
                                            "Suggestion": "No action needed." ,
                                            "Instance Price Data": instance_price_data})
                    # ec2_json_response = {
                    #     'instanceData :': existing_data,
                    #     'Matching Instance Data  :': matching_data,
                    # }
                    # response_json = json.dumps(ec2_json_response, indent=4)
                    # response = HttpResponse(response_json, content_type='application/json')
                    
                    # return response
                
                ec2_json_response = {
                        'instanceData :': existing_data,
                        'Matching Instance Data  :': matching_data,
                    }
                response_result_updated.append(ec2_json_response)

            response_json = json.dumps(response_result_updated, indent=4)
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
    permission_classes = [IsAuthenticated]

    def get_last_activity_time(self, instance_state, launch_time):
        if instance_state == 'running':
            return datetime.utcnow()
        elif instance_state == 'stopped':
            return launch_time
        else:
            return None

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
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
                        start_time = 0
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
            return Response({'utilization_info': all_utilization_info,
                                 'count':count})

        except Exception as e:
            # Handle exceptions appropriately
            return JsonResponse({'error': str(e)}, status=500)

class EC2Recommendation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ec2_url = 'http://127.0.0.1:8000/api/ec2_memory_data/'

    def load_data(self, params,token):
        """
        Load the EC2 utilization data from a URL.
        """
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(self.ec2_url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            return pd.DataFrame(data)
        else:
            raise Exception(f"Failed to load data from URL: {self.ec2_url}. Status code: {response.status_code}")

    def identify_unused_instances(self, data, cpu_threshold, memory_threshold):
        """
        Identify instances for termination based on low utilization or stopped state.
        """
        stopped_instances = data[data['state'] == 'stopped']['instance_id'].unique()
        low_utilized_instances = data[(data['average_utilization'] < cpu_threshold) & 
                                      (data['metric_type'].isin(['cpu', 'memory']))]['instance_id'].unique()
        return list(set(stopped_instances) | set(low_utilized_instances))

    def rightsizing_instances(self, data, high_threshold, low_threshold):
        """
        Identify instances for upsizing or downsizing.
        """
        numeric_cols = ['average_utilization']
        grouped_data = data.groupby(['instance_id', 'metric_type'])[numeric_cols].mean().reset_index()
        upsizing_instances = grouped_data[grouped_data['average_utilization'] > high_threshold]['instance_id'].unique()
        downsizing_instances = grouped_data[grouped_data['average_utilization'] < low_threshold]['instance_id'].unique()
        return list({upsizing_instances,grouped_data['average_utilization']}), list({downsizing_instances,grouped_data['average_utilization']})

    def volume_recommendations(self, data, high_disk_threshold, low_disk_threshold):
        """
        Provide volume recommendations based on disk usage.
        """
        numeric_cols = ['average_utilization']
        grouped_data = data.groupby(['instance_id', 'metric_type'])[numeric_cols].mean().reset_index()
        high_disk_utilization_instances = grouped_data[(grouped_data['metric_type'] == 'disk') & (grouped_data['average_utilization'] > high_disk_threshold)]['instance_id'].unique()
        low_disk_utilization_instances = grouped_data[(grouped_data['metric_type'] == 'disk') & (grouped_data['average_utilization'] < low_disk_threshold)]['instance_id'].unique()
        return list({high_disk_utilization_instances,grouped_data['average_utilization']}), list({low_disk_utilization_instances,grouped_data['average_utilization']})

    def get(self, request):
        try:
            token = request.headers.get('Authorization').split(' ')[1]
            if not token:
                return Response({'error': 'Authorization token is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Extract query parameters
            time_range = request.query_params.get('time-range')
            account_id = request.query_params.get('account_id')

            if not time_range or not account_id:
                return Response({'error': 'time-range and units are required'}, status=400)

            params = {
                'time-range': time_range,
                'account_id': account_id,
            }

            ec2_data = self.load_data(params,token)

            # Define thresholds
            cpu_low_threshold = 5
            memory_low_threshold = 5
            high_utilization_threshold = 80
            low_utilization_threshold = 20
            high_disk_threshold = 75
            low_disk_threshold = 10

            # Analysis
            instances_to_terminate = self.identify_unused_instances(ec2_data, cpu_low_threshold, memory_low_threshold)
            upsizing_instances, downsizing_instances = self.rightsizing_instances(ec2_data, high_utilization_threshold, low_utilization_threshold)
            high_disk_instances, low_disk_instances = self.volume_recommendations(ec2_data, high_disk_threshold, low_disk_threshold)

            # Construct JSON response
            response = {
                "instances_to_terminate": instances_to_terminate,
                "instances_to_upsize": upsizing_instances,
                "instances_to_downsize": downsizing_instances,
                "instances_needing_more_disk_space": high_disk_instances,
                "instances_with_possible_excess_disk_space": low_disk_instances
            }

            return Response(response)
        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=500)

class ECRRecommendation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self):
        self.ecr_url = 'http://13.233.252.20:8000/api/ecr-detail-data/'

    def load_data(self, token, params):
        """
        Load the ECR (Elastic Container Registry) data from the provided URL with Authorization header and query parameters.
        """
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(self.ecr_url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to load data from URL: {self.ecr_url}. Status code: {response.status_code}")

    def make_repository_recommendations(self, ecr_data):
        """
        Make recommendations based on the last pull time.
        """
        recommendations = []
        current_date = datetime.now(timezone.utc)
        days_threshold = 30

        for repo in ecr_data:
            for image in repo.get('Images', []):
                last_pull_time_str = image.get('lastpulltime')
                if last_pull_time_str:
                    last_pull_time = datetime.strptime(last_pull_time_str, '%Y-%m-%dT%H:%M:%S.%f%z').astimezone(timezone.utc)
                    if (current_date - last_pull_time).days > days_threshold:
                        recommendations.append({
                            'Repository': repo['Repository'],
                            'Image_Tag': ', '.join(image['Tags']),
                            'Recommendation': 'Consider deleting the repository and adding a lifecycle policy'
                        })

        return recommendations

    def get(self, request):
        try:
            """
            Get recommendations based on the ECR data and return as JSON response.
            """
            token = request.headers.get('Authorization').split(' ')[1]
            if not token:
                return Response({'error': 'Authorization token is required'}, status=status.HTTP_400_BAD_REQUEST)

            time_range = request.query_params.get('time-range')
            account_id = request.query_params.get('account_id')

            if not time_range or not account_id:
                return Response({'error': 'time-range and account_id are required'}, status=status.HTTP_400_BAD_REQUEST)

            params = {
                'time-range': time_range,
                'account_id': account_id
            }

            ecr_data = self.load_data(token, params)
            repository_recommendations = self.make_repository_recommendations(ecr_data)

            # Convert the recommendations to a JSON response
            return Response(repository_recommendations)

        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ECSRecommendation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self):
        self.ecs_url = 'http://127.0.0.1:8000/api/ecs-data/'

    def load_data(self, token, params):
        """
        Load the ECS (Elastic Container Service) data from the provided URL with Authorization header and query parameters.
        """
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(self.ecs_url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to load data from URL: {self.ecs_url}. Status code: {response.status_code}")

    def recommend_downsizing(self, ecs_data):
        """
        Analyze CPU utilization and recommend downsizing if necessary.
        """
        recommendations = []

        for region_data in ecs_data:
            for cluster_data in region_data['Clusters']:
                for service_data in cluster_data.get('Services', []):
                    cpu_utilized = service_data['Metrics'][2].get('CpuUtilized', 'No data available')
                    if cpu_utilized != 'No data available' and float(cpu_utilized) < 50:
                        recommendations.append({
                            'Cluster': cluster_data['Cluster'],
                            'Service': service_data['Service'],
                            'Current CPU Utilization': cpu_utilized,
                            'Recommendation': 'Consider downsizing the instance'
                        })

        return recommendations

    def get(self, request):
        """
        Handle GET requests.
        """
        try:
            token = request.headers.get('Authorization').split(' ')[1]
            if not token:
                return Response({'error': 'Authorization token is required'}, status=status.HTTP_400_BAD_REQUEST)

            time_range = request.query_params.get('time-range')
            account_id = request.query_params.get('account_id')

            if not time_range or not account_id:
                return Response({'error': 'time-range, units, and account_id are required'}, status=status.HTTP_400_BAD_REQUEST)

            params = {
                'time-range': time_range,
                'account_id': account_id
            }

            ecs_data = self.load_data(token, params)

            # Generate recommendations based on the ECS data
            downsizing_recommendations = self.recommend_downsizing(ecs_data)

            # Return the recommendations as a JSON response
            return Response(downsizing_recommendations)

        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class S3Recommendation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self):
        self.s3_url = 'http://127.0.0.1:8000/api/s3-detail-data/'

    def load_data(self, token, params):
        """
        Load the S3 data from the provided URL with Authorization header.
        """
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(self.s3_url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            return data  # Assuming data is a list of dictionaries
        else:
            raise Exception(f"Failed to load data from URL: {self.s3_url}. Status code: {response.status_code}")

    def recommend_storage_class_change(self, bucket_data):
        """
        Determine if the storage class should be changed based on the last modified date.
        """
        recommendations = []

        # Define the threshold in days
        threshold_days = 90
        # Define the date threshold
        date_threshold = datetime.now() - timedelta(days=threshold_days)

        # Loop through each bucket in the data
        for bucket in bucket_data:
            # Parse the 'Last Modified Date'
            try:
                last_modified_date = datetime.strptime(bucket.get('Last Modified Date'), '%Y-%m-%d')
            except (ValueError, TypeError):
                # If there's an error parsing the date, we skip the recommendation for this bucket
                continue

            # Check if the last modified date is older than the threshold and the storage class is neither GLACIER nor STANDARD_IA
            if last_modified_date < date_threshold and bucket['Storage Class'] not in ['GLACIER', 'STANDARD_IA']:
                # Add a recommendation
                recommendations.append({
                    'Bucket': bucket['Bucket'],
                    'Current Storage Class': bucket['Storage Class'],
                    'Recommended Storage Class': 'GLACIER/STANDARD_IA',
                    'Last Modified Date': bucket['Last Modified Date']
                })

        return recommendations

    def get(self, request):
        try:
            # Extract the token from the Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return Response({'error': 'Authorization header is required'}, status=status.HTTP_400_BAD_REQUEST)
            token = auth_header.split(' ')[1]
            if not token:
                return Response({'error': 'Authorization token is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Extract account ID from query parameters
            account_id = request.query_params.get('account_id')
            if not account_id:
                return Response({'error': 'Account ID is required'}, status=status.HTTP_400_BAD_REQUEST)

            params = {
                'account_id': account_id,
            }
            s3_data = self.load_data(token, params)
            recommendations = self.recommend_storage_class_change(s3_data)
            return Response(recommendations)
        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class VPCRecommendation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
 
    def __init__(self):
        self.vpc_url = 'http://127.0.0.1:8000/api/vpc-data/'
 
    def load_data(self, token, params):
        """
        Load the VPC data from a URL with Authorization header and query parameters.
        """
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(self.vpc_url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to fetch data from URL: {self.vpc_url}. Status code: {response.status_code}")
 
    def check_subnets(self, Subnets):
        """
        Check if subnets are present in the VPC and return appropriate message.
        """
        if Subnets:
            return {'Subnets': Subnets}
        else:
            return {'No Subnets': 'No subnets present in the VPC'}
 
    def check_nat_gateways(self, nat_gateways):
        """
        Check if NAT Gateways are present and return appropriate message.
        """
        if nat_gateways:
            return {'NAT Gateways': nat_gateways}
        else:
            return {'No NAT Gateways': 'No NAT Gateways present in the VPC'}
 
    def check_nat_attachment(self, nat_gateways):
        """
        Check if NAT Gateways are attached to the VPC and return appropriate message.
        """
        nat_attachment_status = []
        for nat in nat_gateways:
            if nat.get('Attached', False):
                nat_attachment_status.append({'NAT Gateway ID': nat['ID'], 'Status': 'Attached'})
            else:
                nat_attachment_status.append({'NAT Gateway ID': nat['ID'], 'Status': 'Not Attached', 'Recommendation': 'Consider attaching the NAT Gateway if needed'})
       
        if not nat_attachment_status:
            return {'No NAT Gateways': 'No NAT Gateways present in the VPC'}
       
        return {'NAT Gateway Attachment Status': nat_attachment_status}
 
    def generate_vpc_cost_savings_report(self, token, params):
        """
        Generate cost-saving recommendations for VPC.
        """
        reports=[]
        try:
            vpc_data = self.load_data(token, params)
            for region in vpc_data:
                for data in vpc_data[region]:
                    subnet_status = self.check_subnets(data['Subnets'])
                    nat_gw_status = self.check_nat_gateways(data['NAT Gateways'])
                    nat_attachment_status = self.check_nat_attachment(data['NAT Gateways'])
                    report = {
                        'VPC ID':data['VPC ID'],
                        'Subnet Status': subnet_status,
                        'NAT Gateway Status': nat_gw_status,
                        'NAT Gateway Attachment Status': nat_attachment_status,
                    }
                reports.append(report)
            return reports
        except Exception as e:
            # Print the exception for debugging purposes
            print(f"An error occurred: {e}")
            raise  # Re-raise the exception
 
    def get(self, request):
        """
        Get VPC cost-savings report as JSON response.
        """
        try:
            # Extract the token from the Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return Response({'error': 'Authorization header is required'}, status=status.HTTP_400_BAD_REQUEST)
            token = auth_header.split(' ')[1]
            if not token:
                return Response({'error': 'Authorization token is required'}, status=status.HTTP_400_BAD_REQUEST)
 
            # Extract account ID from query parameters
            account_id = request.query_params.get('account_id')
            if not account_id:
                return Response({'error': 'Account ID is required'}, status=status.HTTP_400_BAD_REQUEST)
 
            params = {
                'account_id': account_id,
            }
            vpc_cost_savings_report = self.generate_vpc_cost_savings_report(token, params)
            return Response(vpc_cost_savings_report)
        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class EBSRecommendation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self):
        self.ebs_url = 'http://127.0.0.1:8000/api/ebs-data/'

    def fetch_ebs_data(self, token, params):
        """
        Fetch the EBS data from the provided API URL with Authorization header and query parameters.
        """
        headers = {'Authorization': f'Bearer {token}'}
        try:
            response = requests.get(self.ebs_url, headers=headers, params=params)
            response.raise_for_status()  # Raises an HTTPError if the HTTP request returned an unsuccessful status code.
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to fetch EBS data from API URL: {self.ebs_url}. Error: {e}")

    def analyze_ebs_data(self, ebs_json):
        """
        Analyze EBS data to generate recommendations.
        """
        recommendations = []

        for volume in ebs_json:
            volume_id = volume["VolumeId"]
            attached = volume['attached']
            

            # Check for volumes that may be underutilized based on null average read/write operations
            if not attached:
                recommendations.append({
                    'VolumeId': volume_id,
                    'Recommendation': 'This EBS is not attached to any of the EC2 Instance so try attaching it or Delete it'
                })
        if recommendations==[]:
            recommendations.append({'Recommendation':"No recommendation need all the EBS are attached to EC2 Instances"})
            # Additional checks could include analyzing IOPS and size to make recommendations on changing volume types

        return recommendations

    def generate_ebs_recommendations_report(self, token, params):
        """
        Generate EBS recommendations based on the fetched data.
        """
        try:
            ebs_data = self.fetch_ebs_data(token, params)
            recommendations = self.analyze_ebs_data(ebs_data)
            return recommendations
        except Exception as e:
            # Print the exception for debugging purposes
            print(f"An error occurred: {e}")
            raise  # Re-raise the exception

    def get(self, request):
        """
        Get EBS recommendations report as JSON response.
        """
        try:
            # Extract the token from the Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return Response({'error': 'Authorization header is required'}, status=status.HTTP_400_BAD_REQUEST)
            token = auth_header.split(' ')[1]
            if not token:
                return Response({'error': 'Authorization token is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Extract query parameters
            account_id = request.query_params.get('account_id')
            time_range = request.query_params.get('time-range')

            if not account_id:
                return Response({'error': 'Account ID is required'}, status=status.HTTP_400_BAD_REQUEST)
            if not time_range:
                return Response({'error': 'Time range is required'}, status=status.HTTP_400_BAD_REQUEST)
            
            params = {
                'account_id': account_id,
                'time-range': time_range,
            }

            ebs_recommendations_report = self.generate_ebs_recommendations_report(token, params)
            return Response(ebs_recommendations_report)
        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LambdaMetricsAnalyzer(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self):
        self.api_url = 'http://127.0.0.1:8000/api/lambda-metrics/'

    def fetch_lambda_metrics(self, token, params):
        """
        Fetch Lambda function metrics from the provided API URL with Authorization header and query parameters.
        """
        headers = {'Authorization': f'Bearer {token}'}
        try:
            response = requests.get(self.api_url, headers=headers, params=params)
            response.raise_for_status()  # Ensure successful response
            lambda_metrics = response.json()
            return lambda_metrics
        except requests.RequestException as e:
            print(f"Error fetching data from API: {e}")
            return []

    def analyze_lambda_metrics(self, lambda_metrics):
        """
        Analyze Lambda metrics and generate recommendations.
        """
        recommendations = []
        recommendation= []
        for function in lambda_metrics:
            recommendation= []
            func_name = function.get("Function", "Unknown")
            invocations = function.get("Invocations", [])
            avg_duration = function.get("AvgDuration", [])
            concurrent_executions = function.get("ConcurrentExecutions", [])

            # Assuming these are lists of numbers
            total_invocations = sum(invocations)
            average_duration = sum(avg_duration) / len(avg_duration) if avg_duration else 0
            max_concurrency = max(concurrent_executions) if concurrent_executions else 0
            recommendation.append({
                'total_invocations':total_invocations,
                'avg_duration':average_duration,
                'max_concurrency':max_concurrency
            }
            )
            if total_invocations == 0:
                recommendation.append({
                    'Function': func_name,
                    'Recommendation': 'Consider decommissioning due to lack of usage.'
                })
            
            if average_duration > 500:  # Threshold in milliseconds
                recommendation.append({
                    'Function': func_name,
                    'Recommendation': 'Review for performance optimization (high average duration).'
                })
            
            if max_concurrency >= 5:  # Example threshold
                recommendation.append({
                    'Function': func_name,
                    'Recommendation': 'Review concurrency settings (high concurrent executions).'
                })
            recommendations.append(recommendation)
            
        return recommendations

    def get(self, request):
        """
        Get Lambda recommendations report as JSON response.
        """
        try:
            token = request.headers.get('Authorization').split(' ')[1]  # Extract Bearer token
            if not token:
                return Response({'error': 'Authorization token is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Extract query parameters
            account_id = request.query_params.get('account_id')
            time_range = request.query_params.get('time-range')

            if not account_id:
                return Response({'error': 'Account ID is required'}, status=status.HTTP_400_BAD_REQUEST)

            if not time_ecrange:
                return Response({'error': 'Time range is required'}, status=status.HTTP_400_BAD_REQUEST)

            params = {
                'account_id': account_id,
                'time_range': time_range,
            }

            lambda_metrics = self.fetch_lambda_metrics(token, params)
            lambda_recommendations_report = self.analyze_lambda_metrics(lambda_metrics)
            return Response(lambda_recommendations_report)
        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                
class AwsServiceCost(APIView):
    # def get (self , request):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            # Get parameters from the request
            # units_str = request.GET.get("units")
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
            print(response)
            data = response['ResultsByTime']

            monthly_costs = {}

            for result in data:
                start_date = result['TimePeriod']['Start']
                month_key = start_date[:7]
                daily_cost = round(float(result['Total']['UnblendedCost']['Amount']), 5)

                if month_key not in monthly_costs:
                    monthly_costs[month_key] = Decimal(0)

                monthly_costs[month_key] += Decimal(daily_cost)

            total_ec2_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_ec2_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)
        # *********************** S3 data ***********************
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

            total_s3_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_s3_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)
            # ************************************* ECR cost data ****************************
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

            total_ecr_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_ecr_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)
            # ********************** Lambda cost data ****************************
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

            total_lambda_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_lambda_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)
            # *********************** ECS cost data ******************************
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

            total_ecs_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_ecs_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)
            # ******************************* WAF cost data *******************************
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

            total_waf_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_waf_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)
            # ******************* Secrets cost data *************************
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

            total_secrets_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_secrets_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)
            # **************************** RDS cost data **************************
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

            total_rds_cost = round(sum(monthly_costs.values()), 5)
            average_monthly_cost = round(total_rds_cost / len(monthly_costs), 5)

            # Round monthly costs to about 5 decimals
            for key, value in monthly_costs.items():
                monthly_costs[key] = round(value, 5)
            response_data = json.dumps([
               {"name":"EC2", "total_cost":total_ec2_cost},
               {"name":"S3", "total_cost":total_s3_cost},
               {"name":"ECR", "total_cost":total_ecr_cost},
               {"name":"Lambda", "total_cost":total_lambda_cost},
               {"name":"ECS", "total_cost":total_ecs_cost},
               {"name":"WAF", "total_cost":total_waf_cost},
               {"name":"Secrets", "total_cost":total_secrets_cost},
               {"name":"RDS", "total_cost":total_rds_cost},

            ], cls=DecimalEncoder)
            
            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500)

overall_unused_data = []
overall_unused_data_count=[]
ec2_compute_unit=[]
class AWS_Unused_Resource_and_EC2_Compute(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def setup(self,request, *args, **kwargs):
        super().setup(*args, **kwargs)
        print("er")
        account_id = request.GET.get('account_id')
        if not account_id:
            return JsonResponse({'error': 'Account ID is required'}, status=400)
        access_key, secret_key = get_decrypted_credentials(account_id)
        if not access_key or not secret_key:
            return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
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
            #self.get_unused_secrets(start_time)
            self.get_unused_waf_webacls(start_time)
            self.get_ec2_less_50(start_time)

            sum_overall_count = sum(overall_unused_data_count)
            json_response = json.dumps({"unused_data": overall_unused_data, "unused_data_count": sum_overall_count,"ec2_compute_unit":ec2_compute_unit},
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
            if function['last_activity_time'] and function['last_activity_time'] > (
                self.utc_now - timedelta(days=start_time)).replace(tzinfo=timezone.utc)
                
        ]
        test=(self.utc_now - timedelta(days=start_time)).replace(tzinfo=timezone.utc)
        print(test)

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
                            last_activity_time > (self.utc_now - timedelta(days=start_time)).replace(tzinfo=timezone.utc) and \
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
            instance['last_activity_time'] > (self.utc_now - timedelta(days=start_time)).replace(tzinfo=timezone.utc) and
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
                    if datetime.now() - last_activity_time > timedelta(days=start_time):
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
        regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']
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

                all_databases.append({
                    'db_instance_id': db_instance_id,
                    'db_instance_status': db_instance_status,
                    'last_activity_time': last_activity_time.strftime("%Y-%m-%d %H:%M:%S %Z") if last_activity_time else None
                })

        unused_databases = [db for db in all_databases
                            if db['db_instance_status'] == 'stopped' and db['last_activity_time'] and
                            db['last_activity_time'] > (datetime.utcnow() - timedelta(days=start_time)).replace(tzinfo=timezone.utc)]

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
    def get_unused_s3_buckets(self,start_time):
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
    def get_last_activity_time(self, instance_state, launch_time):
        if instance_state == 'running':
            return datetime.utcnow()
        elif instance_state == 'stopped':
            return launch_time
        else:
            return None

    def get_ec2_less_50(self,request, start_time):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
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
                        # time_range=request.GET.get('time-range')
                        #                 # Calculate start time based on the time range provided by the user
                        # if time_range == "1 Week":
                        #     start_time = end_time - timedelta(weeks=1)
                        # elif time_range == "15 Days":
                        #     start_time = end_time - timedelta(days=15)
                        
                        # elif time_range == "1 Month":
                        #     start_time = end_time - timedelta(weeks=4 * 1)
                        
                        # elif time_range == "3 Months":
                        #     start_time = end_time - timedelta(weeks=4 * 3)
                        # elif time_range == "6 Months":
                        #     start_time = end_time - timedelta(weeks=4 * 6)

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

            ec2_compute_unit_less_50=({'utilization_info': all_utilization_info,
                                 'ec2_compute_count_less_than_50%':count})
            ec2_compute_unit.append(ec2_compute_unit_less_50)
            
        except Exception as e:
            # Handle exceptions appropriately
            return JsonResponse({'error': str(e)}, status=500)
        
class EKS_Data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'  # Specify your desired region
            )
            eks_client = session.client('eks')

            # Get the list of clusters
            clusters_response = eks_client.list_clusters()
            cluster_names = clusters_response.get('clusters', [])

            cluster_details = []
            for cluster_name in cluster_names:
                # Describe each cluster to get detailed information
                response = eks_client.describe_cluster(name=cluster_name)
                cluster_info = response.get('cluster', {})
                cluster_details.append(cluster_info)

            response_json = json.dumps(cluster_details, indent=4)
            return JsonResponse(cluster_details, safe=False)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)


class Document_DB_Details(APIView):
    authentication_classes = []
    permission_classes = [IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            client = session.client('docdb')
            db_instance_response = client.describe_db_instances()

            return JsonResponse(db_instance_response, safe=False)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

class SNS_Details(APIView):
    authentication_classes = []
    permission_classes = [IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            client = session.client('sns')
            sns_details = client.list_topics()
            return JsonResponse(sns_details, safe=False, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)
        
class Services_Cost_Data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    services={
        'ec2':['Amazon Elastic Compute Cloud - Compute'],
        'vpc':['Amazon Virtual Private Cloud'],
        's3':['Amazon Simple Storage Service'],
        'lbr':['Amazon Elastic Load Balancing','Amazon Elastic Load Balancer','Application Load Balancer','Network Load Balancer','Gateway Load Balancer'],
        'ebs':['Amazon Elastic Block Store'],
        'eip':['Elastic IP'],
        'ss':['EC2: EBS - Snapshots'],
        'docdb':['DocumentDB'],
        'sns':['Amazon Simple Notification Service'],
        'ses': ['Amazon Simple Email Service'],
        'ecr':['Amazon Elastic Container Registry'],
        'lambda':['AWS Lambda'],
        'ecs':['Amazon Elastic Container Service'],
        'waf':['AWS WAF'],
        'secrets':['AWS Secrets Manager'],
        'rds':['Amazon Relational Database Service'],
        'api':['AmazonApiGateway'],
    }

    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            service=request.GET.get('service')
            if service not in self.services:
                return JsonResponse({'error': 'service not available'}, status=400)
            
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

            
            filter= {
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': self.services[service]
                }
            }
        
            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_time.strftime('%Y-%m-%d'),
                    'End': end_time.strftime('%Y-%m-%d'),
                },
                Granularity='DAILY',
                Filter=filter,
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
                'short_service':service,
                'service': self.services[service],
                'total_cost': total_cost,
                'average_monthly_cost': average_monthly_cost,
                'monthly_breakdown': monthly_costs,
            }, cls=DecimalEncoder)

            response = HttpResponse(response_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"},content_type='application/json', status=500) 

def get_location_name(region_code):
    ec2 = boto3.client("ec2", region_name=region_code)
    ec2_responses = ec2.describe_regions()
    ssm_client = boto3.client('ssm', region_name=region_code)
    for resp in ec2_responses['Regions']:
        region_id = resp['RegionName']
        tmp = '/aws/service/global-infrastructure/regions/%s/longName' % region_code
        ssm_response = ssm_client.get_parameter(Name = tmp)
        region_name = ssm_response['Parameter']['Value'] 
        print ("region_id:",region_id,"region_name:",region_name)
    return region_name

def get_ec2_pricing(instance_type, region, os):
    pricing_client = boto3.client('pricing')  # Use 'us-east-1' for pricing API

    location = get_location_name(region)

    if not location:
        return "Invalid region"
    
    response = pricing_client.get_products(
        ServiceCode='AmazonEC2',
        Filters=[
            {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
            {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': location},
            {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': str(os)},
            {'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'Compute Instance'},
            {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'shared'},  # Example tenancy filter
            {'Type': 'TERM_MATCH', 'Field': 'licenseModel', 'Value': 'No License required'},
        ],
        MaxResults=1
    )

    for price_item in response['PriceList']:
        price_item = json.loads(price_item)
        terms = price_item['terms'].get('OnDemand', {})
        if terms:
            price_dimensions = list(terms.values())[0]['priceDimensions']
            price_per_hour = list(price_dimensions.values())[0]['pricePerUnit']['USD']
            return price_per_hour
    return None

def calculate_instance_cost(time_range, price_per_hour):
    try:
        duration = time_range
        duration_hours = duration*24
        total_cost= int(duration_hours) * float(price_per_hour)
        return total_cost
    except Exception as e:
        print(f"Error in calculate_instance_cost: {e}")
        return 0  # Return 0 in case of any error
        
class EC2_Instance_Cost(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self,request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )

            ec2_client = session.client('ec2',region_name='ap-south-1')
            instances = ec2_client.describe_instances()['Reservations']
            ec2_description = []
            time_range=request.GET.get('time-range')
            if time_range == "1 Week":
                duration = timedelta(weeks=1)
            elif time_range == "15 Days":
                duration = timedelta(days=15)
            
            elif time_range == "1 Month":
                duration = timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                duration = timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                duration = timedelta(weeks=4 * 6)

            # return Response(instances)
            for info in instances:
                for detail in info['Instances']:
                    instance_detail = {}
                    instance_detail['InstanceId'] = detail['InstanceId']
                    instance_detail['InstanceType'] = detail['InstanceType']
                    instance_detail['AvailabilityZone'] = detail['Placement']['AvailabilityZone'][:-1]
                    instance_detail['PrivateIpAddress'] = detail['PrivateIpAddress']
                    instance_detail['SubnetId'] = detail['SubnetId']
                    instance_detail['VpcId'] = detail['VpcId']
                    instance_detail['Ebs-VolumeId'] = [{ebs['Ebs']['VolumeId']:ebs['Ebs']['Status']} for ebs in detail['BlockDeviceMappings']]
                    instance_detail['PlatformDetails'] = detail['PlatformDetails'].split("/")[0]
                    instance_detail['CpuOptions'] = detail['CpuOptions']
                    price_per_hour = get_ec2_pricing(detail['InstanceType'], detail['Placement']['AvailabilityZone'][:-1],detail['PlatformDetails'].split("/")[0])
                    instance_detail['duration']=duration
                    instance_cost = calculate_instance_cost(duration.days, price_per_hour)
                    instance_detail['costperhour']=price_per_hour
                    instance_detail['InstanceCost'] = instance_cost
                    ec2_description.append(instance_detail)
            return Response(ec2_description)
            
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)

class EC2_REGION_WISE_COST_DATA(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name="ap-south-1",
            )
            ec2_client = session.client('ec2')
 
            regions_response = ec2_client.describe_regions()
            regions = [region['RegionName'] for region in regions_response['Regions']]
            region_instance_map = {}
            time_range=request.GET.get('time-range')
            if time_range == "1 Week":
                duration = timedelta(weeks=1)
            elif time_range == "15 Days":
                duration = timedelta(days=15)
            
            elif time_range == "1 Month":
                duration = timedelta(weeks=4 * 1)
            
            elif time_range == "3 Months":
                duration = timedelta(weeks=4 * 3)
            elif time_range == "6 Months":
                duration = timedelta(weeks=4 * 6)
 
            for region in regions:
                ec2_client = session.client('ec2', region_name=region)
                instances_response = ec2_client.describe_instances()
                instances = []
                for reservation in instances_response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        instance_type = instance['InstanceType']
                        print(instance)
                        os = instance['PlatformDetails'].split("/")[0]
                        cost_data = get_ec2_pricing(instance_type,region, os)
                        total_cost=calculate_instance_cost(duration.days,cost_data)
                        instances.append({
                            'InstanceId': instance_id,
                            'InstanceType': instance_type,
                            'os':os,
                            'TotalCost': total_cost,
                            'CostPerHour': cost_data
                        })
                region_instance_map[region] = instances
 
            return Response(region_instance_map)
 
        except Exception as e:
            return Response({"error": f"An error occurred: {e}"}, status=500)
        
class GetTotalPercentageIncrease(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            client = session.client('ce', region_name='us-east-1')

            # Define the time periods
            end_date = datetime.utcnow().replace(day=1)
            start_date = (end_date - timedelta(days=1)).replace(day=1)
            prev_start_date = (start_date - timedelta(days=1)).replace(day=1)
            prev_end_date = start_date - timedelta(days=1)

            # Fetch current month cost
            current_month_data = client.get_cost_and_usage(
                TimePeriod={'Start': start_date.strftime('%Y-%m-%d'), 'End': end_date.strftime('%Y-%m-%d')},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost']
            )

            # Fetch previous month cost
            prev_month_data = client.get_cost_and_usage(
                TimePeriod={'Start': prev_start_date.strftime('%Y-%m-%d'), 'End': prev_end_date.strftime('%Y-%m-%d')},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost']
            )

            current_cost = float(current_month_data['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'])
            prev_cost = float(prev_month_data['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'])

            # Calculate percentage increase
            if prev_cost == 0:
                percentage_increase = 100.0
            else:
                percentage_increase = ((current_cost - prev_cost) / prev_cost) * 100

            data = {
                'current_cost': current_cost,
                'previous_cost': prev_cost,
                'percentage_increase': percentage_increase,
            }
            return JsonResponse(data)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500) 
        
class GetPercentageIncrease(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            client = session.client('ce', region_name='us-east-1')

            # Define the time periods
            end_date = datetime.utcnow().replace(day=1)
            start_date = (end_date - timedelta(days=1)).replace(day=1)
            prev_start_date = (start_date - timedelta(days=1)).replace(day=1)
            prev_end_date = start_date - timedelta(days=1)

            # Function to fetch cost data
            def fetch_cost_data(client, start_date, end_date):
                return client.get_cost_and_usage(
                    TimePeriod={'Start': start_date.strftime('%Y-%m-%d'), 'End': end_date.strftime('%Y-%m-%d')},
                    Granularity='MONTHLY',
                    Metrics=['UnblendedCost'],
                    GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
                )

            # Fetch cost data for current and previous month
            current_month_data = fetch_cost_data(client, start_date, end_date)
            prev_month_data = fetch_cost_data(client, prev_start_date, prev_end_date)

            # Function to extract cost for a specific service
            def extract_cost(data, service_name):
                for group in data['ResultsByTime'][0]['Groups']:
                    if service_name in group['Keys']:
                        return float(group['Metrics']['UnblendedCost']['Amount'])
                return 0.0

            # List of services to calculate percentage increase for
            services = ['Amazon Elastic Compute Cloud - Compute', 'AWS Lambda', 'Amazon Simple Storage Service', 'AWS WAF']

            cost_data = {}

            for service in services:
                current_cost = extract_cost(current_month_data, service)
                prev_cost = extract_cost(prev_month_data, service)

                if prev_cost == 0:
                    percentage_increase = 100.0 if current_cost != 0 else 0.0
                else:
                    percentage_increase = ((current_cost - prev_cost) / prev_cost) * 100

                cost_data[service] = {
                    'current_cost': current_cost,
                    'previous_cost': prev_cost,
                    'percentage_increase': percentage_increase,
                }
            return JsonResponse(cost_data)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

        
class Services3_Cost_Data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    services = {
        'ec2': ['Amazon Elastic Compute Cloud - Compute'],
        's3': ['Amazon Simple Storage Service'],
        'lambda': ['AWS Lambda']
    }

    def get(self, request, *args, **kwargs):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            time_range = request.GET.get('time-range')
            fy_start_year = datetime.utcnow().year
            fy_end_year = fy_start_year + 1

            if time_range == "Q1":
                start_time = datetime(fy_start_year, 4, 1)
                end_time = datetime(fy_start_year, 7, 31)
            elif time_range == "Q2":
                start_time = datetime(fy_start_year, 8, 1)
                end_time = datetime(fy_start_year, 11, 30)
            elif time_range == "Q3":
                start_time = datetime(fy_start_year, 12, 1)
                end_time = datetime(fy_end_year, 3, 31)
            else:
                return JsonResponse({'error': 'Invalid time range specified'}, status=400)

            # Configure the AWS client with the stored credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            ce_client = session.client('ce')

            response_data = {}

            for service, dimensions in self.services.items():
                filter = {
                    'Dimensions': {
                        'Key': 'SERVICE',
                        'Values': dimensions
                    }
                }

                response = ce_client.get_cost_and_usage(
                    TimePeriod={
                        'Start': start_time.strftime('%Y-%m-%d'),
                        'End': end_time.strftime('%Y-%m-%d'),
                    },
                    Granularity='MONTHLY',
                    Filter=filter,
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

                response_data[service] = {
                    'short_service': service,
                    'service': dimensions,
                    'total_cost': total_cost,
                    'average_monthly_cost': average_monthly_cost,
                    'monthly_breakdown': monthly_costs,
                }

            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class EC2InstancesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            client = session.client('ec2')
            regions = client.describe_regions()['Regions']
            ec2_instances = {}

            for region in regions:
                region_name = region['RegionName']
                ec2_client = session.client('ec2', region_name=region_name)
                instances = ec2_client.describe_instances()
                if instances['Reservations']:
                    instance_details = []
                    for reservation in instances['Reservations']:
                        for instance in reservation['Instances']:
                            instance_details.append({
                                'InstanceId': instance['InstanceId'],
                                'InstanceType': instance['InstanceType'],
                                'State': instance['State']['Name'],
                            })
                    ec2_instances[region_name] = instance_details

            return JsonResponse(ec2_instances, safe=False)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

class S3BucketsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            client = session.client('ec2')
            regions = client.describe_regions()['Regions']
            s3_buckets = {}

            for region in regions:
                region_name = region['RegionName']
                s3_client = session.client('s3', region_name=region_name)
                buckets = s3_client.list_buckets()
                if buckets['Buckets']:
                    bucket_details = []
                    for bucket in buckets['Buckets']:
                        bucket_details.append({
                            'BucketName': bucket['Name'],
                            'CreationDate': bucket['CreationDate'].isoformat()
                        })
                    s3_buckets[region_name] = bucket_details

            return JsonResponse(s3_buckets, safe=False)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        
class ElasticIPsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID is required'}, status=400)
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'AWS credentials are not configured'}, status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            client = session.client('ec2')
            regions = client.describe_regions()['Regions']
            elastic_ips = {}

            for region in regions:
                region_name = region['RegionName']
                ec2_client = session.client('ec2', region_name=region_name)
                addresses = ec2_client.describe_addresses()

                if addresses['Addresses']:
                    eip_details = []
                    for address in addresses['Addresses']:
                        eip_details.append({
                            'PublicIp': address.get('PublicIp'),
                            'AllocationId': address.get('AllocationId'),
                            'AssociationId': address.get('AssociationId'),
                            'Domain': address.get('Domain'),
                        })
                    elastic_ips[region_name] = eip_details

            return JsonResponse(elastic_ips, safe=False)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

class RDS_Recommendation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self,request):
        try:
            account_id= request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error: account id required'},status=400)
            
            access_key,secret_key=get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error: access_key or secret_key is required'},status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            cloudwatch_namespace = 'AWS/RDS'
            cpu_metric_name = 'CPUUtilization'
            freeable_memory_metric_name = 'FreeableMemory'
            ec2 = session.client('ec2')
            ec2_regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
            instance_memory_info = {}
            with open('rds_instance_types.csv', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    instance_type = row['Instance type']
                    vcpu = row['vCPU']
                    memory = row['Memory']  # Memory in GB
                    instance_memory_info[instance_type] = {
                        'instance_type':instance_type,
                        'cpu_count': vcpu,
                        'memory': float(memory) if memory else 0.0,  # Convert memory to float
                    }

            terminate_list=[]
            downsize_list=[]    
            for region_name in ec2_regions:
                rds_client_region = session.client('rds', region_name=region_name)
                cloudwatch_client = session.client('cloudwatch', region_name=region_name)
                instances = rds_client_region.describe_db_instances()['DBInstances']
                for instance in instances:
                    print(instance['DBInstanceIdentifier'])
                    db_identifier = instance['DBInstanceIdentifier']
                    engine = instance['Engine']
                    db_instance_class = instance['DBInstanceClass']
                    status = instance['DBInstanceStatus']
                    instance_type = instance['DBInstanceClass']
                    db_connections_read_write = instance.get('ReadReplicaSourceDBInstanceIdentifier', 'N/A')
                    storage = instance.get('AllocatedStorage', 'N/A')
                    allocated_storage = instance['AllocatedStorage']
                    start_time = datetime.now(timezone.utc) - timedelta(days=1)
                    end_time = datetime.now(timezone.utc)
                    time_range = request.GET.get('time_range')
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
                    # Check if instance_type exists in instance_memory_info
                    if instance_type in instance_memory_info:
                        actual_memory = instance_memory_info[instance_type]['memory']
                        freeable_memory_gb = freeable_memory / (1024 ** 3) if freeable_memory != 'N/A' else 0
                        free_memory = round(freeable_memory_gb, 2)
                        used_memory = actual_memory - freeable_memory_gb
                        utilized_memory_in_percentage = (used_memory / actual_memory) * 100 if actual_memory > 0 else None
                    else:
                        actual_memory = None
                        used_memory = None
                        free_memory=None
                        utilized_memory_in_percentage = None
                    actual_cpu = instance_memory_info[instance_type]['cpu_count']
                    # Include last activity time for stopped instances
                    last_active_time = instance.get('LatestRestorableTime') if status == 'stopped' else None
                    half_ram=0
                    half_cpu=0
                    # Check if utilized memory is less than 50%
                    if status == 'stopped':
                        if last_active_time:
                            time_difference = datetime.utcnow() - last_active_time
                            if int(time_difference.days) > 30:
                                suggestion = 'This instance has been stopped for over 30 days. Consider terminating it.'
                    else:
                        if cpu_utilization == 50 and utilized_memory_in_percentage == 50:
                            half_ram = float(actual_memory) / 3 if actual_memory != 'N/A' else 'N/A'
                            half_cpu = float(actual_cpu) / 3 if actual_cpu != 'N/A' else 'N/A'
                            suggestion = "This Instance utilizing 50% of RAM and CPU, so consider changing the RAM and CPU to lower by 30%"
                        elif cpu_utilization == 50 :
                            half_cpu = float(actual_cpu) / 3 if actual_cpu != 'N/A' else 'N/A'
                            suggestion = "This Instance utilizing 50% of CPU, so consider changing the CPU to lower to 30%"
                        elif utilized_memory_in_percentage == 50:
                            half_ram = float(actual_memory) / 3 if actual_memory != 'N/A' else 'N/A'
                            suggestion = "This Instance utilizing 50% of RAM, so consider changing the RAM to lower to 30%"
                        elif cpu_utilization < 50 and utilized_memory_in_percentage < 50:
                            half_ram = float(actual_memory) / 2 if actual_memory != 'N/A' else 'N/A'
                            half_cpu = float(actual_cpu) / 2 if actual_cpu != 'N/A' else 'N/A'
                            suggestion = "This Instance utilizing less than 50% of RAM and CPU, so consider changing the RAM and CPU to lower"
                        elif cpu_utilization < 50 :
                            half_cpu = float(actual_cpu) / 2 if actual_cpu != 'N/A' else 'N/A'
                            suggestion = "This Instance utilizing less than 50% of CPU, so consider changing the CPU to lower"
                        elif utilized_memory_in_percentage < 50:
                            half_ram = float(actual_memory) / 2 if actual_memory != 'N/A' else 'N/A'
                            suggestion = "This Instance utilizing less than 50% of RAM, so consider changing the RAM to lower"
                        else:
                            suggestion = "No Change needed"
                    
                    if status != 'stopped' and half_ram != 'N/A' and half_cpu != 'N/A':
                        matching_data = [data for data in instance_memory_info.values()
                            if (data['memory'] == int(half_ram) or data['cpu_count'] == int(half_cpu))
                        ]
                    else:
                        matching_data = []
                        

                            # Create a dictionary for the current instance
                    instance_details = {
                        'DBInstanceIdentifier': db_identifier,
                        'Engine': engine,
                        'Status': status,
                        'DBInstanceClass': db_instance_class,
                        'Memory (GB)': actual_memory,
                        'CPUUtilization (%)': round(cpu_utilization, 2),
                        'utilized_memory_in_percentage': utilized_memory_in_percentage,
                        'UsedMemoryGB': used_memory,
                        'FreeMemory': free_memory,
                        'AllocatedStorage': allocated_storage,
                        'ConnectionsRW': db_connections_read_write,
                        'Suggestion': suggestion,
                        'matching_data':matching_data
                    }
                    if suggestion.startswith('This instance has been stopped'):
                        terminate_list.append(instance_details)
                    elif suggestion.startswith('This Instance utilizing less'):
                        downsize_list.append(instance_details)

                    response_data = {
                        'terminate': terminate_list,
                        'downsize': downsize_list
                    }

            # Check if any data was collected
            if not response_data:
                return JsonResponse({"error": "No RDS instance data found."}, status=404)

            # Return the response
            return JsonResponse(response_data, safe=False, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)

def get_last_activity_time(self,launch_time,instance_state):
        if instance_state=='running':
            return datetime.now(timezone.utc)
        elif instance_state == 'stopped':
            return launch_time
        else:
            return None
        
class EC2RecommendationNew(APIView):

    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
        
    def get(self,request):
        try:
            account_id= request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error: account id required'},status=400)
            
            access_key,secret_key=get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error: access_key or secret_key is required'},status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            ec2 = session.client('ec2')
            ec2_regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
            instance_data = []
            for region_name in ec2_regions:
                cloudwatch_client = session.client('cloudwatch', region_name=region_name)
                instances = ec2.describe_instances()
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        instance_type = instance['InstanceType']
                        instance_state = instance['State']['Name']
                        launch_time = instance['LaunchTime']
                        last_activity_time = get_last_activity_time(launch_time,instance_state)

                        start_time = datetime.now(timezone.utc) - timedelta(days=1)
                        end_time = datetime.now(timezone.utc)
                        time_range = request.GET.get('time_range')
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
                        
                        memory_response = cloudwatch_client.get_metric_data(
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
                        # Calculate average utilizations
                        def calculate_average(data):
                            values = data.get('Values', [])
                            return round(sum(values) / len(values), 2) if values else 0

                        avg_cpu_utilization = calculate_average(cpu_response['MetricDataResults'][0]) if cpu_response['MetricDataResults'] else 0
                        avg_memory_utilization = calculate_average(memory_response['MetricDataResults'][0]) if memory_response['MetricDataResults'] else 0

                        instance_data.append({
                            'region': region_name,
                            'instance_id': instance_id,
                            'instance_type': instance_type,
                            'state': instance_state,
                            'cpu_average_utilization': avg_cpu_utilization,
                            'memory_average_utilization': avg_memory_utilization,
                            'last_activity_time': last_activity_time.isoformat() if last_activity_time else None,
                            'suggestion': 'N/A'
                        })

            # Load instance prices
            instance_prices = {}
            with open('ec2_instance_prices.csv', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                instance_prices = {
                    row['Instance Type']: {
                        'Instance Type': row['Instance Type'],
                        'Market': row['Market'],
                        'vCPU': row['vCPU'],
                        'RAM (GiB)': row['RAM (GiB)'],
                    }
                    for row in reader
                }
            response_data={}
            terminate_list = []
            downsize_list = []
            half_ram=0
            half_cpu=0
            for instance in instance_data:
                instance_type = instance['instance_type']
                instance_detail_data = instance_prices.get(instance_type, {
                    'Instance Type': 'N/A',
                    'Market': 'N/A',
                    'vCPU': 'N/A',
                    'RAM (GiB)': 'N/A',
                })
                first_letter = instance['instance_type'][0]
                # Determine suggestion
                if instance["state"] == 'stopped':
                    if instance['last_activity_time']:
                        last_activity_time = datetime.fromisoformat(instance['last_activity_time'])
                        time_difference = datetime.now(timezone.utc) - last_activity_time
                        if int(time_difference.days) > 30:
                            suggestion = 'This instance has been stopped for over 30 days. Consider terminating it.'
                else:
                    if instance['cpu_average_utilization'] == 50 and instance['memory_average_utilization'] == 50:
                        half_ram = float(instance_detail_data['RAM (GiB)']) / 3 if instance_detail_data['RAM (GiB)'] != 'N/A' else 'N/A'
                        half_cpu = float(instance_detail_data['vCPU']) / 3 if instance_detail_data['vCPU'] != 'N/A' else 'N/A'
                        suggestion = "This Instance utilizing 50% of RAM and CPU, so consider changing the RAM and CPU to lower by 30%"
                    elif instance['cpu_average_utilization'] == 50 :
                        half_cpu = float(instance_detail_data['vCPU']) / 3 if instance_detail_data['vCPU'] != 'N/A' else 'N/A'
                        suggestion = "This Instance utilizing 50% of CPU, so consider changing the CPU to lower to 30%"
                    elif instance['memory_average_utilization'] == 50:
                        half_ram = float(instance_detail_data['RAM (GiB)']) / 3 if instance_detail_data['RAM (GiB)'] != 'N/A' else 'N/A'
                        suggestion = "This Instance utilizing 50% of RAM, so consider changing the RAM to lower to 30%"
                    elif instance['cpu_average_utilization'] < 50 and instance['memory_average_utilization'] < 50:
                        half_ram = float(instance_detail_data['RAM (GiB)']) / 2 if instance_detail_data['RAM (GiB)'] != 'N/A' else 'N/A'
                        half_cpu = float(instance_detail_data['vCPU']) / 2 if instance_detail_data['vCPU'] != 'N/A' else 'N/A'
                        suggestion = "This Instance utilizing less than 50% of RAM and CPU, so consider changing the RAM and CPU to lower"
                    elif instance['cpu_average_utilization'] < 50 :
                        half_cpu = float(instance_detail_data['vCPU']) / 2 if instance_detail_data['vCPU'] != 'N/A' else 'N/A'
                        suggestion = "This Instance utilizing less than 50% of CPU, so consider changing the CPU to lower"
                    elif instance['memory_average_utilization'] < 50:
                        half_ram = float(instance_detail_data['RAM (GiB)']) / 2 if instance_detail_data['RAM (GiB)'] != 'N/A' else 'N/A'
                        suggestion = "This Instance utilizing less than 50% of RAM, so consider changing the RAM to lower"
                    else:
                        suggestion = "No Change needed"

                instance['suggestion'] = suggestion

                if instance["state"] != 'stopped' and half_ram != 'N/A' and half_cpu != 'N/A':
                    matching_data = [data for data in instance_prices.values()
                        if (data['RAM (GiB)'] == str(half_ram) or data['vCPU'] == str(half_cpu)) and data['Instance Type'][0] == first_letter
                    ]
                else:
                    matching_data = []

                # Build response based on suggestion and matching data
                ec2_json_response = {
                    'instanceData': instance,
                    'Matching Instance Data': matching_data if matching_data else 'No matching data found'
                }

                if suggestion.startswith('This instance has been stopped'):
                    terminate_list.append(ec2_json_response)
                elif suggestion.startswith('This Instance utilizing less'):
                    downsize_list.append(ec2_json_response)

                response_data = {
                    'terminate': terminate_list,
                    'downsize': downsize_list
                }
            return JsonResponse(response_data, json_dumps_params={'indent': 4})

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
def calculate_average(data):
    values = data.get('Values', [])
    return round(sum(values) / len(values), 2) if values else 0

class EC2_UnUsedRecources(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_last_activity_time(self,launch_time,instance_state):
        if instance_state=='running':
            return datetime.now(timezone.utc)
        elif instance_state == 'stopped':
            return launch_time
        else:
            return None
        
    def fetch_ebs_price(self, session, region_name, volume_type):
        pricing_client = session.client('pricing', region_name='us-east-1')  # Pricing is only available in us-east-1
        
        price_filters = [
            {'Type': 'TERM_MATCH', 'Field': 'volumeType', 'Value': volume_type},
            {'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'Storage'},
            {'Type': 'TERM_MATCH', 'Field': 'regionCode', 'Value': region_name},
        ]

        try:
            price_list = pricing_client.get_products(ServiceCode='AmazonEC2', Filters=price_filters)
            
            price_per_gb = None
            for price_item in price_list['PriceList']:
                price_details = json.loads(price_item)  # PriceList is already in JSON format
                terms = price_details.get('terms', {}).get('OnDemand', {})
                for term in terms.values():
                    for dimension in term.get('priceDimensions', {}).values():
                        price_per_gb = float(dimension.get('pricePerUnit', {}).get('USD', 0))
                        break
                if price_per_gb:
                    break
            
            return price_per_gb if price_per_gb else 0.0  # Return 0.0 if no pricing found
        except Exception as e:
            return 0.0  # Handle any pricing API errors gracefully

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'account id required'}, status=400)
            
            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'access_key or secret_key is required'}, status=400)
            
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )
            ec2 = session.client('ec2')
            ec2_regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
            instance_data = []

            for region_name in ec2_regions:
                cloudwatch_client = session.client('cloudwatch', region_name=region_name)
                instances = ec2.describe_instances()
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        instance_type = instance['InstanceType']
                        instance_state = instance['State']['Name']
                        launch_time = instance['LaunchTime']
                        last_activity_time = self.get_last_activity_time(launch_time, instance_state)

                        start_time = datetime.now(timezone.utc) - timedelta(days=1)
                        end_time = datetime.now(timezone.utc)
                        time_range = request.GET.get('time_range')

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
                        
                        # Fetch Memory Utilization
                        memory_response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[{
                                'Id': 'mem_utilization',
                                'MetricStat': {
                                    'Metric': {
                                        'Namespace': 'CWAgent',
                                        'MetricName': 'mem_used_percent',
                                        'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                                    },
                                    'Period': 3600,
                                    'Stat': 'Average',
                                },
                                'ReturnData': True,
                            }],
                            StartTime=start_time,
                            EndTime=end_time,
                        )

                        # Fetch CPU Utilization
                        cpu_response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[{
                                'Id': 'cpu_utilization',
                                'MetricStat': {
                                    'Metric': {
                                        'Namespace': 'AWS/EC2',
                                        'MetricName': 'CPUUtilization',
                                        'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                                    },
                                    'Period': 3600,
                                    'Stat': 'Average',
                                },
                                'ReturnData': True,
                            }],
                            StartTime=start_time,
                            EndTime=end_time,
                        )

                        avg_cpu_utilization = calculate_average(cpu_response['MetricDataResults'][0]) if cpu_response['MetricDataResults'] else 0
                        avg_memory_utilization = calculate_average(memory_response['MetricDataResults'][0]) if memory_response['MetricDataResults'] else 0
                        
                        if instance_state == 'stopped':
                            # Check if attached to EBS volumes
                            volumes = instance['BlockDeviceMappings']
                            ebs_cost = 0
                            if volumes:
                                for volume in volumes:
                                    volume_id = volume['Ebs']['VolumeId']
                                    volume_info = ec2.describe_volumes(VolumeIds=[volume_id])
                                    volume_size = volume_info['Volumes'][0]['Size']  # size in GB
                                    volume_type = volume_info['Volumes'][0]['VolumeType']

                                    # Fetch pricing based on volume type and region
                                    price_per_gb = self.fetch_ebs_price(session, region_name, volume_type)

                                    # Calculate the cost of this volume
                                    ebs_cost += volume_size * price_per_gb
                            # Add EBS cost and instance info to response data
                            instance_data.append({
                                'instance_id': instance_id,
                                'instance_type': instance_type,
                                'state': instance_state,
                                'cpu_utilization': avg_cpu_utilization,
                                'memory_utilization': avg_memory_utilization,
                                'ebs_cost': ebs_cost,
                                'last_activity_time': last_activity_time,
                            })

            return JsonResponse(instance_data, safe=False)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)

# Define your services
SERVICE_CATEGORIES = {
    'compute': [
        'ec2',   # Amazon Elastic Compute Cloud
        'lambda',  # AWS Lambda
        'ecs',   # Amazon Elastic Container Service
        'ecr'    # Amazon Elastic Container Registry
    ],
    'storage': [
        'rds',   # Amazon Relational Database Service
        's3',    # Amazon Simple Storage Service
        'ebs',   # Amazon Elastic Block Store
       # 'ss',    # EC2: EBS Snapshots
        'docdb'  # Amazon DocumentDB
    ],
    'networking': [
        'vpc',   # Amazon Virtual Private Cloud
        'elbv2',   # Elastic Load Balancing
        'eip'    # Elastic IP
    ],
    'other': [
        #'sns',   # Amazon Simple Notification Service
        #'ses',   # Amazon Simple Email Service
        #'waf',   # AWS WAF
        'secretsmanager', # AWS Secrets Manager
        'apigateway' # Amazon API Gateway
    ]
}

class Service_Categorization(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID required'}, status=400)

            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'Access key or secret key is required'}, status=400)

            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='ap-south-1'
            )

            # Initialize service counts and details
            service_counts = {service: 0 for category in SERVICE_CATEGORIES.values() for service in category}
            service_details = {service: [] for category in SERVICE_CATEGORIES.values() for service in category}

            # Fetch resources for each service
            for category, services in SERVICE_CATEGORIES.items():
                for service in services:

                    # Handle each service category
                    if service == 'ec2':
                        # Fetch EC2 instances
                        client = session.client(service)
                        ec2_response = client.describe_instances()
                        for reservation in ec2_response['Reservations']:
                            for instance in reservation['Instances']:
                                instance_id = instance['InstanceId']
                                service_counts['ec2'] += 1
                                service_details['ec2'].append({
                                    'resource_arn': f'arn:aws:ec2:ap-south-1:{account_id}:instance/{instance_id}',
                                    'tags': instance.get('Tags', [])
                                })
                    elif service == 'lambda':
                        client = session.client(service)
                        lambda_response = client.list_functions()
                        for function in lambda_response['Functions']:
                            function_name = function['FunctionName']
                            service_counts['lambda'] += 1
                            service_details['lambda'].append({
                                'resource_arn': f'arn:aws:lambda:ap-south-1:{account_id}:function:{function_name}',
                                'tags': function.get('Tags', {})
                            })

                    elif service == 'ecs':
                        client = session.client(service)
                        ecs_response = client.list_clusters()
                        for cluster_arn in ecs_response['clusterArns']:
                            service_counts['ecs'] += 1
                            service_details['ecs'].append({
                                'resource_arn': cluster_arn,
                                'tags': []  # ECS clusters do not have tags returned in this call
                            })

                    elif service == 'ecr':
                        client = session.client(service)
                        ecr_response = client.describe_repositories()
                        for repository in ecr_response['repositories']:
                            repository_name = repository['repositoryName']
                            service_counts['ecr'] += 1
                            service_details['ecr'].append({
                                'resource_arn': f'arn:aws:ecr:ap-south-1:{account_id}:repository:{repository_name}',
                                'tags': repository.get('tags', [])
                            })
                    

                    elif service == 'rds':
                        client = session.client(service)
                        rds_response = client.describe_db_instances()
                        for db_instance in rds_response['DBInstances']:
                            db_instance_id = db_instance['DBInstanceIdentifier']
                            service_counts['rds'] += 1
                            service_details['rds'].append({
                                'resource_arn': f'arn:aws:rds:ap-south-1:{account_id}:db:{db_instance_id}',
                                'tags': db_instance.get('TagList', [])
                            })

                    elif service == 's3':
                        client = session.client(service)
                        s3_response = client.list_buckets()
                        for bucket in s3_response['Buckets']:
                            bucket_name = bucket['Name']
                            service_counts['s3'] += 1
                            service_details['s3'].append({
                                'resource_arn': f'arn:aws:s3:::{bucket_name}',
                                'tags': []  # S3 buckets do not have tags returned in this call
                            })

                    elif service == 'ebs':
                        # Fetch EBS volumes using the EC2 client
                        ec2_client = session.client('ec2')
                        ebs_response = ec2_client.describe_volumes()
                        for volume in ebs_response['Volumes']:
                            volume_id = volume['VolumeId']
                            service_counts['ebs'] += 1
                            service_details['ebs'].append({
                                'resource_arn': f'arn:aws:ec2:ap-south-1:{account_id}:volume/{volume_id}',
                                'tags': volume.get('Tags', [])
                            })

                    
                    # elif service == 'ss':
                    #     # Fetch EBS Snapshots using the EC2 client
                    #     ec2_client = session.client('ec2')  # Create the EC2 client
                    #     snapshots_response = ec2_client.describe_snapshots(OwnerIds=[account_id])  # Call describe_snapshots
                    #     for snapshot in snapshots_response['Snapshots']:
                    #         snapshot_id = snapshot['SnapshotId']
                    #         service_counts['ss'] += 1
                    #         service_details['ss'].append({
                    #             'resource_arn': f'arn:aws:ec2:ap-south-1:{account_id}:snapshot/{snapshot_id}',
                    #             'tags': snapshot.get('Tags', [])
                    #         })

                    elif service == 'docdb':
                        # Fetch DocumentDB clusters
                        client = session.client(service)
                        docdb_response = client.describe_db_clusters()
                        for cluster in docdb_response['DBClusters']:
                            cluster_id = cluster['DBClusterIdentifier']
                            service_counts['docdb'] += 1
                            service_details['docdb'].append({
                                'resource_arn': f'arn:aws:docdb:ap-south-1:{account_id}:cluster:{cluster_id}',
                                'tags': cluster.get('TagList', [])
                            })

                    elif service == 'vpc':
                        client = session.client('ec2')
                        vpc_response = client.describe_vpcs()
                        for vpc in vpc_response['Vpcs']:
                            vpc_id= vpc['VpcId']
                            service_counts['vpc'] += 1
                            service_details['vpc'].append({
                                'resource_arn': f'arn:aws:ec2:ap-south-1:{account_id}:vpc:{vpc_id}',
                                'tags': vpc.get('Tags', [])
                            })


                    elif service == 'elbv2':
                        # Fetch Load Balancers
                        client = session.client(service)
                        lbr_response = client.describe_load_balancers()
                        for load_balancer in lbr_response['LoadBalancers']:
                            load_balancer_arn = load_balancer['LoadBalancerArn']
                            service_counts['elbv2'] += 1
                            service_details['elbv2'].append({
                                'resource_arn': load_balancer_arn,
                            })

                    elif service == 'eip':
                        # Fetch Elastic IPs
                        client = session.client('ec2')
                        eip_response = client.describe_addresses()
                        for address in eip_response['Addresses']:
                            allocation_id = address['AllocationId']
                            service_counts['eip'] += 1
                            service_details['eip'].append({
                                'resource_arn': f'arn:aws:ec2:ap-south-1:{account_id}:elastic-ip/{allocation_id}',
                                'tags': []  # Elastic IPs do not have tags returned in this call
                            })
                    
                    # elif service == 'sns':
                    #     client = session.client(service)
                    #     sns_response = client.list_topics()
                    #     for topic in sns_response['Topics']:
                    #         topic_arn = topic['TopicArn']
                    #         service_counts['sns'] += 1
                    #         service_details['sns'].append({
                    #             'resource_arn': topic_arn,
                    #             'tags': []  # SNS topics do not have tags returned in this call
                    #         })

                    # elif service == 'ses':
                    #     client = session.client(service)
                    #     ses_response = client.list_identities()
                    #     for identity in ses_response['Identities']:
                    #         service_counts['ses'] += 1
                    #         service_details['ses'].append({
                    #             'resource_arn': f'arn:aws:ses:ap-south-1:{account_id}:identity/{identity}',
                    #             'tags': []  # SES identities do not have tags returned in this call
                    #         })

                    # elif service == 'waf':
                    #     client = session.client(service)
                    #     waf_response = client.list_web_acls()
                    #     for web_acl in waf_response['WebACLs']:
                    #         web_acl_id = web_acl['WebACLId']
                    #         service_counts['waf'] += 1
                    #         service_details['waf'].append({
                    #             'resource_arn': f'arn:aws:waf:ap-south-1:{account_id}:webacl/{web_acl_id}',
                    #             'tags': []  # WAF ACLs do not have tags returned in this call
                    #         })

                    elif service == 'secretsmanager':
                        client = session.client(service)
                        secrets_response = client.list_secrets()
                        for secret in secrets_response['SecretList']:
                            secret_name = secret['Name']
                            service_counts['secretsmanager'] += 1
                            service_details['secretsmanager'].append({
                                'resource_arn': f'arn:aws:secretsmanager:ap-south-1:{account_id}:secret:{secret_name}',
                                'tags': secret.get('Tags', [])
                            })

                    elif service == 'apigateway':
                        client = session.client(service)
                        api_response = client.get_rest_apis()
                        for api in api_response['items']:
                            api_id = api['id']
                            service_counts['apigateway'] += 1
                            service_details['apigateway'].append({
                                'resource_arn': f'arn:aws:apigateway:ap-south-1::/restapis/{api_id}',
                                'tags': []  # API Gateway does not have tags returned in this call
                            })

            # Calculate total counts for categories
            compute_count = sum(service_counts[service] for service in SERVICE_CATEGORIES['compute'])
            storage_count = sum(service_counts[service] for service in SERVICE_CATEGORIES['storage'])
            networking_count = sum(service_counts[service] for service in SERVICE_CATEGORIES['networking'])
            other_count = sum(service_counts[service] for service in SERVICE_CATEGORIES['other'])
            total_count = storage_count+compute_count+networking_count

            return JsonResponse({
                'service_counts': service_counts,
                'compute_count': compute_count,
                'storage_count': storage_count,
                'networking_count': networking_count,
                'other_count': other_count,
                'total_count':total_count,
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

class SecurityGroupPortsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            account_id = request.GET.get('account_id')
            if not account_id:
                return JsonResponse({'error': 'Account ID required'}, status=400)

            access_key, secret_key = get_decrypted_credentials(account_id)
            if not access_key or not secret_key:
                return JsonResponse({'error': 'Access key or secret key is required'}, status=400)

            # Create a session with the provided credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            # Create an EC2 client for security group queries
            ec2_client = session.client('ec2')
            ec2_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            regions={}
            for region_name in ec2_regions:
                # Fetch all security groups
                response = ec2_client.describe_security_groups()
                public_ports = []
                securityGroups = {}

                for group in response['SecurityGroups']:
                    for permission in group['IpPermissions']:
                        # Check if the permission allows all IPs (0.0.0.0/0)
                        for ip_range in permission.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                public_ports.append({
                                    'GroupName': group['GroupName'],
                                    'GroupId': group['GroupId'],
                                    'FromPort': permission.get('FromPort'),
                                    'ToPort': permission.get('ToPort'),
                                    'IpProtocol': permission.get('IpProtocol') or 'N/A',  # Handle cases with no protocol
                                    'Vulnerability': 'This port is vulnerable to public access.'
                                })
                        securityGroups[group['GroupId']]=public_ports
                regions[region_name]=securityGroups

            return JsonResponse(regions, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
