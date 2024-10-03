from django.urls import path
from . import views
urlpatterns = [
    path("check/",views.CheckAPI.as_view()),
    path('api/register/',views.RegisterUser.as_view()),
    path('api/login/', views.LoginView.as_view(),name='login'),
    path('account-and-credentials/create/', views.AWSAccountAndCredentialManagerView.as_view(), name='account-and-credentials-create'),
    path('account-details/', views.AccountDetailsListView.as_view(), name='account-details-list'),
    path("aws/get_details/", views.AWSAccountDetails.as_view(), name = 'aws-account-details'),
    path('api/get_users/', views.UserListView.as_view(), name='user-list'),
    path('api/delete_user/<str:email>/', views.UserDeleteView.as_view(), name='user-delete'),

    path('api/all-services-available/',views.AvailableServices.as_view(),name="available-services"),

    path("aws/ec2-details/", views.AWSEC2Details.as_view(), name = 'aws-recources-details'),
    path("aws/s3-details/", views.AWSS3Details.as_view(), name = 'aws-recources-s3-details'),
    path("aws/vpc-details/", views.AWSVpcDetails.as_view(), name = 'aws-recources-s3-details'),
    path("aws/Document_DB_Details/",views.Document_DB_Details.as_view(),name='aws-document-db-details'),
    path("aws/SNS_Details/",views.SNS_Details.as_view(),name='aws-SNS_Details'),
    path('api/ses-service-details/',views.SES_Details.as_view(),name="ses-details"),

    #path("aws/configure/signout/",views.SignOutView.as_view(),name='aws-configure-signout'),

    path('api/ec2_memory_data/',views.EC2_Memory_utilization.as_view(),name='ec2_memory_data'),#1 time limit
    path('api/rds-data/', views.RDSData.as_view(), name='rds_data'),#3 time
    path('api/s3-detail-data/', views.Get_S3_Data.as_view(), name='s3-detail-data'),#5
    path('api/vpc-data/',views.Get_VPCData.as_view(), name='VPC-detail-data'),#8 
    path('api/ebs-data/',views.Get_EBS_Data.as_view(),name='ebs-detail-data'),#11 time
    path('api/secrets-data/', views.Secrets_data.as_view(), name='secrets-data'),#4 
    path('api/ecr-detail-data/', views.Get_ECR_Data.as_view(), name='ecr-detail-data'),#6
    path('api/lambda-metrics/', views.LambdaMetricsView.as_view(), name='lambda_metrics-data'),#7 time 
    path('api/ecs-data/',views.Get_ECS_Data.as_view(),name='ecs-detailed-data'),#9 time
    path('api/eip-data/',views.Get_Elastic_Ip.as_view(),name='eip-detail-data'),#13
    path('api/loadbalancer-data/',views.Get_load_balancer_Data.as_view(),name='loadbalancer-detailed-data'),#10 time
    path('api/ebs-data/',views.Get_EBS_Data.as_view(),name='ebs-detail-data'),#11 time
    path('api/waf-acl-data/',views.Get_WAF_Data.as_view(),name='waf-detail-data'),#12 time
    path('api/api-gateway-data/',views.Get_APIGateway.as_view(),name='api-gateway'),#16 time
    path('api/snapshot_data/',views.Get_Snapshot_Data.as_view(),name='snapshot_data'),#17
    path('api/eks-data/',views.EKS_Data.as_view(),name='eks-data'),
    path('api/send_email/',views.Send_cost_Email.as_view(),name='send-mail'),#15 #Email
    path('api/get_detailed_usage_data/',views.Get_Detailed_usage_Data.as_view(),name='detailed_usage_data'),
    
    path('api/detail-cost-data/', views.GetTotalBill.as_view(), name='detail-cost-data'),#Bar Chart#14
    
    path('api/cost-data/',views.FetchAWSCostView.as_view(),name='cost-data'),
    path("aws/all/cost/", views.AWSAllServiceCost.as_view(), name = 'aws-recources-s3-details'),
 
    path('api/instance-usage-type/',views.Ec2_instance_usage_type.as_view(),name="ec2-instance-usage-type"),
    # Graphs

    #path('api/EC2_instance_graphical_data/',views.EC2_Memory_utilization_Graph.as_view(),name='graph_data'),
    path('api/services_cost_data/',views.Services_Cost_Data.as_view(),name='services_cost'),
    path('api/ec2_instance_cost/',views.EC2_Instance_Cost.as_view(),name='services_cost'),
    path('api/ec2_region_wise_cost/',views.EC2_REGION_WISE_COST_DATA.as_view(),name='ec2_region_cost'),
    path('api/total_percentage_increase/',views.GetTotalPercentageIncrease.as_view(),name='total_increase'),
    path('api/percentage_increase/', views.GetPercentageIncrease.as_view(), name='percentage_increase'),
    path('api/services3_cost_data/',views.Services3_Cost_Data.as_view(),name='service3'),
    path('ec2instancesapiview/', views.EC2InstancesAPIView.as_view(), name='ec2-by-region'),
    path('s3bucketsapiview/', views.S3BucketsAPIView.as_view(), name='s3-by-region'),
    path('eipdetailsapiview/',views.ElasticIPsAPIView.as_view(), name='eip-by-region'),
    # path('api/ec2_cost_data/',views.EC2_instance_cost_data.as_view(),name='ec2_cost'),
    # path('api/s3_cost_data/',views.S3_cost_data.as_view(),name='s3_cost_data'),
    # path('api/vpc_cost_data/',views.VPC_cost_data.as_view(),name='vpc-cost'),
    # path('api/loadbalancer_cost_data/',views.LoadBalancer_cost_data.as_view(),name='loadbalancer_cost'),
    # path('api/ebs_cost_data/',views.EBS_cost_data.as_view(),name='ebs-cost'),
    # path('api/eip_cost_data/',views.EIP_cost_data.as_view(),name='eip-cost'),
    # path('api/snapshot_cost_data/',views.SnapShot_cost_data.as_view(),name='snapshot-cost'),
    # path('api/document_db_cost_data/',views.DocumentDB_cost_data.as_view(),name='documentdb-cost'),
    # path('api/sns_cost_data/',views.SNS_cost_data.as_view(),name='sns-cost'),
    # path('api/ses_cost_data/',views.SES_cost_data.as_view(),name='ses-cost'),
    # path('api/ecr_cost_data/',views.ECR_cost_data.as_view(),name='ecr-cost'),
    # path('api/lambda_cost_data/',views.Lambda_cost_data.as_view(),name='lambda-cost'),
    # path('api/ecs_cost_data/',views.ECS_cost_data.as_view(),name="ecs-cost"),
    # path('api/waf_cost_data/',views.WAF_cost_data.as_view(),name="waf-cost"),
    # path('api/secrets_cost_data/',views.SecretsManager_cost_data.as_view(),name='secrets-cost'),
    # path('api/rds_cost_data/',views.RDS_Cost_Data.as_view(),name='rds-cost'),
    path('api/awsresourcecost/',views.AwsServiceCost.as_view(),name='aws-resource-cost'),
    path("aws/all/count/",views.AWSResourcesListCount.as_view(),name="all-cost"),

    #Unused resources
    path('api/unused_resource_data/',views.AWSResourceManager.as_view(),name="unused_resource"),
    path('api/unused_resources/',views.AWS_Unused_Resources.as_view(),name='unused_resource_data'),
    path('api/ec2_compute_unused_resource/',views.AWS_Unused_Resource_and_EC2_Compute.as_view(),name='ec2-compute-and-unsued-resource'),

    #Recommendations
    path('api/ec2_recc/',views.EC2_Recommendations.as_view(),name='ec2-recomendations'),
    path('api/ec2_less_than_50/',views.EC2_Utilization.as_view(),name='ec2-utilization'),
    path('api/rds_recommendation/', views.RDS_Recommendation.as_view(), name='rds-recommendation'),
    path('api/ec2_recommendation/',views.EC2Recommendation.as_view(),name='ec2-recommendation'),
    path('api/ecr_recommendation/',views.ECRRecommendation.as_view(),name='ecr-recommendation'),
    path('api/ecs_recommendation/',views.ECSRecommendation.as_view(),name='ecs-recommendation'),
    path('api/s3_recommendation/',views.S3Recommendation.as_view(),name='s3-recommendation'),
    path('api/vpc_recommendation/',views.VPCRecommendation.as_view(),name='vpc-recommendation'),
    path('api/ebs_recommendation/',views.EBSRecommendation.as_view(),name='ebs-recommendation'),
    path('api/lambda_recommendation/',views.LambdaMetricsAnalyzer.as_view(),name='Lambda-recommendation'),
    path('api/ec2reccom/',views.EC2RecommendationNew.as_view(),name="ec2"),
    
    path('api/service_category/',views.Service_Categorization.as_view(),name="category"),
    path('api/ec2_unused_resource/',views.EC2_UnUsedRecources.as_view(),name='unused'),

    path('api/security-groups/ports/',views.SecurityGroupPortsView.as_view(),name="ports"),

]

