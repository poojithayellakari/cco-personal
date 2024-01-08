from django.urls import path
from . import views
urlpatterns = [
    path('api/register/',views.Registeruser.as_view()),
    path("aws_configure/", views.AWSConfigure.as_view(),name='configuration'),
    #path("aws/configure/signout/",views.SignOutView.as_view(),name='aws-configure-signout'),
    path('api/login/', views.LoginView.as_view(),name='login'),
    path('api/ec2_memory_data/',views.EC2_Memory_utilization.as_view(),name='ec2_memory_data'),#1 time limit
    path('api/cost-data/',views.FetchAWSCostView.as_view(),name='cost-data'),#2 time
    path('api/rds-data/', views.RDSData.as_view(), name='rds_data'),#3 time
    path('api/secrets-data/', views.Secrets_data.as_view(), name='secrets-data'),#4 
    path('api/s3-detail-data/', views.Get_S3_Data.as_view(), name='s3-detail-data'),#5 
    path('api/ecr-detail-data/', views.Get_ECR_Data.as_view(), name='ecr-detail-data'),#6
    path('api/lambda-metrics/', views.LambdaMetricsView.as_view(), name='lambda_metrics-data'),#7 time 
    path('api/vpc-data/',views.Get_VPCData.as_view(), name='VPC-detail-data'),#8 
    path('api/ecs-data/',views.Get_ECS_Data.as_view(),name='ecs-detailed-data'),#9 time
    path('api/loadbalancer-data/',views.Get_load_balancer_Data.as_view(),name='loadbalancer-detailed-data'),#10 time
    path('api/ebs-data/',views.Get_EBS_Data.as_view(),name='ebs-detail-data'),#11 time
    path('api/waf-acl-data/',views.Get_WAF_Data.as_view(),name='waf-detail-data'),#12 time
    path('api/eip-data/',views.Get_Elastic_Ip.as_view(),name='eip-detail-data'),#13
    path('api/detail-cost-data/', views.GetTotalBill.as_view(), name='detail-cost-data'),#Bar Chart#14
    path('api/send_email/',views.Send_cost_Email.as_view(),name='send-mail'),#15 #Email
    path('api/api-gateway-data',views.Get_APIGateway.as_view(),name='api-gateway'),#16 time
    path('api/snapshot_data',views.Get_Snapshot_Data.as_view(),name='snapshot_data'),#17
    

    # Graphs

    #path('api/EC2_instance_graphical_data/',views.EC2_Memory_utilization_Graph.as_view(),name='graph_data'),
    path('api/ec2_cost_data/',views.EC2_instance_cost_data.as_view(),name='ec2_cost'),
    path('api/s3_cost_data/',views.S3_cost_data.as_view(),name='s3_cost_data'),
    path('api/ecr_cost_data/',views.ECR_cost_data.as_view(),name='ecr-cost'),
    path('api/lambda_cost_data/',views.Lambda_cost_data.as_view(),name='lambda-cost'),
    path('api/ecs_cost_data/',views.ECS_cost_data.as_view(),name="ecs-cost"),
    path('api/waf_cost_data/',views.WAF_cost_data.as_view(),name="waf-cost"),
    path('api/vpc_cost_data/',views.VPC_cost_data.as_view(),name='vpc-cost'),
    path('api/secrets_cost_data/',views.SecretsManager_cost_data.as_view(),name='secrets-cost'),
    path('api/rds_cost_data/',views.RDS_Cost_Data.as_view(),name='rds-cost'),

    #Unused resources
    path('api/unused_resource_data/',views.AWSResourceManager.as_view(),name="unused_resource"),
    path('api/unused_resources/',views.AWS_Unused_Resources.as_view(),name='unused_resource_data'),

    #Recommendations
    path('api/ec2_recommendation/',views.EC2_Recommendations.as_view(),name='ec2-recomendations'),
    path('api/ec2_less_than_50/',views.EC2_Utilization.as_view(),name='ec2-utilization'),
    path('api/rds_recommendation/', views.RDS_Recommendation.as_view(), name='rds-recommendation'),
]
