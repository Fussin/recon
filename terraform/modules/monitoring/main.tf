resource "aws_cloudwatch_log_group" "main" {
  name = "/aws/eks/main/cluster"
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "main"

  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [ "AWS/EKS", "CPUUtilization", "ClusterName", "main" ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "${var.aws_region}",
        "title": "EKS CPU Utilization"
      }
    }
  ]
}
EOF
}

resource "aws_cloudwatch_metric_alarm" "main" {
  alarm_name          = "main"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EKS"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  dimensions = {
    ClusterName = "main"
  }
}
