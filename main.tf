terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region     = "eu-west-2"
  access_key = "AKIA5BTWWSQ6FBDV6CXX"
  secret_key = "LIwDQ5u18ztP7yHMb/ZmEqFi5sQ2LAb2mT5nZA+P"
}


# Creating ec2

resource "aws_instance" "example-mohsen1" {
  ami           = "ami-0055e70f580e9ae80"
  instance_type = "t2.micro"

}

# creating user IAM
resource "aws_iam_user" "lb" {
  name = "loadbalancer"
  path = "/system/"

  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_access_key" "lb" {
  user = aws_iam_user.lb.name
}

data "aws_iam_policy_document" "lb_ro" {
  statement {
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "lb_ro" {
  name   = "test"
  user   = aws_iam_user.lb.name
  policy = data.aws_iam_policy_document.lb_ro.json
}


#creatin policy

resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


#Role

data "aws_iam_policy_document" "instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "instance_role"
  path               = "/system/"
  assume_role_policy = data.aws_iam_policy_document.instance_assume_role_policy.json
}
#Budget 
/* #resource "aws_budgets_budget" "ec2" {
  name              = "budget-ec2-monthly"
  budget_type       = "COST"
  limit_amount      = "1"
  limit_unit        = "USD"
  time_period_end   = "2087-06-15_00:00"
  time_period_start = "2023-03-15_09:33"
  time_unit         = "MONTHLY"

  cost_filter {
    name = "Service"
    values = [
      "Amazon Elastic Compute Cloud - Compute",
    ]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = ["test@example.com"]
  }
} */


#Security Group

resource "aws_security_group" "example" {
  # ... other configuration ...

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}


#Placement Group
resource "aws_placement_group" "web" {
  name     = "Critical Group"
  strategy = "cluster"
}

#Application Load Balancer
/* 
resource "aws_lb" "test" {
  name                       = "test-lb-tf"
  internal                   = false
  load_balancer_type         = "application"
  subnets                    = ["subnet-03759ea6ad05e81fc", "subnet-0888423c38f57cdf3"]
  enable_deletion_protection = true


  tags = {
    Environment = "production"
  }
} */

#Network Load Balancer
resource "aws_lb" "test" {
  name                       = "test-lb-tf"
  internal                   = false
  load_balancer_type         = "network"
  subnets                    = ["subnet-03759ea6ad05e81fc", "subnet-0888423c38f57cdf3"]
  enable_deletion_protection = true

  tags = {
    Environment = "production"
  }
}


#RDS
/* 
resource "aws_db_instance" "default" {
  allocated_storage    = 10
  db_name              = "mydb"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true
} */

#Arura

/* module "cluster" {
  source = "terraform-aws-modules/rds-aurora/aws"

  name           = "test-aurora-db-postgres96"
  engine         = "aurora-postgresql"
  engine_version = "11.12"
  instance_class = "db.r6g.large"
  instances = {
    one = {}
    2 = {
      instance_class = "db.r6g.2xlarge"
    }
  }

  vpc_id  = "vpc-0553a9a77b889ff56"
  subnets = ["subnet-0d74fcb25520a2062", "subnet-07379a0f1582ab7f0"]

  allowed_security_groups = ["sg-05d1e29f096115607"]
  allowed_cidr_blocks     = ["10.0.0.0/24"]

  storage_encrypted   = true
  apply_immediately   = true
  monitoring_interval = 10

  db_parameter_group_name         = "default"
  db_cluster_parameter_group_name = "default"

  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = {
    Environment = "dev"
    Terraform   = "true"
  }
} */



#Bucket

resource "aws_s3_bucket" "mohsen1989uk" {
  bucket = "my-tf-test-bucket-1989"

  tags = {
    Name        = "My bucket 1989"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_acl" "example1989" {
  bucket = aws_s3_bucket.mohsen1989uk.id
  acl    = "private"
}


resource "aws_s3_bucket_versioning" "example_versioning" {
  bucket = aws_s3_bucket.mohsen1989uk.id
  versioning_configuration {
    status = "Enabled"
  }


}


#ECS
resource "aws_kms_key" "example" {
  description             = "example"
  deletion_window_in_days = 7
}

resource "aws_cloudwatch_log_group" "example" {
  name = "example"
}

resource "aws_ecs_cluster" "test" {
  name = "example"

  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.example.arn
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.example.name
      }
    }
  }
}


#Cloudwatch

resource "aws_cloudwatch_metric_alarm" "mohsenk222" {
  alarm_name                = "terraform-test-foobar5"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = 120
  statistic                 = "Average"
  threshold                 = 80
  alarm_description         = "This metric monitors ec2 cpu utilization"
  insufficient_data_actions = []
}



