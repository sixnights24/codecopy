### gitlab
resource "aws_iam_role" "iam_role_gitlab" {
  count              = var.environment == "com" ? 1 : 0
  name               = "${var.service_name}-role-${var.environment}-gitlab"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
  tags = {
    Name = "${var.service_name}-role-${var.environment}-gitlab"
  }
}


resource "aws_iam_policy" "iam_policy_gitlab" {
  count  = var.environment == "com" ? 1 : 0
  name   = "${var.service_name}-policy-${var.environment}-gitlab"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:AbortMultipartUpload",
                "s3:GetBucketAcl",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:GetObjectAcl",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:PutLifecycleConfiguration"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "s3:GetBucketLocation",
                "s3:ListAllMyBuckets"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "cloudwatch:PutMetricData",
                "ec2:DescribeVolumes",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "eks:DescribeCluster",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
          "Effect": "Allow",
          "Action": [
            "kms:Decrypt"
          ],
          "Resource": "arn:aws:kms:ap-northeast-2:068254914844:key/3d1ad921-0624-4006-8ad1-860cedcf739c"
        }
    ]
}
EOF
  tags = {
    "Name" = "${var.service_name}-policy-${var.environment}-gitlab"
  }
}

resource "aws_iam_policy_attachment" "gitlab_policy" {
  count      = var.environment == "com" ? 1 : 0
  name       = "${var.service_name}-policy-attach-${var.environment}-gitlab"
  roles      = [aws_iam_role.iam_role_gitlab[count.index].name]
  policy_arn = aws_iam_policy.iam_policy_gitlab[count.index].arn
}

## gitlab runner deploy
resource "aws_iam_role" "iam_role_gitlab_deploy" {
  count              = var.environment == "com" ? 1 : 0
  name               = "${var.service_name}-role-${var.environment}-gitlab-deploy"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com",
        "AWS": "arn:aws:iam::314667246064:role/${var.service_name}-role-com-eks-runner-node"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
  tags = {
    Name = "${var.service_name}-role-${var.environment}-gitlab-deploy"
  }
}

resource "aws_iam_policy" "iam_policy_gitlab_deploy" {
  count  = var.environment == "com" ? 1 : 0
  name   = "${var.service_name}-policy-${var.environment}-gitlab-deploy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
      {
		    "Sid": "1",
			  "Action": [
          "secretsmanager:*",
          "s3:*",
          "route53:*",
          "cloudformation:*",
          "dynamodb:*",
          "ecr:*",
          "ec2:*",
          "sts:*",
          "elasticloadbalancing:*",
          "iam:*",
          "kms:*",
          "logs:*",
          "eks:*",
          "elasticache:*",
          "firehose:*",
          "kinesis:*",
          "es:*",
          "events:*"
			  ],
        "Effect": "Allow",
        "Resource": "*"
		  },
      {
        "Sid": "2",
        "Effect": "Allow",
        "Action": "kms:Decrypt",
        "Resource": "arn:aws:kms:ap-northeast-2:068254914844:key/3d1ad921-0624-4006-8ad1-860cedcf739c"
      }
    ]
}
EOF
  tags = {
    "Name" = "${var.service_name}-policy-${var.environment}-gitlab-deploy"
  }
}

resource "aws_iam_policy_attachment" "gitlab_deploy_policy" {
  count      = var.environment == "com" ? 1 : 0
  name       = "${var.service_name}-policy-attach-${var.environment}-gitlab-deploy"
  roles      = [aws_iam_role.iam_role_gitlab_deploy[count.index].name]
  policy_arn = aws_iam_policy.iam_policy_gitlab_deploy[count.index].arn
}

## eks bastion
data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]

  }
}

data "aws_iam_policy_document" "eks_dev_bastion" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "eks:ListClusters",
      "eks:DescribeCluster",
    ]
  }
  statement {
    effect    = "Allow"
    resources = ["arn:aws:iam::064699816182:role/dept-ssgd-role-dev-cross-role-eks-bastion"]
    actions   = ["sts:AssumeRole"]
  }
  statement {
    effect    = "Allow"
    resources = ["arn:aws:iam::855469239994:role/dept-ssgd-role-stg-cross-role-eks-bastion"]
    actions   = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "eks_prd_bastion" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "eks:ListClusters",
      "eks:DescribeCluster",
    ]
  }
  # statement {
  #   effect = "Allow"
  #   resource = [""]
  #   actions = ["sts:AssumeRole"]
  # }
}

resource "aws_iam_role" "eks_bastion_prd" {
  count = var.environment == "com" ? 1 : 0
  name  = "${var.service_name}-role-${var.environment}-eks-bastion-prd"

  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-bastion-prd"
  }
}

resource "aws_iam_policy" "eks_bastion_prd" {
  count = var.environment == "com" ? 1 : 0
  name  = "${var.service_name}-policy-${var.environment}-eks-bastion-prd"

  policy = data.aws_iam_policy_document.eks_prd_bastion.json

  tags = {
    Name = "${var.service_name}-policy-${var.environment}-eks-bastion-prd"
  }
}

resource "aws_iam_policy_attachment" "eks_bastion_prd" {
  count      = var.environment == "com" ? 1 : 0
  name       = "eks_bastion_prd_attachment"
  roles      = [aws_iam_role.eks_bastion_prd[count.index].name]
  policy_arn = aws_iam_policy.eks_bastion_prd[count.index].arn
}

resource "aws_iam_role" "eks_bastion_dev" {
  count = var.environment == "com" ? 1 : 0
  name  = "${var.service_name}-role-${var.environment}-eks-bastion-dev"

  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-bastion-dev"
  }
}

resource "aws_iam_policy" "eks_bastion_dev" {
  count = var.environment == "com" ? 1 : 0
  name  = "${var.service_name}-policy-${var.environment}-eks-bastion-dev"

  policy = data.aws_iam_policy_document.eks_dev_bastion.json

  tags = {
    Name = "${var.service_name}-policy-${var.environment}-eks-bastion-dev"
  }
}

resource "aws_iam_policy_attachment" "eks_bastion_dev" {
  count      = var.environment == "com" ? 1 : 0
  name       = "eks_bastion_dev_attachment"
  roles      = [aws_iam_role.eks_bastion_dev[count.index].name]
  policy_arn = aws_iam_policy.eks_bastion_dev[count.index].arn
}

#### bastion assume role to eks
data "aws_iam_policy_document" "bastion_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::314667246064:root"]
    }

    actions = ["sts:AssumeRole"]

  }
}

data "aws_iam_policy_document" "bastion_assume_policy" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "eks:*",
    ]
  }
}

resource "aws_iam_role" "bastion_assume_eks" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-cross-role-eks-bastion"

  assume_role_policy = data.aws_iam_policy_document.bastion_assume_role.json

  tags = {
    Name = "${var.service_name}-role-${var.environment}-cross-role-eks-bastion"
  }
}

resource "aws_iam_policy" "bastion_assume_eks" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-policy-${var.environment}-cross-role-eks-bastion"

  policy = data.aws_iam_policy_document.bastion_assume_policy.json

  tags = {
    Name = "${var.service_name}-policy-${var.environment}-cross-role-eks-bastion"
  }
}

resource "aws_iam_policy_attachment" "bastion_assume_eks" {
  count      = var.environment == "com" ? 0 : 1
  name       = "bastion_assume_eks_attachment"
  roles      = [aws_iam_role.bastion_assume_eks[count.index].name]
  policy_arn = aws_iam_policy.bastion_assume_eks[count.index].arn
}

### Nexus
resource "aws_iam_role" "iam_role_nexus" {
  count              = var.environment == "com" ? 1 : 0
  name               = "${var.service_name}-role-${var.environment}-nexus"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
  tags = {
    Name = "${var.service_name}-role-${var.environment}-nexus"
  }
}

resource "aws_iam_policy_attachment" "nexus_policy" {
  count      = var.environment == "com" ? 1 : 0
  name       = "${var.service_name}-policy-attach-${var.environment}-nexus"
  roles      = [aws_iam_role.iam_role_nexus[count.index].name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
