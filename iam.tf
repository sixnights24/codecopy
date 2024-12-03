## policy - secret_csi_driver_policy
resource "aws_iam_policy" "secret_csi_driver_policy" {
  name = "${var.service_name}-policy-${var.environment}-secret-csi-driver"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "ssm:GetParameterHistory",
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:DescribeParameters",
          "ssm:GetParametersByPath",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:ListSecretVersionIds",
          "kms:GetPublicKey",
          "kms:Decrypt",
          "kms:ListKeyPolicies",
          "kms:ListRetirableGrants",
          "kms:GetKeyPolicy",
          "kms:ListResourceTags",
          "kms:ListGrants",
          "kms:GetParametersForImport",
          "kms:DescribeCustomKeyStores",
          "kms:ListKeys",
          "kms:GetKeyRotationStatus",
          "kms:Encrypt",
          "kms:ListAliases",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ],
        "Resource" : "*"
      }
    ]
  })

  tags = {
    Name = "iamp-${var.environment}-secret-csi-driver-policy",
    Name = "${var.service_name}-policy-${var.environment}-secret-csi-driver"
  }
}

## policy - secret_csi_driver_policy
resource "aws_iam_policy" "eks-svc-ssgd-be-fo" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-policy-${var.environment}-eks-svc-ssgd-be-fo"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:SendMessage"
        ],
        "Resource" : [
          "arn:aws:sqs:ap-northeast-2:064699816182:dept-ssgd-sqs-an2-dev-app-log",
          "arn:aws:sqs:ap-northeast-2:064699816182:dept-ssgd-sqs-an2-dev-app-log-mobile-app-activity",
          "arn:aws:sqs:ap-northeast-2:064699816182:dept-ssgd-sqs-an2-dev-app-log-banner-click",
          "arn:aws:sqs:ap-northeast-2:064699816182:dept-ssgd-sqs-an2-dev-app-log-mypage-history"
        ]
      }
    ]
  })

  tags = {
    Name = "iamp-${var.environment}-eks-svc-ssgd-be-fo",
    Name = "${var.service_name}-policy-${var.environment}-eks-svc-ssgd-be-fo"
  }
}


# role
resource "aws_iam_role" "svc-ssgd-fe" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-fe"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-fe"
  }
}
resource "aws_iam_role" "svc-ssgd-fe-fo" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-fe-fo"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-fe-fo"
  }
}

resource "aws_iam_role" "svc-ssgd-fe-bo" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-fe-bo"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-fe-bo"
  }
}

resource "aws_iam_role" "svc-ssgd-fe-po" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-fe-po"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-fe-po"
  }
}

resource "aws_iam_role" "svc-ssgd-be" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-be"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-be"
  }
}

resource "aws_iam_role" "svc-ssgd-be-fo" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-be-fo"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn,
    aws_iam_policy.eks-svc-ssgd-be-fo[0].arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-be-fo"
  }
}

resource "aws_iam_role" "svc-ssgd-be-bo" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-be-bo"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-be-bo"
  }
}

resource "aws_iam_role" "svc-ssgd-be-po" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-be-po"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-be-po"
  }
}


resource "aws_iam_role" "svc-ssgd-sso" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-sso"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-sso"
  }
}

resource "aws_iam_role" "svc-ssgd-pos" {
  count = var.environment == "com" ? 0 : 1
  name  = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-pos"

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    aws_iam_policy.secret_csi_driver_policy.arn
  ]

  assume_role_policy = jsonencode({
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "${module.app_cluster.oidc_provider_arn}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.app_cluster.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
    Version = "2012-10-17"
    }
  )

  lifecycle { ignore_changes = [assume_role_policy] }

  tags = {
    Name = "${var.service_name}-role-${var.environment}-eks-svc-ssgd-pos"
  }
}
