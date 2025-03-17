provider "aws" {
  region = "eu-north-1"
}

resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "subnet_one" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = cidrsubnet(aws_vpc.vpc.cidr_block, 8, 0)
}

resource "aws_subnet" "subnet_two" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = cidrsubnet(aws_vpc.vpc.cidr_block, 8, 1)
}

resource "aws_ecs_cluster" "cluster" {
  name = "test-cluster"
}

resource "aws_ecs_task_definition" "task" {
  family = "test-task"
  container_definitions = jsonencode([
    {
      name      = "test-container"
      image     = "nginx:latest"
      essential = true
    },
  ])
  cpu                      = 256
  memory                   = 512
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
}

module "pass" {
  source              = "./pass"
  cluster_id          = aws_ecs_cluster.cluster.id
  subnet_ids          = [aws_subnet.subnet_one.id, aws_subnet.subnet_two.id]
  task_definition_arn = aws_ecs_task_definition.task.arn
}

module "fail" {
  source              = "./fail"
  cluster_id          = aws_ecs_cluster.cluster.id
  subnet_ids          = [aws_subnet.subnet_one.id, aws_subnet.subnet_two.id]
  task_definition_arn = aws_ecs_task_definition.task.arn
}
