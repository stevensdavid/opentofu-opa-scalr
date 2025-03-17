variable "service_id" {
  type = string
}

variable "cluster_id" {
  type = string
}

variable "task_definition_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

resource "aws_ecs_task_set" "valid" {
  service         = var.service_id
  cluster         = var.cluster_id
  task_definition = var.task_definition_id
}
resource "aws_ecs_task_set" "also_valid" {
  service         = var.service_id
  cluster         = var.cluster_id
  task_definition = var.task_definition_id
  network_configuration {
    subnets          = var.subnet_ids
    assign_public_ip = false
  }
}
