provider "aws" {
  region = "eu-north-1"
}

module "pass" {
  source = "./pass"
}

module "fail" {
  source = "./fail"
}
